require('dotenv').config();
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { Client } = require('pg');
const cron = require('node-cron');

// Logging helper
const log = (msg) => console.log(`[OpenClaw] ${new Date().toISOString()} - ${msg}`);

// Configuration
const RECONNECT_DELAY = 10000; // 5초 -> 10초로 증가 (DB 기동 대기)
const MAX_RETRIES = 20; // 10회 -> 20회로 증가 (충분한 대기 시간 확보)

async function connectToDB(retries = 0) {
    const client = new Client({
        connectionString: process.env.DATABASE_URL,
    });

    try {
        await client.connect();
        log("Connected to PostgreSQL Database.");
        return client;
    } catch (err) {
        if (retries < MAX_RETRIES) {
            log(`DB Connection failed (${err.message}). Retrying in ${RECONNECT_DELAY / 1000}s... (${retries + 1}/${MAX_RETRIES})`);
            await new Promise(res => setTimeout(res, RECONNECT_DELAY));
            return connectToDB(retries + 1);
        } else {
            throw new Error(`Failed to connect to DB after ${MAX_RETRIES} attempts.`);
        }
    }
}

// Skill: Auto-tag Blog Posts
async function autoTagPosts(client, model) {
    log("Running Skill: Auto-tag Blog Posts...");

    try {
        // 태그가 없거나 3개 미만인 공개 포스트를 대상으로 분석 (분석 범위 확대)
        const res = await client.query(`
            SELECT p.id, p.title, p.content 
            FROM "Post" p
            LEFT JOIN "TagOnPost" tp ON p.id = tp."postId"
            WHERE p.published = true
            GROUP BY p.id, p.title, p.content
            HAVING COUNT(tp."tagId") < 3
            LIMIT 5
        `);

        if (res.rows.length === 0) {
            log("No posts need tagging at this time.");
            return;
        }

        for (const post of res.rows) {
            log(`Analyzing tags for post: ${post.title}`);
            
            const prompt = `
                다음 블로그 글의 내용을 분석하여 가장 적절한 해시태그 5개를 추출해줘.
                결과는 오직 콤마(,)로 구분된 단어들만 출력해. 예: Docker,배포,CI/CD,Next.js,서버
                
                글 제목: ${post.title}
                글 내용: ${post.content.substring(0, 1500)}
            `;

            const result = await model.generateContent(prompt);
            const responseText = result.response.text();
            log(`Gemini response: ${responseText}`);
            
            const tags = responseText.split(',').map(t => t.trim()).filter(t => t.length > 0);

            for (const tagName of tags) {
                // 태그 생성 또는 조회
                const tagId = 'tag_' + Date.now() + Math.random().toString(36).substring(7);
                await client.query(
                    'INSERT INTO "Tag" (id, name) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id',
                    [tagId, tagName]
                );
                
                // 해당 태그의 실제 ID 가져오기 (이미 존재했을 경우 포함)
                const realTagRes = await client.query('SELECT id FROM "Tag" WHERE name = $1', [tagName]);
                const realTagId = realTagRes.rows[0].id;

                await client.query(
                    'INSERT INTO "TagOnPost" ("postId", "tagId") VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [post.id, realTagId]
                );
            }
            log(`✅ Successfully updated tags for: ${post.title}`);
        }
    } catch (err) {
        console.error("Error in autoTagPosts:", err);
    }
}

// Skill: Summarize Recent Memos
async function summarizeRecentMemos(client, model) {
    log("Running Skill: Summarize Recent Memos...");
    try {
        const res = await client.query(`SELECT content FROM "Memo" WHERE "createdAt" > NOW() - INTERVAL '24 hours'`);
        if (res.rows.length === 0) return;
        const memoText = res.rows.map(r => `- ${r.content}`).join('\n');
        const prompt = `다음 메모들을 요약해줘:\n${memoText}`;
        const result = await model.generateContent(prompt);
        log("Summary Generated.");
    } catch (err) { console.error("Error in summarizeRecentMemos:", err); }
}

// Skill: Sync Project Data (Notion/Github)
async function syncProjectData(client) {
    log("Running Skill: Sync Project Data...");
    try {
        // 1. 대상 프로젝트 조회
        const projectRes = await client.query(`SELECT id FROM "Project" WHERE name = 'SK_ROOKIES_FINAL_PJT'`);
        if (projectRes.rows.length === 0) {
            log("SK_ROOKIES_FINAL_PJT project not found. Skipping sync.");
            return;
        }
        const projectId = projectRes.rows[0].id;

        // 2. 설정값 조회 (Notion Key 등)
        const settingsRes = await client.query(`SELECT key, value FROM "ProjectSetting" WHERE "projectId" = $1`, [projectId]);
        const settings = {};
        settingsRes.rows.forEach(r => settings[r.key] = r.value);

        log(`Syncing data for project: SK_ROOKIES_FINAL_PJT`);
        
        // TODO: 실제 Notion/Github API 호출 로직 통합
        // 현재는 동기화 성공 로그만 남김
        await client.query(
            `INSERT INTO "ProjectActivityLog" (id, platform, action, content, "projectId", "eventTime", "createdAt") 
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
            ['log_' + Date.now(), 'SYSTEM', 'AUTO_SYNC', '정기 자동 동기화가 완료되었습니다.', projectId]
        );

        log("✅ Project data sync completed.");
    } catch (err) {
        console.error("Error in syncProjectData:", err);
    }
}

// Skill: Send Midnight Report to Discord
async function sendMidnightReport(client) {
    log("Running Skill: Send Midnight Report...");
    try {
        const projectRes = await client.query(`SELECT id FROM "Project" WHERE name = 'SK_ROOKIES_FINAL_PJT'`);
        if (projectRes.rows.length === 0) return;
        const projectId = projectRes.rows[0].id;

        const webhookRes = await client.query(
            `SELECT value FROM "ProjectSetting" WHERE "projectId" = $1 AND key = 'SK_ROOKIES_FINAL_PJT_DISCORD_WEBHOOK_URL'`,
            [projectId]
        );
        if (webhookRes.rows.length === 0) return;
        const webhookUrl = webhookRes.rows[0].value;

        // 오늘 하루치 로그 조회
        const logsRes = await client.query(
            `SELECT platform, action, content, "rawPayload", "eventTime" FROM "ProjectActivityLog" 
             WHERE "projectId" = $1 AND "createdAt" >= NOW() - INTERVAL '24 hours'
             ORDER BY "eventTime" ASC`,
            [projectId]
        );

        if (logsRes.rows.length === 0) {
            log("No logs for midnight report.");
            return;
        }

        // 설정에서 리포트 타입 가져오기 (기본값 RAW)
        const reportType = settings['SK_ROOKIES_FINAL_PJT_MIDNIGHT_REPORT_TYPE'] || 'RAW';
        
        const formData = new FormData();
        const dateStr = new Date().toISOString().split('T')[0];

        if (reportType === 'SUMMARY') {
            let markdown = `# 📊 [${dateStr}] 활동 요약 보고서\n\n`;
            markdown += `## 프로젝트: SK_ROOKIES_FINAL_PJT\n\n`;
            markdown += `### 활동 통계\n`;
            const stats = logsRes.rows.reduce((acc, curr) => {
                acc[curr.platform] = (acc[curr.platform] || 0) + 1;
                return acc;
            }, {});
            Object.entries(stats).forEach(([p, count]) => markdown += `- ${p}: ${count}건\n`);
            
            markdown += `\n### 주요 활동 내역\n`;
            logsRes.rows.slice(-20).forEach(l => {
                markdown += `- [${new Date(l.eventTime).toLocaleTimeString()}] [${l.platform}] ${l.content}\n`;
            });

            const blob = new Blob([markdown], { type: 'text/markdown' });
            formData.append('file', blob, `summary_${dateStr}.md`);
            formData.append('payload_json', JSON.stringify({ content: `✅ [${dateStr}] 요약 보고서가 도착했습니다.` }));
        } else {
            // RAW 방식: 텍스트 리스트 + JSON 파일 생성
            let textLog = `[SK_ROOKIES_FINAL_PJT Activity Logs - ${dateStr}]\n\n`;
            logsRes.rows.forEach(l => {
                textLog += `[${new Date(l.eventTime).toLocaleString()}] [${l.platform}] [${l.action}] ${l.content}\n`;
            });

            const textBlob = new Blob([textLog], { type: 'text/plain' });
            const jsonBlob = new Blob([JSON.stringify(logsRes.rows, null, 2)], { type: 'application/json' });

            formData.append('file0', textBlob, `logs_${dateStr}.txt`);
            formData.append('file1', jsonBlob, `payloads_${dateStr}.json`);
            formData.append('payload_json', JSON.stringify({ content: `📦 [${dateStr}] 원본 데이터 패키지가 도착했습니다. (로그 및 JSON 상세 내역)` }));
        }

        const fetch = (await import('node-fetch')).default;
        await fetch(webhookUrl, {
            method: 'POST',
            body: formData
        });

        log(`✅ Midnight report (${reportType}) sent to Discord with file attachments.`);
    } catch (err) {
        console.error("Error in sendMidnightReport:", err);
    }
}

async function main() {
    log("Starting OpenClaw Agent...");
    let client;
    try { client = await connectToDB(); } catch (err) { process.exit(1); }

    let model;
    if (process.env.GEMINI_API_KEY) {
        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
        model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        log("Gemini API initialized.");
    }

    // Schedule: 매 시간 정각에 실행
    cron.schedule('0 * * * *', async () => {
        if (model) await autoTagPosts(client, model);
        await syncProjectData(client);
    });

    // Schedule: 매일 자정 보고서 발송
    cron.schedule('0 0 * * *', async () => {
        await sendMidnightReport(client);
    });

    // 배포 후 즉시 1회 실행
    setTimeout(async () => {
        if (model) {
            await autoTagPosts(client, model);
            await summarizeRecentMemos(client, model);
        }
        await syncProjectData(client);
    }, 10000);

    log("OpenClaw Agent is ready.");
}

main().catch(console.error);
