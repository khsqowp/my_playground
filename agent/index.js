require('dotenv').config();
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { Client } = require('pg');
const cron = require('node-cron');

const log = (msg) => console.log(`[OpenClaw] ${new Date().toISOString()} - ${msg}`);

const RECONNECT_DELAY = 10000;
const MAX_RETRIES = 20;

async function connectToDB(retries = 0) {
    const client = new Client({ connectionString: process.env.DATABASE_URL });
    try {
        await client.connect();
        log("Connected to PostgreSQL Database.");
        return client;
    } catch (err) {
        if (retries < MAX_RETRIES) {
            log(`DB Connection retry... (${retries + 1}/${MAX_RETRIES})`);
            await new Promise(res => setTimeout(res, RECONNECT_DELAY));
            return connectToDB(retries + 1);
        } else throw err;
    }
}

// -------------------------------------------------------------------------
// 1. 블로그 자동 태깅 (로직 판별 후 최신 3개만 AI 처리)
// -------------------------------------------------------------------------
async function autoTagPosts(client, model) {
    log("Task: Auto-tag Blog Posts (Checking untagged)...");
    try {
        // 태그가 0개인 글을 최신순으로 3개 가져옴
        const res = await client.query(`
            SELECT p.id, p.title, p.content 
            FROM "Post" p
            LEFT JOIN "TagOnPost" tp ON p.id = tp."postId"
            WHERE p.published = true
            GROUP BY p.id, p.title, p.content, p."createdAt"
            HAVING COUNT(tp."tagId") = 0
            ORDER BY p."createdAt" DESC
            LIMIT 3
        `);

        if (res.rows.length === 0) {
            log("No untagged posts found. Skipping.");
            return;
        }

        for (const post of res.rows) {
            log(`AI Analyzing: ${post.title}`);
            const prompt = `다음 블로그 글의 핵심 IT 기술 태그 5개를 콤마로 구분해서 써줘: ${post.title}\n\n내용: ${post.content.substring(0, 1500)}`;
            const result = await model.generateContent(prompt);
            const tags = result.response.text().split(',').map(t => t.trim()).filter(t => t.length > 0);

            for (const tagName of tags) {
                const tagId = 'tag_' + Date.now() + Math.random().toString(36).substring(7);
                await client.query('INSERT INTO "Tag" (id, name) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name', [tagId, tagName]);
                const realTag = await client.query('SELECT id FROM "Tag" WHERE name = $1', [tagName]);
                await client.query('INSERT INTO "TagOnPost" ("postId", "tagId") VALUES ($1, $2) ON CONFLICT DO NOTHING', [post.id, realTag.rows[0].id]);
            }
            log(`✅ Successfully tagged: ${post.title}`);
            await new Promise(r => setTimeout(r, 5000));
        }
    } catch (err) { log(`❌ Auto-tag Error: ${err.message}`); }
}

// -------------------------------------------------------------------------
// 2. 데이터 자동 수집 (30분 주기, AI 미사용, 상세 내용 중심)
// -------------------------------------------------------------------------
async function syncProjectData(client) {
    log("Task: Periodic Data Sync (Every 30m)...");
    try {
        const projects = await client.query(`SELECT id, name FROM "Project"`);
        for (const project of projects.rows) {
            const settingsRes = await client.query(`SELECT key, value FROM "ProjectSetting" WHERE "projectId" = $1`, [project.id]);
            const settings = {};
            settingsRes.rows.forEach(r => settings[r.key] = r.value);

            const githubRepo = settings[`${project.name}_GITHUB_REPO`];
            
            // GitHub 상세 수집 (수정된 파일 목록 포함)
            if (githubRepo) {
                const commitsRes = await fetch(`https://api.github.com/repos/${githubRepo}/commits?per_page=5`);
                if (commitsRes.ok) {
                    const commits = await commitsRes.json();
                    for (const c of commits) {
                        // 커밋 상세 정보 가져오기 (파일 목록 확인용)
                        const detailRes = await fetch(`https://api.github.com/repos/${githubRepo}/commits/${c.sha}`);
                        let fileInfo = "";
                        if (detailRes.ok) {
                            const detail = await detailRes.json();
                            const files = detail.files.map(f => `${f.filename} (${f.status})`).join(', ');
                            fileInfo = `\n[수정된 파일] ${files}`;
                        }

                        await client.query(
                            `INSERT INTO "ProjectActivityLog" (id, platform, action, content, "externalId", "eventTime", "projectId", "createdAt", "rawPayload") 
                             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8) ON CONFLICT DO NOTHING`,
                            ['log_' + Date.now(), 'GITHUB', 'COMMIT', `[Auto] ${c.commit.message}${fileInfo}`, c.sha, new Date(c.commit.author.date), project.id, c]
                        );
                    }
                }
            }
            // Notion 수집 로직은 API 엔드포인트 방식과 동일하게 복잡하므로, 
            // 여기서는 서버의 /api/automation/meetings/sync 를 내부적으로 호출하거나 
            // 공통 라이브러리화를 고려해야 하지만, 일단 기본 로그만 남깁니다.
            log(`✅ Sync check done for ${project.name}`);
        }
    } catch (err) { log(`❌ Sync Error: ${err.message}`); }
}

// -------------------------------------------------------------------------
// 3. 자정 정기 보고서 (AI 미사용, 원본 데이터 전송)
// -------------------------------------------------------------------------
async function sendMidnightReport(client) {
    log("Task: Midnight RAW Report...");
    try {
        const projects = await client.query(`SELECT id, name FROM "Project"`);
        for (const project of projects.rows) {
            const webhookRes = await client.query(`SELECT value FROM "ProjectSetting" WHERE "projectId" = $1 AND key LIKE '%DISCORD_WEBHOOK_URL%'`, [project.id]);
            if (webhookRes.rows.length === 0) continue;
            const webhookUrl = webhookRes.rows[0].value;

            const logsRes = await client.query(
                `SELECT platform, action, content, "eventTime" FROM "ProjectActivityLog" 
                 WHERE "projectId" = $1 AND "createdAt" >= NOW() - INTERVAL '24 hours' ORDER BY "eventTime" ASC`,
                [project.id]
            );

            if (logsRes.rows.length === 0) continue;

            const dateStr = new Date().toISOString().split('T')[0];
            let rawLogs = `[RAW LOGS - ${dateStr}]\n\n`;
            logsRes.rows.forEach(l => {
                rawLogs += `[${new Date(l.eventTime).toLocaleString()}] [${l.platform}] [${l.action}] ${l.content}\n`;
            });

            // 텍스트 내용 전송 (2000자 초과 시 잘림 방지는 추후 보완)
            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    content: `🌙 **자정 원본 활동 기록 (${dateStr})**\n기록 건수: ${logsRes.rows.length}건\nAI 요약 없는 원본 로그입니다.`,
                    files: [] // FormData 방식이 복잡하여 일단 텍스트로 시도
                })
            });
        }
    } catch (err) { log(`❌ Midnight Report Error: ${err.message}`); }
}

// -------------------------------------------------------------------------
// 메인 루프
// -------------------------------------------------------------------------
async function main() {
    log("Starting OpenClaw Agent...");
    let client;
    try { client = await connectToDB(); } catch (err) { process.exit(1); }

    let model;
    if (process.env.GEMINI_API_KEY) {
        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
        model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });
        log("Gemini API (gemini-flash-latest) initialized.");
    }

    // 30분마다 데이터 수집
    cron.schedule('*/30 * * * *', () => syncProjectData(client));
    
    // 새벽 4시 자동 태깅
    cron.schedule('0 4 * * *', () => model && autoTagPosts(client, model));
    
    // 자정 정기 보고 (원본)
    cron.schedule('0 0 * * *', () => sendMidnightReport(client));

    log("OpenClaw is standby. Tasks: 30m Sync, 4am Tagging, 0am Report.");
}

main().catch(err => console.error(err));
