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
        // 태그가 없는 포스트 조회
        const res = await client.query(`
            SELECT p.id, p.title, p.content 
            FROM "Post" p
            LEFT JOIN "TagOnPost" tp ON p.id = tp."postId"
            WHERE tp."tagId" IS NULL AND p.published = true
            LIMIT 5
        `);

        if (res.rows.length === 0) {
            log("No untagged posts found.");
            return;
        }

        for (const post of res.rows) {
            log(`Analyzing tags for post: ${post.title}`);
            
            const prompt = `
                다음 블로그 글의 내용을 분석하여 가장 적절한 해시태그 5~10개를 추출해줘.
                결과는 오직 콤마(,)로 구분된 단어들만 출력해. 예: Docker,배포,CI/CD,Next.js,서버
                
                글 제목: ${post.title}
                글 내용: ${post.content.substring(0, 1000)}
            `;

            const result = await model.generateContent(prompt);
            const tags = result.response.text().split(',').map(t => t.trim());

            for (const tagName of tags) {
                const tagRes = await client.query(
                    'INSERT INTO "Tag" (id, name) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET name = $2 RETURNING id',
                    ['tag_' + Date.now() + Math.random().toString(36).substring(7), tagName]
                );
                const tagId = tagRes.rows[0].id;

                await client.query(
                    'INSERT INTO "TagOnPost" ("postId", "tagId") VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [post.id, tagId]
                );
            }
            log(`✅ Successfully tagged: ${post.title}`);
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

    // Schedule: 매 시간 정각에 자동 태깅 실행
    cron.schedule('0 * * * *', async () => {
        if (model) await autoTagPosts(client, model);
    });

    // 배포 후 즉시 1회 실행
    setTimeout(async () => {
        if (model) {
            await autoTagPosts(client, model);
            await summarizeRecentMemos(client, model);
        }
    }, 10000);

    log("OpenClaw Agent is ready.");
}

main().catch(console.error);
