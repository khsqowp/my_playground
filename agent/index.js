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
        log("Connected to PostgreSQL.");
        return client;
    } catch (err) {
        if (retries < MAX_RETRIES) {
            log(`DB Retry... (${retries + 1}/${MAX_RETRIES})`);
            await new Promise(res => setTimeout(res, RECONNECT_DELAY));
            return connectToDB(retries + 1);
        } else throw err;
    }
}

// Skill: Auto-tag Blog Posts
async function autoTagPosts(client, model) {
    log("Running Skill: Auto-tag Blog Posts...");
    try {
        const res = await client.query(`
            SELECT p.id, p.title, p.content 
            FROM "Post" p
            LEFT JOIN "TagOnPost" tp ON p.id = tp."postId"
            WHERE p.published = true
            GROUP BY p.id, p.title, p.content
            HAVING COUNT(tp."tagId") < 2
            LIMIT 3
        `);

        if (res.rows.length === 0) return;

        for (const post of res.rows) {
            log(`Analyzing: ${post.title}`);
            const prompt = `다음 블로그 글의 핵심 IT 기술 태그 5개를 콤마로 구분해서 써줘: ${post.title}\n\n내용: ${post.content.substring(0, 1000)}`;
            
            const result = await model.generateContent(prompt);
            const tags = result.response.text().split(',').map(t => t.trim()).filter(t => t.length > 0);

            for (const tagName of tags) {
                let tagRes = await client.query('SELECT id FROM "Tag" WHERE name = $1', [tagName]);
                let tagId = tagRes.rows.length > 0 ? tagRes.rows[0].id : 'tag_' + Date.now() + Math.random().toString(36).substring(7);
                if (tagRes.rows.length === 0) {
                    await client.query('INSERT INTO "Tag" (id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING', [tagId, tagName]);
                }
                await client.query('INSERT INTO "TagOnPost" ("postId", "tagId") VALUES ($1, $2) ON CONFLICT DO NOTHING', [post.id, tagId]);
            }
            log(`✅ Tagged: ${post.title}`);
            await new Promise(r => setTimeout(r, 5000)); // 요청 간 간격 (할당량 보호)
        }
    } catch (err) { log(`❌ Error: ${err.message}`); }
}

async function main() {
    log("Starting OpenClaw...");
    let client;
    try { client = await connectToDB(); } catch (err) { process.exit(1); }

    let model;
    if (process.env.GEMINI_API_KEY) {
        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
        model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        log("Gemini API initialized (1.5-flash).");
    }

    // 매일 오전 4시에 한 번만 자동 태깅 실행 (사용자 활동이 적은 시간)
    cron.schedule('0 4 * * *', async () => {
        if (model) await autoTagPosts(client, model);
    });

    log("OpenClaw is standby. Automatic tasks scheduled.");
}

main().catch(err => console.error(err));
