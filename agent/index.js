require('dotenv').config();
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { Client } = require('pg');
const cron = require('node-cron');

// Logging helper
const log = (msg) => console.log(`[OpenClaw] ${new Date().toISOString()} - ${msg}`);

const RECONNECT_DELAY = 10000;
const MAX_RETRIES = 20;

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
            log(`DB Connection failed (${err.message}). Retrying... (${retries + 1}/${MAX_RETRIES})`);
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
        // 태그가 3개 미만인 포스트 찾기
        const res = await client.query(`
            SELECT p.id, p.title, p.content 
            FROM "Post" p
            LEFT JOIN "TagOnPost" tp ON p.id = tp."postId"
            WHERE p.published = true
            GROUP BY p.id, p.title, p.content
            HAVING COUNT(tp."tagId") < 3
            LIMIT 5
        `);

        log(`Found ${res.rows.length} posts needing tags.`);

        for (const post of res.rows) {
            log(`Analyzing tags for post: ${post.title}`);
            const prompt = `다음 블로그 글의 내용을 분석하여 가장 적절한 IT 기술 해시태그 5개를 추출해줘. 결과는 오직 콤마(,)로 구분된 단어들만 출력해. 예: Docker,배포,CI/CD,Next.js,서버\n\n제목: ${post.title}\n내용: ${post.content.substring(0, 1500)}`;

            const result = await model.generateContent(prompt);
            const responseText = result.response.text();
            const tags = responseText.split(',').map(t => t.trim()).filter(t => t.length > 0);
            log(`Gemini suggested tags: ${tags.join(', ')}`);

            for (const tagName of tags) {
                // 태그 존재 확인 및 생성
                let tagRes = await client.query('SELECT id FROM "Tag" WHERE name = $1', [tagName]);
                let tagId;
                if (tagRes.rows.length === 0) {
                    tagId = 'tag_' + Date.now() + Math.random().toString(36).substring(7);
                    await client.query('INSERT INTO "Tag" (id, name) VALUES ($1, $2)', [tagId, tagName]);
                } else {
                    tagId = tagRes.rows[0].id;
                }

                // 포스트에 태그 연결
                await client.query(
                    'INSERT INTO "TagOnPost" ("postId", "tagId") VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [post.id, tagId]
                );
            }
            log(`✅ Tags updated for: ${post.title}`);
        }
    } catch (err) {
        log(`❌ Error in autoTagPosts: ${err.message}`);
    }
}

// Skill: Sync Project Data
async function syncProjectData(client) {
    log("Running Skill: Sync Project Data (Automatic)...");
    // 기존 동기화 로직 (필요 시 보강)
}

async function main() {
    log("Starting OpenClaw Agent...");
    let client;
    try { client = await connectToDB(); } catch (err) { process.exit(1); }

    let model;
    if (process.env.GEMINI_API_KEY) {
        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
        // 모델 이름 문자열 확인 및 명시적 초기화
        model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        log("Gemini API initialized.");
    } else {
        log("⚠️ GEMINI_API_KEY is missing! Auto-tagging will not work.");
    }

    // 매 시간 정각 실행
    cron.schedule('0 * * * *', async () => {
        if (model) await autoTagPosts(client, model);
    });

    // 시작 10초 후 즉시 1회 실행 (테스트용)
    setTimeout(async () => {
        log("Running initial check...");
        if (model) await autoTagPosts(client, model);
    }, 10000);
}

main().catch(err => console.error("Main Error:", err));
