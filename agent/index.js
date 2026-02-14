require('dotenv').config();
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { Client } = require('pg');
const cron = require('node-cron');

// Logging helper
const log = (msg) => console.log(`[OpenClaw] ${new Date().toISOString()} - ${msg}`);

// Configuration
const RECONNECT_DELAY = 5000; // 5 seconds
const MAX_RETRIES = 10;
const GEMINI_RATE_LIMIT_DELAY = 1000; // 1 second between calls

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

// Skill: Summarize Recent Memos
async function summarizeRecentMemos(client, model) {
    log("Running Skill: Summarize Recent Memos...");

    try {
        // 1. Fetch memos from last 24 hours
        const res = await client.query(`
      SELECT content, "createdAt" 
      FROM "Memo" 
      WHERE "createdAt" > NOW() - INTERVAL '24 hours'
      ORDER BY "createdAt" DESC
    `);

        if (res.rows.length === 0) {
            log("No recent memos found to summarize.");
            return;
        }

        const memoText = res.rows.map(r => `- ${r.content} (${new Date(r.createdAt).toLocaleTimeString()})`).join('\n');
        log(`Found ${res.rows.length} memos. Generating summary...`);

        // 2. Generate Summary with Gemini
        const prompt = `
      다음은 최근 24시간 동안 작성된 나의 메모들이다. 
      이 메모들을 바탕으로 '오늘의 주요 활동 및 생각'을 3줄 요약해줘.
      그리고 핵심 태그 3개를 추출해줘.
      
      [메모 목록]
      ${memoText}
    `;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const summary = response.text();

        log("=== Daily Summary ===");
        log(summary);
        log("=====================");

        // TODO: Save this summary to a 'Note' or 'DailyLog' table in DB
        // await client.query('INSERT INTO "Note" ...');

    } catch (err) {
        console.error("Error in summarizeRecentMemos:", err);
    }
}

async function main() {
    log("Starting OpenClaw Agent...");

    // 1. Connect to Database with Retry
    let client;
    try {
        client = await connectToDB();
    } catch (err) {
        console.error(err.message);
        process.exit(1);
    }

    // 2. Initialize Gemini API
    let model;
    if (!process.env.GEMINI_API_KEY) {
        log("WARNING: GEMINI_API_KEY is not set. AI skills will be disabled.");
    } else {
        try {
            const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
            model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
            log("Gemini API initialized successfully.");
        } catch (err) {
            console.error("Failed to initialize Gemini:", err);
        }
    }

    // 3. Setup Scheduler
    // Run every morning at 9:00 AM
    cron.schedule('0 9 * * *', async () => {
        if (model) await summarizeRecentMemos(client, model);
    });

    // For testing: Run immediately on startup (after 5s delay)
    setTimeout(async () => {
        if (model) await summarizeRecentMemos(client, model);
    }, 5000);

    log("OpenClaw Agent is running and ready. Scheduled tasks active.");
}

main().catch(console.error);
