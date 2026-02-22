import 'dotenv/config';
import { GoogleGenAI } from "@google/genai";
import pkg from 'pg';
const { Client } = pkg;
import cron from 'node-cron';
import { Client as DiscordClient, GatewayIntentBits } from 'discord.js';

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
// 1. 블로그 자동 태깅 (앱 내부 API 호출 — callAI 라운드로빈 활용)
// -------------------------------------------------------------------------
async function autoTagPosts() {
    log("Task: Auto-tag Blog Posts via API...");
    try {
        const appUrl = process.env.APP_INTERNAL_URL || 'http://app:3000';
        const serviceKey = process.env.SERVICE_API_KEY || '';
        const res = await fetch(`${appUrl}/api/cron/blog-tags`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-service-key': serviceKey,
            },
        });
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const data = await res.json();
        log(`✅ Blog tags: ${data.message}`);
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
                            ['log_' + Date.now(), 'GITHUB', 'COMMIT', `[Auto] ${c.commit.message}${fileInfo}`, c.sha, new Date(c.commit.author.date), project.id, JSON.stringify(c)]
                        );
                    }
                }
            }
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

            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    content: `🌙 **자정 원본 활동 기록 (${dateStr})**\n기록 건수: ${logsRes.rows.length}건\nAI 요약 없는 원본 로그입니다.`
                })
            });
        }
    } catch (err) { log(`❌ Midnight Report Error: ${err.message}`); }
}

// -------------------------------------------------------------------------
// 4. Discord 봇 (!ask / !quiz / !note)
// -------------------------------------------------------------------------
async function startDiscordBot() {
    const token = process.env.DISCORD_BOT_TOKEN;
    if (!token) {
        log("DISCORD_BOT_TOKEN not set, skipping Discord bot.");
        return;
    }

    const appUrl = process.env.APP_INTERNAL_URL || 'http://app:3000';
    const serviceKey = process.env.SERVICE_API_KEY || '';

    const bot = new DiscordClient({
        intents: [
            GatewayIntentBits.Guilds,
            GatewayIntentBits.GuildMessages,
            GatewayIntentBits.MessageContent,
        ]
    });

    bot.once('ready', () => {
        log(`Discord bot logged in as ${bot.user.tag}`);
    });

    bot.on('messageCreate', async (message) => {
        if (message.author.bot) return;
        const content = message.content.trim();
        if (!content.startsWith('!')) return;

        const parts = content.split(' ');
        const command = parts[0].toLowerCase();
        const args = parts.slice(1).join(' ');

        try {
            if (command === '!ask') {
                if (!args) {
                    await message.reply('사용법: `!ask <질문>`');
                    return;
                }
                const res = await fetch(`${appUrl}/api/persona/chat`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-service-key': serviceKey
                    },
                    body: JSON.stringify({ message: args })
                });
                if (!res.ok) throw new Error(`API error: ${res.status}`);
                const data = await res.json();
                await message.reply(data.response.substring(0, 1900));

            } else if (command === '!quiz') {
                if (!args) {
                    await message.reply('사용법: `!quiz <주제> [문제수]` (예: `!quiz TypeScript 5`)');
                    return;
                }

                const argParts = args.split(' ');
                let topic = args;
                let count = 5;
                const lastPart = argParts[argParts.length - 1];
                if (/^\d+$/.test(lastPart)) {
                    count = Math.min(20, Math.max(1, parseInt(lastPart)));
                    topic = argParts.slice(0, -1).join(' ');
                }

                await message.reply(`⏳ "${topic}" 주제로 ${count}개 퀴즈를 생성 중입니다...`);

                const res = await fetch(`${appUrl}/api/archive/quiz/generate`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-service-key': serviceKey
                    },
                    body: JSON.stringify({ topic, count })
                });
                if (!res.ok) throw new Error(`API error: ${res.status}`);
                const quizSet = await res.json();

                let reply = `📝 **${quizSet.title}** (${quizSet._count?.questions || quizSet.questions?.length || count}문제)\n\n`;
                const questions = quizSet.questions || [];
                questions.forEach((q, i) => {
                    reply += `**Q${i + 1}.** ${q.question}\n`;
                    if (q.hint) reply += `💡 힌트: ${q.hint}\n`;
                    reply += `||✅ ${q.answer}||\n\n`;
                });

                await message.reply(reply.substring(0, 1900));

            } else if (command === '!note') {
                if (!args) {
                    await message.reply('사용법: `!note <내용>`');
                    return;
                }
                const res = await fetch(`${appUrl}/api/archive/notes`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-service-key': serviceKey
                    },
                    body: JSON.stringify({
                        title: `[Discord] ${args.substring(0, 50)}`,
                        content: args,
                        visibility: 'PRIVATE'
                    })
                });
                if (!res.ok) throw new Error(`API error: ${res.status}`);
                await message.reply(`✅ 노트가 저장되었습니다: "${args.substring(0, 50)}..."`);
            }
        } catch (err) {
            log(`❌ Discord bot error: ${err.message}`);
            await message.reply(`오류가 발생했습니다: ${err.message.substring(0, 200)}`);
        }
    });

    bot.on('error', (err) => log(`Discord bot error: ${err.message}`));

    await bot.login(token);
    log("Discord bot started.");
}

// -------------------------------------------------------------------------
// 메인 루프
// -------------------------------------------------------------------------
async function main() {
    log("Starting OpenClaw Agent...");
    let client;
    try { client = await connectToDB(); } catch (err) { process.exit(1); }

    if (process.env.GEMINI_API_KEY) {
        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
        log("Gemini API (unified SDK) initialized.");
    }

    cron.schedule('*/30 * * * *', () => syncProjectData(client));
    cron.schedule('0 2 * * *', () => autoTagPosts());
    cron.schedule('0 0 * * *', () => sendMidnightReport(client));

    await startDiscordBot();

    log("OpenClaw is standby. Tasks: 30m Sync, 2am Tagging, 0am Report, Discord Bot.");
}

main().catch(err => console.error(err));
