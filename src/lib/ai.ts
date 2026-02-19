import prisma from "@/lib/prisma";
import { GoogleGenerativeAI } from "@google/generative-ai";

/**
 * Gemini AI 호출
 */
export async function callGemini(
  prompt: string,
  apiKey: string,
  modelName = "gemini-flash-latest"
): Promise<string> {
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: modelName });
    const result = await model.generateContent(prompt);
    return result.response.text();
  } catch (error: any) {
    console.error("[GEMINI_API_ERROR]", error.message);
    if (error.message?.includes("429") || error.message?.includes("quota")) {
      throw new Error("RATE_LIMIT");
    }
    if (error.message?.includes("404") && modelName !== "gemini-2.5-flash") {
      return callGemini(prompt, apiKey, "gemini-2.5-flash");
    }
    throw new Error(`Gemini 오류: ${error.message}`);
  }
}

/**
 * Groq AI 호출 (Llama 3.3 70B)
 */
export async function callGroq(
  prompt: string,
  apiKey: string,
  modelName = "llama-3.3-70b-versatile"
): Promise<string> {
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: modelName,
      messages: [{ role: "user", content: prompt }],
      temperature: 0.7,
      max_tokens: 2048,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    if (res.status === 429) throw new Error("RATE_LIMIT");
    throw new Error(`Groq 오류: ${res.status} ${err}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content ?? "";
}

/**
 * 라운드로빈 인덱스 — 요청마다 서로 다른 프로바이더부터 시작해 RPM 분산
 */
let rrIndex = 0;

/**
 * 통합 AI 호출 — 라운드로빈 + fallback
 *
 * 프로바이더: GEMINI_API_KEY → GROQ_API_KEY → GEMINI_API_KEY2 → GEMINI_API_KEY3 → GEMINI_API_KEY4
 * 매 성공 후 다음 호출은 다음 프로바이더부터 시작 (RPM 분산).
 * 각 단계에서 429(쿼터 초과)가 발생하면 다음 제공자로 넘어감.
 */
export async function callAI(prompt: string): Promise<string> {
  type Provider = { name: string; call: () => Promise<string> };

  const providers: Provider[] = [];

  if (process.env.GEMINI_API_KEY) {
    providers.push({
      name: "Gemini (KEY1)",
      call: () => callGemini(prompt, process.env.GEMINI_API_KEY!),
    });
  }
  if (process.env.GROQ_API_KEY) {
    providers.push({
      name: "Groq (Llama 3.3 70B)",
      call: () => callGroq(prompt, process.env.GROQ_API_KEY!),
    });
  }
  if (process.env.GEMINI_API_KEY2) {
    providers.push({
      name: "Gemini (KEY2)",
      call: () => callGemini(prompt, process.env.GEMINI_API_KEY2!),
    });
  }
  if (process.env.GEMINI_API_KEY3) {
    providers.push({
      name: "Gemini (KEY3)",
      call: () => callGemini(prompt, process.env.GEMINI_API_KEY3!),
    });
  }
  if (process.env.GEMINI_API_KEY4) {
    providers.push({
      name: "Gemini (KEY4)",
      call: () => callGemini(prompt, process.env.GEMINI_API_KEY4!),
    });
  }

  if (providers.length === 0) {
    throw new Error(
      "AI API 키가 설정되지 않았습니다. (GEMINI_API_KEY, GROQ_API_KEY, GEMINI_API_KEY2~4 중 하나 필요)"
    );
  }

  let lastError: Error | null = null;
  const startIdx = rrIndex % providers.length;

  for (let i = 0; i < providers.length; i++) {
    const idx = (startIdx + i) % providers.length;
    const provider = providers[idx];
    try {
      const result = await provider.call();
      console.log(`[AI] 성공: ${provider.name}`);
      rrIndex = (idx + 1) % providers.length;
      return result;
    } catch (e: any) {
      if (e.message === "RATE_LIMIT") {
        console.warn(`[AI] 쿼터 초과: ${provider.name} → 다음 제공자로 전환`);
        lastError = e;
        continue;
      }
      // 쿼터 외 에러는 바로 throw
      throw e;
    }
  }

  throw new Error(
    `모든 AI 제공자의 쿼터가 초과되었습니다. 잠시 후 다시 시도해주세요.\n(${providers.map((p) => p.name).join(" → ")} 모두 소진)`
  );
}

/**
 * 사용자 데이터 컨텍스트 생성
 */
async function getKnowledgeContext() {
  const [notes, portfolios, posts, projectLogs] = await Promise.all([
    prisma.note.findMany({ take: 5, orderBy: { createdAt: "desc" } }),
    prisma.portfolio.findMany({ take: 3, orderBy: { createdAt: "desc" } }),
    prisma.post.findMany({ where: { published: true }, take: 5, orderBy: { createdAt: "desc" } }),
    prisma.projectActivityLog.findMany({ take: 30, orderBy: { eventTime: "desc" } }),
  ]);

  let context = "당신은 김한수 님의 페르소나 AI입니다. 최근 정보는 다음과 같습니다:\n\n";
  context += "--- 활동 로그 ---\n";
  projectLogs.forEach((l) => (context += `[${l.platform}] ${l.content}\n`));
  context += "\n--- 최근 노트 ---\n";
  notes.forEach((n) => (context += `- ${n.title}\n`));

  return context;
}

export async function chatWithPersona(userMessage: string): Promise<string> {
  const knowledgeContext = await getKnowledgeContext();
  const systemPrompt = `
    당신은 김한수 님의 페르소나입니다.
    제공된 정보를 바탕으로 답변하세요. 정보가 없다면 정직하게 모른다고 하세요.

    [정보]
    ${knowledgeContext}

    질문: ${userMessage}
  `;
  return callAI(systemPrompt);
}

export async function processWithAI(prompt: string): Promise<string> {
  return callAI(prompt);
}
