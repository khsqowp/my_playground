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
    if (error.message?.includes("429")) {
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
    throw new Error(`Groq 오류: ${res.status} ${err}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content ?? "";
}

/**
 * 통합 AI 호출 — Gemini 우선, 429(쿼터 초과) 시 Groq로 자동 fallback
 */
export async function callAI(prompt: string): Promise<string> {
  const geminiKey = process.env.GEMINI_API_KEY;
  const groqKey = process.env.GROQ_API_KEY;

  if (geminiKey) {
    try {
      const result = await callGemini(prompt, geminiKey);
      return result;
    } catch (e: any) {
      if (e.message === "RATE_LIMIT" && groqKey) {
        console.warn("[AI] Gemini 쿼터 초과 → Groq fallback");
        return callGroq(prompt, groqKey);
      }
      // Groq도 없으면 원래 에러 메시지로 변환
      if (e.message === "RATE_LIMIT") {
        throw new Error("AI 사용량이 초과되었습니다. 잠시 후 다시 시도해주세요.");
      }
      throw e;
    }
  }

  if (groqKey) {
    return callGroq(prompt, groqKey);
  }

  throw new Error("AI API 키가 설정되지 않았습니다. (GEMINI_API_KEY 또는 GROQ_API_KEY 필요)");
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
