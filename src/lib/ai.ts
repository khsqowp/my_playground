import prisma from "@/lib/prisma";
import { GoogleGenerativeAI } from "@google/generative-ai";

/**
 * Gemini AI 호출 함수
 */
export async function callGemini(
  prompt: string,
  apiKey: string,
  modelName = "gemini-2.0-flash" // 사용자 가이드에 맞춰 2.0으로 업그레이드
): Promise<string> {
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: modelName });
    
    const result = await model.generateContent(prompt);
    return result.response.text();
  } catch (error: any) {
    console.error("[GEMINI_API_ERROR]", error);
    // 404 에러 시 1.5-flash로 폴백 시도
    if (error.message?.includes("404") && modelName !== "gemini-1.5-flash") {
        console.log("Retrying with gemini-1.5-flash...");
        return callGemini(prompt, apiKey, "gemini-1.5-flash");
    }
    throw new Error(`AI 응답 생성 중 오류: ${error.message}`);
  }
}

/**
 * 사용자 데이터 컨텍스트 생성
 */
async function getKnowledgeContext() {
  const [notes, portfolios, posts, projectLogs] = await Promise.all([
    prisma.note.findMany({ take: 5, orderBy: { createdAt: 'desc' } }),
    prisma.portfolio.findMany({ take: 3, orderBy: { createdAt: 'desc' } }),
    prisma.post.findMany({ where: { published: true }, take: 5, orderBy: { createdAt: 'desc' } }),
    prisma.projectActivityLog.findMany({ take: 20, orderBy: { eventTime: 'desc' } }),
  ]);

  let context = "당신은 '김한수'의 페르소나 AI입니다. 아래는 최근 수집된 활동 정보입니다:\n\n";
  
  context += "--- 최근 활동 로그 ---\n";
  projectLogs.forEach(l => context += `[${l.platform}] ${l.content}\n`);

  context += "\n--- 학습 노트 ---\n";
  notes.forEach(n => context += `- ${n.title}\n`);

  return context;
}

export async function chatWithPersona(userMessage: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY missing");

  const knowledgeContext = await getKnowledgeContext();
  
  const systemPrompt = `
    당신은 김한수 님의 페르소나입니다. 
    제공된 정보를 바탕으로 답변하세요. 질문에 정보가 없다면 모른다고 하세요.
    
    [정보]
    ${knowledgeContext}
    
    사용자 질문: ${userMessage}
  `;

  return callGemini(systemPrompt, apiKey);
}

export async function processWithAI(prompt: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) return callGemini(prompt, apiKey);
  throw new Error("No Gemini API key");
}
