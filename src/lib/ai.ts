import prisma from "@/lib/prisma";
import { GoogleGenerativeAI } from "@google/generative-ai";

/**
 * Gemini AI 호출 함수
 */
export async function callGemini(
  prompt: string,
  apiKey: string,
  modelName = "gemini-flash-latest" // 목록에 있는 안정적인 최신 모델로 변경
): Promise<string> {
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: modelName });
    
    const result = await model.generateContent(prompt);
    return result.response.text();
  } catch (error: any) {
    console.error("[GEMINI_API_ERROR]", error.message);
    
    if (error.message?.includes("429")) {
        throw new Error("AI 사용량이 초과되었습니다. 잠시 후 다시 시도해주세요.");
    }
    if (error.message?.includes("404")) {
        // 404 발생 시 gemini-2.5-flash로 마지막 시도
        if (modelName !== "gemini-2.5-flash") {
            return callGemini(prompt, apiKey, "gemini-2.5-flash");
        }
    }
    
    throw new Error(`AI 응답 생성 중 오류가 발생했습니다: ${error.message}`);
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
    prisma.projectActivityLog.findMany({ take: 30, orderBy: { eventTime: 'desc' } }),
  ]);

  let context = "당신은 김한수 님의 페르소나 AI입니다. 최근 정보는 다음과 같습니다:\n\n";
  context += "--- 활동 로그 ---\n";
  projectLogs.forEach(l => context += `[${l.platform}] ${l.content}\n`);
  context += "\n--- 최근 노트 ---\n";
  notes.forEach(n => context += `- ${n.title}\n`);

  return context;
}

export async function chatWithPersona(userMessage: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY missing");

  const knowledgeContext = await getKnowledgeContext();
  
  const systemPrompt = `
    당신은 김한수 님의 페르소나입니다. 
    제공된 정보를 바탕으로 답변하세요. 정보가 없다면 정직하게 모른다고 하세요.
    
    [정보]
    ${knowledgeContext}
    
    질문: ${userMessage}
  `;

  return callGemini(systemPrompt, apiKey);
}

export async function processWithAI(prompt: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) return callGemini(prompt, apiKey);
  throw new Error("No Gemini API key");
}
