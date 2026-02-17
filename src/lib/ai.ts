import prisma from "@/lib/prisma";
import { GoogleGenerativeAI } from "@google/generative-ai";

/**
 * Gemini AI 호출 함수
 */
export async function callGemini(
  prompt: string,
  apiKey: string,
  modelName = "gemini-1.5-flash" // 가장 범용적인 1.5-flash로 복구
): Promise<string> {
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    // 모델 초기화 시 불필요한 접두사 없이 이름만 전달
    const model = genAI.getGenerativeModel({ model: modelName });
    
    const result = await model.generateContent(prompt);
    return result.response.text();
  } catch (error: any) {
    console.error("[GEMINI_API_ERROR]", error.message);
    
    // 할당량 초과(429)에 대한 구체적인 안내
    if (error.message?.includes("429")) {
        throw new Error("AI 사용량이 일시적으로 초과되었습니다. 1~2분 후 다시 시도해주세요.");
    }
    // 모델 없음(404)에 대한 처리
    if (error.message?.includes("404")) {
        throw new Error("지정된 AI 모델을 찾을 수 없습니다. API 키 설정을 확인해주세요.");
    }
    
    throw new Error(`AI 응답 생성 중 오류가 발생했습니다.`);
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

  let context = "당신은 '김한수'의 페르소나 AI 비서입니다. 아래는 최근 수집된 프로젝트 및 학습 정보입니다:\n\n";
  
  context += "--- 최근 프로젝트 및 회의 활동 로그 ---\n";
  if (projectLogs.length > 0) {
    projectLogs.forEach(l => context += `[${l.eventTime.toLocaleDateString()}] [${l.platform}] ${l.content}\n`);
  } else {
    context += "최근 활동 로그가 없습니다.\n";
  }

  context += "\n--- 학습 및 기술 노트 ---\n";
  notes.forEach(n => context += `- ${n.title}\n`);

  return context;
}

export async function chatWithPersona(userMessage: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("서버에 GEMINI_API_KEY가 설정되지 않았습니다.");

  const knowledgeContext = await getKnowledgeContext();
  
  const systemPrompt = `
    당신은 김한수 님의 페르소나입니다. 
    제공된 정보를 바탕으로 대화하되, 정보가 부족한 경우 사용자에게 직접 물어보거나 기록을 더 남겨달라고 요청하세요.
    수집된 정보(GitHub, Notion 등)에 대해 물어보면 '최근 활동 로그'를 요약하여 답변하세요.
    
    [참고 정보]
    ${knowledgeContext}
    
    사용자 질문: ${userMessage}
  `;

  return callGemini(systemPrompt, apiKey);
}

export async function processWithAI(prompt: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) return callGemini(prompt, apiKey);
  throw new Error("No Gemini API key found");
}
