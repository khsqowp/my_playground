import prisma from "@/lib/prisma";
import { GoogleGenerativeAI } from "@google/generative-ai";

/**
 * Gemini AI 호출 함수
 */
export async function callGemini(
  prompt: string,
  apiKey: string,
  modelName = "gemini-1.5-flash"
): Promise<string> {
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    // 모델 이름을 명확하게 지정
    const model = genAI.getGenerativeModel({ model: modelName });
    
    const result = await model.generateContent(prompt);
    return result.response.text();
  } catch (error: any) {
    console.error("[GEMINI_API_ERROR]", error);
    throw new Error(`AI 응답 생성 중 오류: ${error.message}`);
  }
}

/**
 * 사용자 데이터(학습 노트, 포트폴리오, 프로젝트 로그)를 수집하여 지식 베이스 컨텍스트 생성
 */
async function getKnowledgeContext() {
  const [notes, portfolios, posts, projectLogs] = await Promise.all([
    prisma.note.findMany({ take: 5, orderBy: { createdAt: 'desc' } }),
    prisma.portfolio.findMany({ take: 3, orderBy: { createdAt: 'desc' } }),
    prisma.post.findMany({ where: { published: true }, take: 5, orderBy: { createdAt: 'desc' } }),
    prisma.projectActivityLog.findMany({ take: 20, orderBy: { eventTime: 'desc' } }), // 추가된 활동 로그
  ]);

  let context = "당신은 사용자 '김한수'의 모든 기록을 알고 있는 페르소나 AI입니다. 아래는 수집된 최신 정보들입니다:\n\n";
  
  context += "--- 프로젝트 및 회의 활동 기록 (최신 20건) ---\n";
  projectLogs.forEach(l => context += `[${l.eventTime.toLocaleDateString()}] [${l.platform}] ${l.content}\n`);

  context += "\n--- 최근 학습 노트 ---\n";
  notes.forEach(n => context += `제목: ${n.title}\n내용: ${n.content.substring(0, 200)}\n\n`);
  
  context += "--- 포트폴리오 ---\n";
  portfolios.forEach(p => context += `프로젝트명: ${p.title} (${p.techStack})\n`);

  context += "\n--- 블로그 게시글 ---\n";
  posts.forEach(p => context += `제목: ${p.title}\n`);

  return context;
}

/**
 * 페르소나 AI와 대화하기
 */
export async function chatWithPersona(userMessage: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY가 설정되지 않았습니다.");

  const knowledgeContext = await getKnowledgeContext();
  
  const systemPrompt = `
    당신은 '김한수'의 개인 비서이자 페르소나입니다. 
    제공된 [최신 정보]를 바탕으로 김한수 님의 활동과 지식을 대변하여 답변하세요.
    수집된 정보에 대해 물어보면 '프로젝트 활동 로그' 섹션의 내용을 요약해서 알려주세요.
    말투는 친절하면서도 명확하게 하세요.
    
    [최신 정보]
    ${knowledgeContext}
    
    사용자 질문: ${userMessage}
  `;

  return callGemini(systemPrompt, apiKey);
}

export async function processWithAI(prompt: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) {
    return callGemini(prompt, apiKey);
  }
  throw new Error("No Gemini API configuration found");
}
