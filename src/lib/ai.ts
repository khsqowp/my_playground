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
  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({ model: modelName });
  
  const result = await model.generateContent(prompt);
  const response = await result.response;
  return response.text();
}

/**
 * 사용자 데이터(학습 노트, 포트폴리오)를 수집하여 지식 베이스 컨텍스트 생성
 */
async function getKnowledgeContext() {
  const [notes, portfolios, posts] = await Promise.all([
    prisma.note.findMany({ take: 10, orderBy: { createdAt: 'desc' } }),
    prisma.portfolio.findMany({ take: 5, orderBy: { createdAt: 'desc' } }),
    prisma.post.findMany({ where: { published: true }, take: 5, orderBy: { createdAt: 'desc' } }),
  ]);

  let context = "아래는 사용자의 지식 베이스 및 포트폴리오 내용입니다:\n\n";
  
  context += "--- 학습 및 기술 노트 ---\n";
  notes.forEach(n => context += `제목: ${n.title}\n내용: ${n.content.substring(0, 300)}\n\n`);
  
  context += "--- 포트폴리오 및 프로젝트 ---\n";
  portfolios.forEach(p => context += `프로젝트명: ${p.title}\n설명: ${p.description}\n기술스택: ${p.techStack}\n\n`);

  context += "--- 블로그 포스트 ---\n";
  posts.forEach(p => context += `제목: ${p.title}\n요약: ${p.excerpt}\n\n`);

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
    당신은 '김한수'의 개인 비서이자 지식 에이전트입니다. 
    제공된 [지식 베이스]의 내용을 바탕으로 사용자의 질문에 친절하고 전문적으로 대답하세요.
    제공되지 않은 정보에 대해서는 아는 척하지 말고, 사용자님의 기록을 더 찾아보겠다고 답변하세요.
    
    [지식 베이스]
    ${knowledgeContext}
    
    질문: ${userMessage}
  `;

  return callGemini(systemPrompt, apiKey);
}

// 기존 processWithAI 보강
export async function processWithAI(prompt: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) {
    return callGemini(prompt, apiKey);
  }
  throw new Error("No Gemini API configuration found");
}
