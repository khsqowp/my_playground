import prisma from "@/lib/prisma";
import { GoogleGenerativeAI } from "@google/generative-ai";

/**
 * Gemini AI 호출 (최신 2.0 Flash 모델 사용으로 속도와 지능 최적화)
 */
export async function callGemini(
  prompt: string,
  apiKey: string,
  modelName = "gemini-2.0-flash-001"
): Promise<string> {
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ 
      model: modelName,
      generationConfig: {
        temperature: 0.3, // 일관성 있는 전문적 답변을 위해 온도 낮춤
        topP: 0.8,
        maxOutputTokens: 4096,
      }
    });
    const result = await model.generateContent(prompt);
    return result.response.text();
  } catch (error: any) {
    console.error("[GEMINI_API_ERROR]", error.message);
    if (error.message?.includes("429") || error.message?.includes("quota") || error.message?.includes("503")) {
      throw new Error("RATE_LIMIT");
    }
    // 하위 호환성 및 안정성을 위한 fallback
    return callGemini(prompt, apiKey, "gemini-1.5-flash");
  }
}

/**
 * Groq AI 호출 (Llama 3.3 70B - 고성능 보조 지능)
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
      temperature: 0.3,
      max_tokens: 4096,
    }),
  });

  if (!res.ok) {
    if (res.status === 429) throw new Error("RATE_LIMIT");
    throw new Error(`Groq 오류: ${res.status}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content ?? "";
}

let rrIndex = 0;

/**
 * 통합 AI 호출 — 다중 키 라운드로빈 및 폴백
 */
export async function callAI(prompt: string): Promise<string> {
  const keys = [
    { name: "Gemini 2.0", key: process.env.GEMINI_API_KEY },
    { name: "Groq Llama 3.3", key: process.env.GROQ_API_KEY },
    { name: "Gemini Alt 1", key: process.env.GEMINI_API_KEY2 },
    { name: "Gemini Alt 2", key: process.env.GEMINI_API_KEY3 },
    { name: "Gemini Alt 3", key: process.env.GEMINI_API_KEY4 },
    { name: "Gemini Alt 4", key: process.env.GEMINI_API_KEY5 },
    { name: "Gemini Alt 5", key: process.env.GEMINI_API_KEY6 },
    { name: "Gemini Alt 6", key: process.env.GEMINI_API_KEY7 },
    { name: "Gemini Alt 7", key: process.env.GEMINI_API_KEY8 },
    { name: "Gemini Alt 8", key: process.env.GEMINI_API_KEY9 },
  ].filter(k => k.key);

  if (keys.length === 0) throw new Error("AI API 키가 설정되지 않았습니다.");

  const startIdx = rrIndex % keys.length;

  for (let i = 0; i < keys.length; i++) {
    const idx = (startIdx + i) % keys.length;
    const provider = keys[idx];
    try {
      const result = provider.name.includes("Groq") 
        ? await callGroq(prompt, provider.key!) 
        : await callGemini(prompt, provider.key!);
      
      rrIndex = (idx + 1) % keys.length;
      return result;
    } catch (e: any) {
      if (e.message === "RATE_LIMIT") continue;
      throw e;
    }
  }
  throw new Error("모든 AI 제공자의 쿼터가 초과되었습니다.");
}

/**
 * RAG 지식 베이스 컨텍스트 생성 (데이터 일관성 및 최신성 보장)
 */
async function getKnowledgeContext() {
  const [notes, portfolios, posts, projectLogs] = await Promise.all([
    prisma.note.findMany({ take: 10, orderBy: { updatedAt: "desc" } }),
    prisma.portfolio.findMany({ take: 5, orderBy: { createdAt: "desc" } }),
    prisma.post.findMany({ where: { published: true }, take: 10, orderBy: { createdAt: "desc" } }),
    prisma.projectActivityLog.findMany({ take: 50, orderBy: { eventTime: "desc" } }),
  ]);

  let context = "### [프라이빗 지식 베이스]\n\n";
  context += "#### 1. 활동 로그 (최근 50건 - 최신성 우선)\n";
  projectLogs.forEach((l) => (context += `- [${l.eventTime.toLocaleString('ko-KR')}] [${l.platform}] ${l.content}\n`));
  
  context += "\n#### 2. 주요 기술 노트\n";
  notes.forEach((n) => (context += `- ${n.title}\n`));
  
  context += "\n#### 3. 최근 블로그 포스트\n";
  posts.forEach((p) => (context += `- ${p.title} (URL: /p/blog/${p.slug})\n`));

  return context;
}

/**
 * 벡터 DB에서 관련 컨텍스트 검색 (RAG)
 */
async function getVectorContext(query: string, limit = 5) {
  try {
    const { generateEmbedding } = await import("./vector-utils");
    const embedding = await generateEmbedding(query);
    const vectorStr = `[${embedding.join(",")}]`;

    // pgvector 코사인 유사도 검색 (<=> 연산자 사용)
    const results: any[] = await prisma.$queryRawUnsafe(`
      SELECT 
        c.content, 
        f."fileName", 
        f.folder,
        (c.embedding <=> $1::vector) as distance
      FROM "FileChunk" c
      JOIN "ArchiveFile" f ON c."fileId" = f.id
      ORDER BY distance ASC
      LIMIT $2
    `, vectorStr, limit);

    if (!results || results.length === 0) return "";

    let context = "\n### [아카이브 파일 검색 결과 (참조 데이터)]\n";
    results.forEach((r, i) => {
      context += `\n[참조 ${i + 1}: ${r.folder}/${r.fileName}]\n${r.content}\n`;
    });
    
    return context;
  } catch (err) {
    console.error("[VECTOR_SEARCH_ERROR]", err);
    return "";
  }
}

/**
 * 페르소나 채팅 - 적응형 지능 및 전문 정책 적용
 */
export async function chatWithPersona(userMessage: string): Promise<string> {
  const [knowledgeContext, vectorContext] = await Promise.all([
    getKnowledgeContext(),
    getVectorContext(userMessage)
  ]);

  const systemPrompt = `당신은 '김한수'의 디지털 자아이자, 개인 학습 보조 및 기술 아카이브 관리 비서입니다.

[역할 정의]
- 본인의 기술 기록(활동 로그, 노트, 블로그) 및 **[아카이브 파일 검색 결과]**를 기반으로 답변하는 데이터 기반 AI입니다.
- 추측이나 일반론보다 제공된 "기록 근거 기반 분석"을 우선합니다.
- 정확성을 최우선으로 하며, 불확실한 정보는 명확히 한계를 밝힙니다.
- 공격 기법 설명은 허용하되, 반드시 방어 전략을 병행합니다.

[지식 우선순위]
1. 내부 지식 베이스 및 아카이브 파일 검색 결과
2. 내부 기록의 최신성 필터링 (과거 방식이 최신 보안 표준과 충돌 시 명시)
3. 일반 Best Practice (내부 데이터에 없는 경우에만 제한적으로 사용)

[행동 원칙]
- 데이터에 없는 내용은: "내 기록 기준으로 확인되지 않습니다."라고 명시
- 추론이 필요한 경우: "추론입니다."라고 명확히 구분
- 기술 제언은 반드시 근거를 명시
- 질문 난이도에 따라 깊이 조절 (초급/중급/심화 자동 판단)

[보안 관련 답변 규칙]
- 공격 기법 설명 가능
- 반드시 방어 전략, 완화 방법, 운영 관점 대응 포함
- 위험도 수준 명시 (Low / Medium / High)

[출력 구조 - 반드시 유지]
다음 형식을 준수하십시오:

[요약]
핵심 결론 3~5줄

[기록 기반 근거]
내부 데이터 및 아카이브 파일 참조 요약

[기술 분석]
원리, 구조, 동작 방식

[리스크]
보안/운영 관점 영향

[권장 대응]
구체적 개선안 또는 학습 방향

모든 답변은 한국어로 작성하십시오.

[지식 베이스 데이터]
${knowledgeContext}
${vectorContext}

사용자 질문: ${userMessage}
AI 에이전트 답변:`;

  return callAI(systemPrompt);
}

export async function processWithAI(prompt: string): Promise<string> {
  return callAI(prompt);
}
