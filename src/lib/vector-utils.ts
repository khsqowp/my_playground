import fs from "fs";
import path from "path";
// @ts-ignore
import pdf from "pdf-parse-fork";
import { GoogleGenAI } from "@google/genai";

/**
 * 파일에서 텍스트 추출 (MD, TXT, PDF 대응)
 */
export async function extractTextFromFile(filePath: string): Promise<string> {
  const ext = path.extname(filePath).toLowerCase();
  
  if (ext === ".pdf") {
    const dataBuffer = fs.readFileSync(filePath);
    const data = await pdf(dataBuffer);
    return data.text;
  } else if (ext === ".md" || ext === ".txt") {
    return fs.readFileSync(filePath, "utf-8");
  }
  
  return "";
}

/**
 * 텍스트를 의미 있는 단위로 분할 (Chunking)
 */
export function chunkText(text: string, chunkSize = 1000, overlap = 200): string[] {
  const chunks: string[] = [];
  let start = 0;
  
  while (start < text.length) {
    const end = start + chunkSize;
    chunks.push(text.slice(start, end));
    start += (chunkSize - overlap);
  }
  
  return chunks;
}

let currentKeyIndex = 0;

/**
 * Gemini를 사용한 텍스트 임베딩 생성 (3072차원)
 * 다중 API 키 로테이션 및 재시도 로직 포함
 */
export async function generateEmbedding(text: string, retryCount = 0): Promise<number[]> {
  const keys = [
    process.env.GEMINI_API_KEY,
    process.env.GEMINI_API_KEY2,
    process.env.GEMINI_API_KEY3,
    process.env.GEMINI_API_KEY4,
    process.env.GEMINI_API_KEY5,
    process.env.GEMINI_API_KEY6,
    process.env.GEMINI_API_KEY7,
    process.env.GEMINI_API_KEY8,
    process.env.GEMINI_API_KEY9,
  ].filter(Boolean) as string[];

  if (keys.length === 0) throw new Error("GEMINI_API_KEY가 설정되지 않았습니다.");

  const MAX_RETRIES = keys.length * 2; // 모든 키를 최소 두 번씩은 시도
  const apiKey = keys[currentKeyIndex % keys.length];

  try {
    // 요청 간 최소 지연 시간
    await new Promise(resolve => setTimeout(resolve, 500));

    const ai = new GoogleGenAI({ apiKey, apiVersion: "v1beta" });
    const response = await ai.models.embedContent({
      model: "models/gemini-embedding-001",
      contents: [{ parts: [{ text }] }]
    });
    
    const values = response.embeddings?.[0]?.values;
    if (!values) throw new Error("임베딩 생성 실패: API 응답에 결과값이 없습니다.");
    
    return values;
  } catch (err: any) {
    const status = err.status || (err.message?.includes("429") ? 429 : 0);
    
    if (status === 429 && retryCount < MAX_RETRIES) {
      // 할당량 초과 시 다음 키로 교체
      currentKeyIndex = (currentKeyIndex + 1) % keys.length;
      const nextWaitTime = retryCount < keys.length ? 500 : 2000; // 키 교체 시에는 짧게 대기
      
      console.warn(`[GEMINI_ROTATION] 키 할당량 초과. 다음 키(${currentKeyIndex + 1})로 전환하여 재시도 (${retryCount + 1}/${MAX_RETRIES})`);
      
      await new Promise(resolve => setTimeout(resolve, nextWaitTime));
      return generateEmbedding(text, retryCount + 1);
    }
    
    throw err;
  }
}
