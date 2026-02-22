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

/**
 * Gemini를 사용한 텍스트 임베딩 생성 (3072차원)
 * API 할당량 초과(429) 시 재시도 로직 포함
 */
export async function generateEmbedding(text: string, retryCount = 0): Promise<number[]> {
  const MAX_RETRIES = 5;
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY가 설정되지 않았습니다.");

  try {
    // 요청 간 최소 지연 시간 (API 숨 돌리기)
    await new Promise(resolve => setTimeout(resolve, 800));

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
      const waitTime = Math.pow(2, retryCount) * 2000; // 2s, 4s, 8s, 16s...
      console.warn(`[GEMINI_QUOTA] 할당량 초과. ${waitTime/1000}초 후 재시도 (${retryCount + 1}/${MAX_RETRIES})`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      return generateEmbedding(text, retryCount + 1);
    }
    
    throw err;
  }
}
