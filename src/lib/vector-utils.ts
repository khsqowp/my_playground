import fs from "fs";
import path from "path";
import { createRequire } from "module";
import { GoogleGenerativeAI } from "@google/generative-ai";

// PDF-parse environment polyfill
if (typeof global.DOMMatrix === "undefined") {
  (global as any).DOMMatrix = class DOMMatrix {};
}

const require = createRequire(import.meta.url);
const pdf = require("pdf-parse");

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
 * Gemini를 사용한 텍스트 임베딩 생성 (768차원)
 */
export async function generateEmbedding(text: string): Promise<number[]> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY가 설정되지 않았습니다.");

  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({ model: "text-embedding-004" });
  
  const result = await model.embedContent(text);
  return result.embedding.values;
}
