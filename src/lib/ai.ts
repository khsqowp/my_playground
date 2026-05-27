import { GoogleGenAI } from "@google/genai";

/**
 * Gemini AI 호출 (최신 2.0 Flash 모델 사용으로 속도와 지능 최적화)
 */
export async function callGemini(
  prompt: string,
  apiKey: string,
  modelName = "gemini-2.0-flash"
): Promise<string> {
  try {
    // 임베딩 모델과의 일관성을 위해 v1beta 명시
    const ai = new GoogleGenAI({ apiKey, apiVersion: "v1beta" });
    const response = await ai.models.generateContent({
      model: modelName,
      contents: prompt,
      config: {
        temperature: 0.3,
        maxOutputTokens: 4096,
      }
    });
    
    return response.text || "";
  } catch (error: any) {
    console.error("[GEMINI_API_ERROR]", error.message);
    if (error.message?.includes("429") || error.message?.includes("quota") || error.message?.includes("503")) {
      throw new Error("RATE_LIMIT");
    }
    // 하위 호환성 및 안정성을 위한 fallback (최신 SDK 형식 유지)
    const aiFallback = new GoogleGenAI({ apiKey });
    const fallbackResponse = await aiFallback.models.generateContent({
      model: "gemini-2.0-flash-lite", // 최신 모델 권장 사항 반영
      contents: prompt
    });
    return fallbackResponse.text || "";
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

export async function processWithAI(prompt: string): Promise<string> {
  return callAI(prompt);
}
