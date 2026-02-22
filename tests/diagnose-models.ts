import { GoogleGenAI } from "@google/genai";
import "dotenv/config";

async function diagnose() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.error("GEMINI_API_KEY가 설정되지 않았습니다.");
    return;
  }

  // apiVersion을 v1beta와 v1 모두 시도해봅니다.
  const versions = ["v1beta", "v1"];
  
  for (const v of versions) {
    console.log(`
--- API Version: ${v} 모델 목록 체크 ---`);
    try {
      const ai = new GoogleGenAI({ apiKey, apiVersion: v });
      const response = await ai.models.list();
      
      const models = (response as any).pageInternal || [];
      
      console.log(`총 ${models.length}개의 모델 정보 수신.`);
      const embeddingModels = models.filter((m: any) => 
        m.supportedActions?.includes("embedContent") || 
        m.supportedMethods?.includes("embedContent")
      );
      
      if (embeddingModels.length > 0) {
        console.log("임베딩 지원 모델 목록:");
        embeddingModels.forEach((m: any) => {
          console.log(`- Full Name: ${m.name}`);
          console.log(`  Supported Actions: ${JSON.stringify(m.supportedActions || m.supportedMethods)}`);
        });
      } else {
        console.log("이 버전의 API에서는 임베딩 모델을 찾을 수 없습니다.");
      }
    } catch (error: any) {
      console.error(`[${v}] 목록 조회 실패:`, error.message || error);
    }
  }
}

diagnose();
