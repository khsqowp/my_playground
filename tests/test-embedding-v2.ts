import { GoogleGenAI } from "@google/genai";
import "dotenv/config";

async function testEmbeddingSuccess() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY가 없습니다.");

  console.log("=== [TDD] 임베딩 생성 기능 검증 테스트 시작 ===");
  
  // 우리가 진단으로 찾아낸 정확한 설정 적용
  const ai = new GoogleGenAI({ apiKey, apiVersion: "v1beta" });
  const modelName = "models/gemini-embedding-001";

  try {
    console.log(`테스트 모델: ${modelName}`);
    const response = await ai.models.embedContent({
      model: modelName,
      contents: [{ parts: [{ text: "TDD 테스트 문장입니다." }] }]
    });

    const values = response.embeddings?.[0]?.values;
    
    if (values && values.length > 0) {
      console.log(`✅ 성공: 임베딩 벡터 생성 완료 (차원: ${values.length})`);
      process.exit(0); // 테스트 통과
    } else {
      console.error("❌ 실패: 응답값이 비어있습니다.");
      process.exit(1);
    }
  } catch (error: any) {
    console.error("❌ 에러 발생:", error.message);
    process.exit(1);
  }
}

testEmbeddingSuccess();
