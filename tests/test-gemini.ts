import { GoogleGenerativeAI } from "@google/generative-ai";
import * as dotenv from "dotenv";
import path from "path";

dotenv.config({ path: path.resolve(process.cwd(), ".env") });

async function finalTest() {
  const apiKey = process.env.GEMINI_API_KEY;
  const modelName = "gemini-flash-latest"; // 우리가 찾아낸 모델명

  console.log(`=== [${modelName}] 최종 연결 테스트 ===`);

  if (!apiKey) {
    console.error("에러: GEMINI_API_KEY가 없습니다.");
    return;
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: modelName });

    console.log("메시지 전송 중...");
    const result = await model.generateContent("Hello! Reply with 'READY'");
    const text = result.response.text();

    console.log("---------------------------------");
    console.log("✅ 테스트 대성공!");
    console.log(`AI 응답: ${text}`);
    console.log("---------------------------------");
  } catch (error: any) {
    console.error("---------------------------------");
    console.error("❌ 테스트 실패");
    console.error(`메시지: ${error.message}`);
    console.log("---------------------------------");
  }
}

finalTest();
