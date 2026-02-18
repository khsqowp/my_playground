import { GoogleGenerativeAI } from "@google/generative-ai";
import * as dotenv from "dotenv";
import path from "path";

// .env 파일 로드
dotenv.config({ path: path.resolve(process.cwd(), ".env") });

async function testGemini() {
  const apiKey = process.env.GEMINI_API_KEY;
  const modelName = "gemini-1.5-flash";

  console.log("=== Gemini API 연결 테스트 ===");
  console.log(`사용 중인 모델: ${modelName}`);
  console.log(`API 키 존재 여부: ${apiKey ? "YES (확인됨)" : "NO (누락됨)"}`);

  if (!apiKey) {
    console.error("에러: .env 파일에 GEMINI_API_KEY가 설정되어 있지 않습니다.");
    return;
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: modelName });

    console.log("AI에게 메시지 전송 중...");
    const result = await model.generateContent("Hello, this is a connectivity test. Reply with 'OK' if you can hear me.");
    const response = await result.response;
    const text = response.text();

    console.log("---------------------------------");
    console.log("✅ 테스트 성공!");
    console.log(`AI 응답: ${text}`);
    console.log("---------------------------------");
  } catch (error: any) {
    console.error("---------------------------------");
    console.error("❌ 테스트 실패!");
    console.error(`상태 코드: ${error.status || "알 수 없음"}`);
    console.error(`에러 메시지: ${error.message}`);
    
    if (error.message.includes("429")) {
      console.error("원인: 할당량 초과 (Too Many Requests)");
    } else if (error.message.includes("404")) {
      console.error("원인: 모델을 찾을 수 없음 (모델명 혹은 리전 문제)");
    } else if (error.message.includes("API key not valid")) {
      console.error("원인: 유효하지 않은 API 키");
    }
    console.error("---------------------------------");
  }
}

testGemini();
