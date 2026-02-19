import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { callAI, chatWithPersona } from "@/lib/ai";
import { isServiceRequest } from "@/lib/service-auth";

interface HistoryMessage {
  role: "user" | "assistant";
  content: string;
}

export async function POST(req: NextRequest) {
  try {
    // Service-key auth (Discord bot) bypasses session auth
    if (!isServiceRequest(req)) {
      const session = await auth();
      if (!session) {
        return new NextResponse("Unauthorized", { status: 401 });
      }
    }

    const { message, pageContext, pagePath, history } = await req.json();
    if (!message) {
      return new NextResponse("Message is required", { status: 400 });
    }

    let response: string;

    // 페이지 컨텍스트가 있으면 페이지 내용 기반 대화
    if (pageContext && pageContext.trim().length > 50) {
      const historyText = (history as HistoryMessage[] ?? [])
        .map((m) => `${m.role === "user" ? "사용자" : "AI"}: ${m.content}`)
        .join("\n");

      const prompt = `당신은 이 웹사이트의 AI 어시스턴트입니다.

[현재 페이지 경로]
${pagePath ?? "알 수 없음"}

[현재 페이지 내용]
${pageContext}

[답변 규칙]
- 사용자의 질문이 현재 페이지 내용과 관련 있다면, 반드시 위 페이지 내용을 근거로 정확하게 답변하세요.
- 페이지에 없는 내용을 추측하거나 지어내지 마세요. 모르면 솔직하게 말하세요.
- 현재 페이지·사이트와 무관한 일반적인 질문(여행, 음식, 날씨 등)은 일반 AI 어시스턴트로서 자연스럽게 답변하세요.
- 답변은 한국어로 작성하세요.
${historyText ? `\n[이전 대화]\n${historyText}\n` : ""}
사용자: ${message}
AI:`;

      response = await callAI(prompt);
    } else {
      // 페이지 컨텍스트가 없으면 Discord bot 등 외부 요청 — 페르소나 모드
      response = await chatWithPersona(message);
    }

    return NextResponse.json({ response });
  } catch (error: any) {
    console.error("[PERSONA_CHAT_ERROR]", error);
    return new NextResponse(error.message || "Internal Server Error", { status: 500 });
  }
}
