import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { callAI, chatWithPersona } from "@/lib/ai";
import { isServiceRequest } from "@/lib/service-auth";

interface HistoryMessage {
  role: "user" | "assistant";
  content: string;
}

function ragServiceUrl() {
  return (process.env.RAG_SERVICE_URL || "").replace(/\/$/, "");
}

async function askProjectRag(message: string, project: string, history?: HistoryMessage[]) {
  const baseUrl = ragServiceUrl();
  if (!baseUrl) {
    return chatWithPersona(message);
  }

  const recentHistory = (history ?? [])
    .slice(-6)
    .map((m) => `${m.role === "user" ? "사용자" : "AI"}: ${m.content}`)
    .join("\n");

  const query = recentHistory
    ? `[이전 대화]\n${recentHistory}\n\n[현재 질문]\n${message}`
    : message;

  const res = await fetch(`${baseUrl}/api/ask`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      project,
      query,
      limit: 8,
      show_context: false,
      web_search: false,
    }),
  });

  const data = await res.json().catch(() => ({}));

  if (res.status === 404) {
    return `"${project}" 프로젝트에서 질문과 관련된 색인 문서를 찾지 못했습니다. 파일을 업로드했거나 블로그/포트폴리오를 저장했다면 RAG 재색인을 먼저 실행해 주세요.`;
  }

  if (!res.ok) {
    throw new Error(data.detail || data.error || "RAG 서비스 응답 오류");
  }

  return data.answer || "답변을 생성하지 못했습니다.";
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

    const { message, project, pageContext, pagePath, history } = await req.json();
    if (!message) {
      return new NextResponse("Message is required", { status: 400 });
    }

    let response: string;

    // 페이지 컨텍스트가 있으면 페이지 내용 기반 대화
    if (pageContext && pageContext.trim().length > 50) {
      const historyText = (history as HistoryMessage[] ?? [])
        .map((m) => `${m.role === "user" ? "User" : "AI"}: ${m.content}`)
        .join("\n");

      const prompt = `당신은 '88Motorcycle' 플랫폼의 기술 분석 어시스턴트입니다.

현재 사용자가 보고 있는 페이지의 정보만을 기반으로,
보안 및 성능 관점에서 분석을 수행합니다.

[컨텍스트]
- 현재 경로: ${pagePath ?? "루트 디렉토리"}
- 페이지 내용: ${pageContext.substring(0, 3000)}

[이전 대화 내역]
${historyText || "대화 기록 없음"}

[행동 원칙]
- 반드시 제공된 페이지 데이터만 사용
- 없는 정보는 추측하지 말 것
- 단순 요약이 아닌 기술적 분석 수행
- 감정적 표현 없이 문제를 냉정하게 지적

[분석 범위]
1. 보안 취약 가능성
   - 인증/인가
   - 입력 검증
   - XSS/SQLi 가능성
   - 정보 노출
2. 성능 관점
   - 렌더링 병목 가능성
   - 불필요한 리소스 로딩
   - API 호출 구조 문제
3. 구조적 개선점

[출력 구조 - 반드시 유지]

[페이지 기능 요약]
기술적 관점에서 간략 요약

[보안 분석]
취약 가능성 + 근거
위험도: Low / Medium / High

[성능 분석]
문제 지점 + 영향

[개선 제안]
구체적 수정 방향

[한계]
현재 페이지 데이터로 확인 불가한 부분

모든 답변은 한국어로 작성하십시오.

사용자 질문: ${message}
전문가 답변:`;

      response = await callAI(prompt);
    } else {
      const selectedProject = String(project || process.env.RAG_DEFAULT_PROJECT || "inbox");
      response = await askProjectRag(message, selectedProject, history as HistoryMessage[] | undefined);
    }

    return NextResponse.json({ response });
  } catch (error: any) {
    console.error("[PERSONA_CHAT_ERROR]", error);
    return new NextResponse(error.message || "Internal Server Error", { status: 500 });
  }
}
