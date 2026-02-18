import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { callGemini } from "@/lib/ai";
import { isServiceRequest, getServiceAuthorId } from "@/lib/service-auth";

export async function POST(request: NextRequest) {
  // Service-key auth (Discord bot) or session auth
  let authorId: string;

  if (isServiceRequest(request)) {
    const serviceAuthorId = await getServiceAuthorId();
    if (!serviceAuthorId) {
      return NextResponse.json({ error: "No owner user found" }, { status: 500 });
    }
    authorId = serviceAuthorId;
  } else {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    authorId = session.user.id;
  }

  const body = await request.json();
  const { topic, content, count = 5, sourceNoteId } = body;

  if (!topic) {
    return NextResponse.json({ error: "topic is required" }, { status: 400 });
  }

  const safeCount = Math.min(Math.max(Number(count) || 5, 1), 20);

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return NextResponse.json({ error: "GEMINI_API_KEY not configured" }, { status: 500 });
  }

  const truncatedContent = content ? content.substring(0, 3000) : "";
  const contentSection = truncatedContent
    ? `\n\n참고 내용:\n${truncatedContent}`
    : "";

  const prompt = `다음 주제로 퀴즈 문제 ${safeCount}개를 만들어줘.${contentSection}

주제: ${topic}

반드시 아래 JSON 배열 형식으로만 응답해줘 (마크다운 코드블록 없이 순수 JSON):
[
  {"question": "질문", "answer": "정답", "hint": "힌트(선택)"},
  ...
]`;

  try {
    const raw = await callGemini(prompt, apiKey);
    const cleaned = raw.replace(/```json\n?|\n?```/g, "").trim();
    let questions: Array<{ question: string; answer: string; hint?: string }>;

    try {
      questions = JSON.parse(cleaned);
    } catch {
      // fallback: extract JSON array with regex
      const match = cleaned.match(/\[[\s\S]*\]/);
      if (!match) throw new Error("AI 응답을 파싱할 수 없습니다.");
      questions = JSON.parse(match[0]);
    }

    if (!Array.isArray(questions) || questions.length === 0) {
      throw new Error("AI가 퀴즈를 생성하지 못했습니다.");
    }

    const quizSet = await prisma.quizSet.create({
      data: {
        title: `[AI] ${topic}`,
        description: sourceNoteId ? `노트 기반 자동 생성` : `주제: ${topic}`,
        visibility: "PRIVATE",
        authorId,
        questions: {
          create: questions.map((q, i) => ({
            question: q.question,
            answer: q.answer,
            hint: q.hint || null,
            order: i + 1,
          })),
        },
      },
      include: {
        questions: true,
        author: { select: { name: true } },
        _count: { select: { questions: true } },
      },
    });

    return NextResponse.json(quizSet, { status: 201 });
  } catch (error: any) {
    console.error("[QUIZ_GENERATE_ERROR]", error);
    return NextResponse.json(
      { error: error.message || "퀴즈 생성 중 오류가 발생했습니다." },
      { status: 500 }
    );
  }
}
