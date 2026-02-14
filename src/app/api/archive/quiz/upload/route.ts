import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { parseQuizCsv } from "@/lib/csv-parser";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const formData = await request.formData();
  const file = formData.get("file") as File | null;
  const title = formData.get("title") as string;

  if (!file || !title) {
    return NextResponse.json({ error: "File and title are required" }, { status: 400 });
  }

  try {
    const csvContent = await file.text();
    const { questions } = parseQuizCsv(csvContent);

    if (questions.length === 0) {
      return NextResponse.json({ error: "No valid questions found in CSV" }, { status: 400 });
    }

    const quizSet = await prisma.quizSet.create({
      data: {
        title,
        authorId: session.user.id,
        questions: {
          create: questions.map((q, i) => ({
            question: q.question,
            answer: q.answer,
            hint: q.hint || null,
            order: i + 1,
          })),
        },
      },
      include: { questions: true },
    });

    return NextResponse.json(quizSet, { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to parse CSV";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
