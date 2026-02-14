import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const search = searchParams.get("search") || "";

  const where: Record<string, unknown> = {};
  if (search) {
    where.OR = [
      { title: { contains: search } },
      { description: { contains: search } },
    ];
  }

  const quizSets = await prisma.quizSet.findMany({
    where,
    include: {
      author: { select: { name: true } },
      _count: { select: { questions: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json(quizSets);
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  const { title, description, visibility, questions } = body;

  const quizSet = await prisma.quizSet.create({
    data: {
      title,
      description,
      visibility: visibility || "PRIVATE",
      authorId: session.user.id,
      questions: {
        create: questions.map((q: { question: string; answer: string; hint?: string }, i: number) => ({
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
}
