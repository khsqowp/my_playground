import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const quizSet = await prisma.quizSet.findUnique({
    where: { id },
    include: {
      author: { select: { id: true, name: true } },
      questions: { orderBy: { order: "asc" } },
    },
  });

  if (!quizSet) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json(quizSet);
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  const body = await request.json();
  const { title, description, visibility, questions } = body;

  // Delete old questions and recreate
  await prisma.quizQuestion.deleteMany({ where: { quizSetId: id } });

  const quizSet = await prisma.quizSet.update({
    where: { id },
    data: {
      title,
      description,
      visibility,
      questions: {
        create: questions?.map((q: { question: string; answer: string; hint?: string }, i: number) => ({
          question: q.question,
          answer: q.answer,
          hint: q.hint || null,
          order: i + 1,
        })),
      },
    },
    include: { questions: { orderBy: { order: "asc" } } },
  });

  return NextResponse.json(quizSet);
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  await prisma.quizSet.delete({ where: { id } });
  return NextResponse.json({ success: true });
}
