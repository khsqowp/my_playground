import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const note = await prisma.note.findUnique({
    where: { id },
    include: {
      author: { select: { id: true, name: true } },
      category: true,
      tags: { include: { tag: true } },
    },
  });

  if (!note) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json(note);
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  const body = await request.json();
  const { title, content, visibility, categoryId, tags } = body;

  // Remove old tags and add new
  await prisma.tagOnNote.deleteMany({ where: { noteId: id } });

  const tagConnections = tags?.length
    ? await Promise.all(
        tags.map(async (name: string) => {
          const tag = await prisma.tag.upsert({ where: { name }, update: {}, create: { name } });
          return { tagId: tag.id };
        })
      )
    : [];

  const note = await prisma.note.update({
    where: { id },
    data: {
      title,
      content,
      visibility,
      categoryId: categoryId || null,
      tags: { create: tagConnections.map((t) => ({ tagId: t.tagId })) },
    },
    include: { category: true, tags: { include: { tag: true } } },
  });

  return NextResponse.json(note);
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  await prisma.note.delete({ where: { id } });
  return NextResponse.json({ success: true });
}
