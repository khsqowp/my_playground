import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const q = request.nextUrl.searchParams.get("q") || "";
  if (!q) return NextResponse.json({ posts: [], notes: [], memos: [] });

  const [posts, notes, memos] = await Promise.all([
    prisma.post.findMany({
      where: { OR: [{ title: { contains: q } }, { content: { contains: q } }] },
      select: { id: true, title: true, slug: true, createdAt: true },
      take: 10,
    }),
    prisma.note.findMany({
      where: { OR: [{ title: { contains: q } }, { content: { contains: q } }] },
      select: { id: true, title: true, createdAt: true },
      take: 10,
    }),
    prisma.memo.findMany({
      where: { content: { contains: q }, authorId: session.user.id },
      select: { id: true, content: true, createdAt: true },
      take: 10,
    }),
  ]);

  return NextResponse.json({ posts, notes, memos });
}
