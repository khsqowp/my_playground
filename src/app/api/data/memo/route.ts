import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = request.nextUrl;
  const search = searchParams.get("search") || "";
  const pinned = searchParams.get("pinned");
  const page = parseInt(searchParams.get("page") || "1");
  const limit = parseInt(searchParams.get("limit") || "20");

  const where: Record<string, unknown> = { authorId: session.user.id };
  if (search) where.content = { contains: search };
  if (pinned === "true") where.pinned = true;

  const [memos, total] = await Promise.all([
    prisma.memo.findMany({
      where,
      orderBy: [{ pinned: "desc" }, { createdAt: "desc" }],
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.memo.count({ where }),
  ]);

  return NextResponse.json({ memos, total, page, totalPages: Math.ceil(total / limit) });
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  const memo = await prisma.memo.create({
    data: {
      content: body.content,
      categoryTag: body.categoryTag || null,
      pinned: body.pinned || false,
      authorId: session.user.id,
    },
  });

  return NextResponse.json(memo, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  const { id, content, categoryTag, pinned } = body;

  if (!id) return NextResponse.json({ error: "ID required" }, { status: 400 });

  const memo = await prisma.memo.update({
    where: { id, authorId: session.user.id },
    data: {
      ...(content !== undefined && { content }),
      ...(categoryTag !== undefined && { categoryTag }),
      ...(pinned !== undefined && { pinned }),
    },
  });

  return NextResponse.json(memo);
}

export async function DELETE(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  await prisma.memo.delete({ where: { id: body.id, authorId: session.user.id } });
  return NextResponse.json({ success: true });
}
