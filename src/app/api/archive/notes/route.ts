import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { isServiceRequest, getServiceAuthorId } from "@/lib/service-auth";

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const page = parseInt(searchParams.get("page") || "1");
  const limit = parseInt(searchParams.get("limit") || "20");
  const search = searchParams.get("search") || "";
  const category = searchParams.get("category") || "";

  const where: Record<string, unknown> = {};
  if (search) {
    where.OR = [
      { title: { contains: search } },
      { content: { contains: search } },
    ];
  }
  if (category) {
    where.category = { slug: category };
  }

  const [notes, total] = await Promise.all([
    prisma.note.findMany({
      where,
      include: {
        author: { select: { name: true } },
        category: { select: { id: true, name: true, slug: true, color: true } },
        tags: { include: { tag: { select: { id: true, name: true } } } },
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.note.count({ where }),
  ]);

  return NextResponse.json({ notes, total, page, totalPages: Math.ceil(total / limit) });
}

export async function POST(request: NextRequest) {
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
  const { title, content, visibility, categoryId, tags } = body;

  const tagConnections = tags?.length
    ? await Promise.all(
        tags.map(async (name: string) => {
          const tag = await prisma.tag.upsert({
            where: { name },
            update: {},
            create: { name },
          });
          return { tagId: tag.id };
        })
      )
    : [];

  const note = await prisma.note.create({
    data: {
      title,
      content,
      visibility: visibility || "PRIVATE",
      categoryId: categoryId || null,
      authorId,
      tags: { create: tagConnections.map((t) => ({ tagId: t.tagId })) },
    },
    include: {
      category: true,
      tags: { include: { tag: true } },
    },
  });

  return NextResponse.json(note, { status: 201 });
}
