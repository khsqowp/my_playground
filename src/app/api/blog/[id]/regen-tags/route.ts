import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { callAI } from "@/lib/ai";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;

  const post = await prisma.post.findUnique({
    where: { id },
    select: { id: true, title: true, content: true, authorId: true },
  });
  if (!post) return NextResponse.json({ error: "Post not found" }, { status: 404 });

  const userRole = (session.user as any).role;
  if (post.authorId !== session.user.id && userRole !== "OWNER") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  try {
    const prompt = `다음 블로그 글의 핵심 IT 기술 태그 5~8개를 콤마로 구분해서 써줘. 마크다운이나 설명 없이 태그만 출력해.

글 제목: ${post.title}
글 내용: ${post.content.substring(0, 2000)}`;

    const aiResponse = await callAI(prompt);
    const tagNames = aiResponse
      .split(",")
      .map((t: string) => t.trim().replace(/^#/, ""))
      .filter((t: string) => t.length > 0 && t.length <= 50)
      .slice(0, 10);

    if (tagNames.length === 0) {
      return NextResponse.json({ error: "AI가 태그를 생성하지 못했습니다." }, { status: 500 });
    }

    const tagIds = await Promise.all(
      tagNames.map(async (name: string) => {
        const tag = await prisma.tag.upsert({
          where: { name },
          update: {},
          create: { name },
        });
        return tag.id;
      })
    );

    // 기존 태그 삭제 후 새 태그 생성
    await prisma.post.update({
      where: { id },
      data: {
        tags: {
          deleteMany: {},
          create: tagIds.map((tagId) => ({ tag: { connect: { id: tagId } } })),
        },
      },
    });

    return NextResponse.json({ tags: tagNames });
  } catch (e: any) {
    console.error("[REGEN-TAGS] Error:", e.message);
    return NextResponse.json({ error: e.message || "태그 생성 실패" }, { status: 500 });
  }
}
