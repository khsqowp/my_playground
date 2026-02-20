import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { isServiceRequest } from "@/lib/service-auth";
import { callAI } from "@/lib/ai";

const BATCH_SIZE = 5; // 한 번에 처리할 최대 글 수

export async function POST(request: NextRequest) {
  // 서비스 키 또는 인증된 세션 허용
  const isService = isServiceRequest(request);
  if (!isService) {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
  }

  // 태그가 없는 게시글 조회 (최신순)
  const posts = await prisma.post.findMany({
    where: { tags: { none: {} } },
    select: { id: true, title: true, content: true },
    orderBy: { createdAt: "desc" },
    take: BATCH_SIZE,
  });

  if (posts.length === 0) {
    return NextResponse.json({ tagged: 0, message: "태그 없는 글이 없습니다." });
  }

  let tagged = 0;
  for (const post of posts) {
    try {
      const prompt = `다음 블로그 글의 핵심 IT 기술 태그 5~8개를 콤마로 구분해서 써줘. 마크다운이나 설명 없이 태그만 출력해.

글 제목: ${post.title}
글 내용: ${post.content.substring(0, 1500)}`;

      const aiResponse = await callAI(prompt);
      const tagNames = aiResponse
        .split(",")
        .map((t: string) => t.trim().replace(/^#/, ""))
        .filter((t: string) => t.length > 0 && t.length <= 50)
        .slice(0, 10);

      if (tagNames.length === 0) continue;

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

      await prisma.tagOnPost.createMany({
        data: tagIds.map((tagId) => ({ postId: post.id, tagId })),
        skipDuplicates: true,
      });

      tagged++;
      console.log(`[BLOG-TAGS] Tagged: "${post.title}"`);
      // AI rate limit 방지
      await new Promise((r) => setTimeout(r, 3000));
    } catch (e: any) {
      console.error(`[BLOG-TAGS] Failed for id=${post.id}:`, e.message);
    }
  }

  return NextResponse.json({
    tagged,
    total: posts.length,
    message: `${tagged}개 글에 태그를 생성했습니다.`,
  });
}
