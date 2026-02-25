import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { callAI } from "@/lib/ai";

function normalizeTags(raw?: string | null): string[] {
    if (!raw) return [];
    return Array.from(
        new Set(
            raw
                .split(/[,#\n]/g)
                .map((s) => s.trim())
                .filter(Boolean)
        )
    );
}

async function ensureFiveTags(title: string, content: string, rawTags?: string | null): Promise<string> {
    const current = normalizeTags(rawTags);
    if (current.length >= 5) return current.slice(0, 5).join(", ");

    try {
        const aiRaw = await callAI(
            `다음 프롬프트를 분석해서 태그를 정확히 5개 생성해줘.
제목: ${title}
내용: ${content}

출력 규칙:
- 태그만 콤마(,)로 구분해서 한 줄로 출력
- 설명, 번호, 따옴표, 마크다운 금지`
        );
        const aiTags = normalizeTags(aiRaw);
        for (const t of aiTags) {
            if (!current.includes(t)) current.push(t);
            if (current.length >= 5) break;
        }
    } catch (e) {
        console.error("[AI_PROMPT_TAGS_ERROR]", (e as any)?.message || e);
    }

    const fallback = ["AI", "프롬프트", "자동화", "업무", "템플릿"];
    for (const t of fallback) {
        if (!current.includes(t)) current.push(t);
        if (current.length >= 5) break;
    }

    return current.slice(0, 5).join(", ");
}

export async function GET(request: NextRequest) {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const q = request.nextUrl.searchParams.get("q")?.trim();

    const prompts = await prisma.aiPrompt.findMany({
        where: {
            userId: session.user.id,
            ...(q
                ? {
                    OR: [
                        { title: { contains: q, mode: "insensitive" } },
                        { content: { contains: q, mode: "insensitive" } },
                        { tags: { contains: q, mode: "insensitive" } },
                    ],
                }
                : {}),
        },
        orderBy: { createdAt: "desc" },
    });

    const repaired = await Promise.all(
        prompts.map(async (p) => {
            const count = normalizeTags(p.tags).length;
            if (count >= 5) return p;
            const tags = await ensureFiveTags(p.title, p.content, p.tags);
            return prisma.aiPrompt.update({
                where: { id: p.id, userId: session.user.id },
                data: { tags },
            });
        })
    );

    return NextResponse.json(repaired);
}

export async function POST(request: NextRequest) {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = await request.json();
    const { title, content, tags } = body;

    if (!title || !content) {
        return NextResponse.json({ error: "Title and content required" }, { status: 400 });
    }

    const ensuredTags = await ensureFiveTags(title, content, tags);

    const prompt = await prisma.aiPrompt.create({
        data: {
            title,
            content,
            tags: ensuredTags,
            userId: session.user.id,
        },
    });

    return NextResponse.json(prompt, { status: 201 });
}

export async function PUT(request: NextRequest) {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = await request.json();
    const { id, title, content, tags } = body;

    if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });
    if (!title || !content) {
        return NextResponse.json({ error: "Title and content required" }, { status: 400 });
    }

    const ensuredTags = await ensureFiveTags(title, content, tags);

    const prompt = await prisma.aiPrompt.update({
        where: { id, userId: session.user.id },
        data: {
            title,
            content,
            tags: ensuredTags,
        },
    });

    return NextResponse.json(prompt);
}

export async function DELETE(request: NextRequest) {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = await request.json();
    const { id } = body;

    await prisma.aiPrompt.delete({
        where: { id, userId: session.user.id },
    });

    return NextResponse.json({ success: true });
}
