import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET() {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const prompts = await prisma.aiPrompt.findMany({
        where: { userId: session.user.id },
        orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(prompts);
}

export async function POST(request: NextRequest) {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = await request.json();
    const { title, content, tags } = body;

    if (!title || !content) {
        return NextResponse.json({ error: "Title and content required" }, { status: 400 });
    }

    const prompt = await prisma.aiPrompt.create({
        data: {
            title,
            content,
            tags,
            userId: session.user.id,
        },
    });

    return NextResponse.json(prompt, { status: 201 });
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
