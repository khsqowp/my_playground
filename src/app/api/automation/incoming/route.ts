import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET() {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const webhooks = await prisma.incomingWebhook.findMany({
        where: { userId: session.user.id },
        include: { _count: { select: { logs: true } } },
        orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(webhooks);
}

export async function POST(request: NextRequest) {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = await request.json();
    const { name } = body;

    if (!name) return NextResponse.json({ error: "Name required" }, { status: 400 });

    // Generate a unique slug (UUID or CUID)
    // Simple random string for slug
    const slug = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

    const webhook = await prisma.incomingWebhook.create({
        data: {
            name,
            slug,
            userId: session.user.id,
        },
    });

    return NextResponse.json(webhook, { status: 201 });
}
