import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET() {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const webhooks = await prisma.webhookConfig.findMany({
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
  const webhook = await prisma.webhookConfig.create({
    data: {
      name: body.name,
      platform: body.platform,
      url: body.url,
      secret: body.secret || null,
      enabled: body.enabled ?? true,
      userId: session.user.id,
    },
  });

  return NextResponse.json(webhook, { status: 201 });
}

export async function PUT(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  const { id, name, platform, url, secret, enabled } = body;

  if (!id) return NextResponse.json({ error: "ID required" }, { status: 400 });

  const webhook = await prisma.webhookConfig.update({
    where: { id, userId: session.user.id },
    data: {
      ...(name !== undefined && { name }),
      ...(platform !== undefined && { platform }),
      ...(url !== undefined && { url }),
      ...(secret !== undefined && { secret }),
      ...(enabled !== undefined && { enabled }),
    },
  });

  return NextResponse.json(webhook);
}

export async function DELETE(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  await prisma.webhookConfig.delete({ where: { id: body.id, userId: session.user.id } });
  return NextResponse.json({ success: true });
}
