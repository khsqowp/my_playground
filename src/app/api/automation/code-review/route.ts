import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET() {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const configs = await prisma.codeReviewConfig.findMany({
    where: { userId: session.user.id },
    include: {
      incomingWebhook: { select: { id: true, name: true, slug: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json(configs);
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  const { name, incomingWebhookId, discordWebhookUrl, enabled } = body;

  if (!name || !incomingWebhookId || !discordWebhookUrl) {
    return NextResponse.json(
      { error: "name, incomingWebhookId, discordWebhookUrl are required" },
      { status: 400 }
    );
  }

  // Verify the incoming webhook belongs to the user
  const webhook = await prisma.incomingWebhook.findFirst({
    where: { id: incomingWebhookId, userId: session.user.id },
  });
  if (!webhook) {
    return NextResponse.json({ error: "Incoming webhook not found" }, { status: 404 });
  }

  const config = await prisma.codeReviewConfig.create({
    data: {
      name,
      incomingWebhookId,
      discordWebhookUrl,
      enabled: enabled ?? true,
      userId: session.user.id,
    },
    include: {
      incomingWebhook: { select: { id: true, name: true, slug: true } },
    },
  });

  return NextResponse.json(config, { status: 201 });
}

export async function PUT(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  const { id, name, discordWebhookUrl, enabled } = body;
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });

  const config = await prisma.codeReviewConfig.update({
    where: { id, userId: session.user.id },
    data: {
      ...(name !== undefined && { name }),
      ...(discordWebhookUrl !== undefined && { discordWebhookUrl }),
      ...(enabled !== undefined && { enabled }),
    },
    include: {
      incomingWebhook: { select: { id: true, name: true, slug: true } },
    },
  });

  return NextResponse.json(config);
}

export async function DELETE(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  await prisma.codeReviewConfig.delete({
    where: { id: body.id, userId: session.user.id },
  });

  return NextResponse.json({ success: true });
}
