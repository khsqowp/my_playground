import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET() {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const configs = await prisma.aiConfig.findMany({
    orderBy: { createdAt: "desc" },
  });

  // Mask API keys
  const masked = configs.map((c) => ({
    ...c,
    apiKey: c.apiKey.slice(0, 8) + "..." + c.apiKey.slice(-4),
  }));

  return NextResponse.json(masked);
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user || session.user.role !== "OWNER") {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();

  // If setting as default, unset others
  if (body.isDefault) {
    await prisma.aiConfig.updateMany({ data: { isDefault: false } });
  }

  const config = body.id
    ? await prisma.aiConfig.update({
      where: { id: body.id },
      data: {
        provider: body.provider,
        apiKey: body.apiKey,
        model: body.model,
        isDefault: body.isDefault ?? false,
      },
    })
    : await prisma.aiConfig.create({
      data: {
        provider: body.provider,
        apiKey: body.apiKey,
        model: body.model,
        isDefault: body.isDefault ?? false,
        user: { connect: { id: session.user.id } },
      },
    });

  return NextResponse.json({
    ...config,
    apiKey: config.apiKey.slice(0, 8) + "..." + config.apiKey.slice(-4),
  });
}

export async function DELETE(request: NextRequest) {
  const session = await auth();
  if (!session?.user || session.user.role !== "OWNER") {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  await prisma.aiConfig.delete({ where: { id: body.id } });
  return NextResponse.json({ success: true });
}
