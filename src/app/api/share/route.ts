import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { generateShareToken } from "@/lib/share";
import bcrypt from "bcryptjs";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  const { targetType, targetId, expiresAt, maxAccess, password } = body;

  const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

  const link = await prisma.shareLink.create({
    data: {
      token: generateShareToken(),
      targetType,
      targetId,
      expiresAt: expiresAt ? new Date(expiresAt) : null,
      maxAccess: maxAccess || null,
      password: hashedPassword,
      createdBy: session.user.id,
    },
  });

  return NextResponse.json(link, { status: 201 });
}
