import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

// 관리자 권한 확인 미들웨어 함수 대용
async function isAdmin() {
  const session = await auth();
  return session?.user?.role === "OWNER" || session?.user?.role === "ADMIN";
}

export async function GET() {
  if (!await isAdmin()) return new NextResponse("Unauthorized", { status: 401 });

  const users = await prisma.user.findMany({
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      name: true,
      email: true,
      phone: true,
      birthDate: true,
      role: true,
      status: true,
      permissions: true,
      createdAt: true,
    }
  });

  return NextResponse.json(users);
}

export async function PATCH(request: NextRequest) {
  if (!await isAdmin()) return new NextResponse("Unauthorized", { status: 401 });

  const body = await request.json();
  const { userId, status, role, permissions } = body;

  const user = await prisma.user.update({
    where: { id: userId },
    data: {
      ...(status && { status }),
      ...(role && { role }),
      ...(permissions && { permissions }),
    }
  });

  return NextResponse.json(user);
}

export async function DELETE(request: NextRequest) {
  if (!await isAdmin()) return new NextResponse("Unauthorized", { status: 401 });

  const { searchParams } = new URL(request.url);
  const userId = searchParams.get("userId");

  if (!userId) return new NextResponse("User ID required", { status: 400 });

  await prisma.user.delete({
    where: { id: userId }
  });

  return NextResponse.json({ success: true });
}
