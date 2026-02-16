import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

// GET: 멤버 목록 조회
export async function GET() {
  try {
    const session = await auth();
    if (!session || session.user.role !== "OWNER") {
      return new NextResponse("Forbidden", { status: 403 });
    }

    const members = await prisma.user.findMany({
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        status: true,
        role: true,
        createdAt: true,
      }
    });

    return NextResponse.json(members);
  } catch (error) {
    return new NextResponse("Internal Server Error", { status: 500 });
  }
}

// PATCH: 승인/거절 처리
export async function PATCH(req: Request) {
  try {
    const session = await auth();
    if (!session || session.user.role !== "OWNER") {
      return new NextResponse("Forbidden", { status: 403 });
    }

    const { id, status, role } = await req.json();

    const updatedUser = await prisma.user.update({
      where: { id },
      data: { status, role },
    });

    return NextResponse.json(updatedUser);
  } catch (error) {
    return new NextResponse("Internal Server Error", { status: 500 });
  }
}

// DELETE: 멤버 추방
export async function DELETE(req: Request) {
  try {
    const session = await auth();
    if (!session || session.user.role !== "OWNER") {
      return new NextResponse("Forbidden", { status: 403 });
    }

    const { searchParams } = new URL(req.url);
    const id = searchParams.get("id");

    if (!id) return new NextResponse("ID required", { status: 400 });

    await prisma.user.delete({
      where: { id },
    });

    return new NextResponse("Deleted", { status: 200 });
  } catch (error) {
    return new NextResponse("Internal Server Error", { status: 500 });
  }
}
