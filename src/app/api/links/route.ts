import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET() {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const links = await prisma.externalLink.findMany({
    where: { userId: session.user.id },
    orderBy: { order: "asc" },
  });

  return NextResponse.json(links);
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();
  const link = await prisma.externalLink.create({
    data: {
      title: body.title,
      url: body.url,
      icon: body.icon || null,
      order: body.order || 0,
      userId: session.user.id,
    },
  });

  return NextResponse.json(link, { status: 201 });
}
