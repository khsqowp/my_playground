import { NextRequest, NextResponse } from "next/server";
import { validateShareLink } from "@/lib/share";
import prisma from "@/lib/prisma";
import bcrypt from "bcryptjs";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ token: string }> }
) {
  const { token } = await params;
  const password = request.nextUrl.searchParams.get("password");

  const link = await prisma.shareLink.findUnique({ where: { token } });
  if (!link || !link.active) {
    return NextResponse.json({ error: "Invalid or expired link" }, { status: 404 });
  }

  // Check password if set
  if (link.password) {
    if (!password) {
      return NextResponse.json({ error: "Password required", needsPassword: true }, { status: 403 });
    }
    const valid = await bcrypt.compare(password, link.password);
    if (!valid) {
      return NextResponse.json({ error: "Invalid password" }, { status: 403 });
    }
  }

  const result = await validateShareLink(token);
  if (!result) {
    return NextResponse.json({ error: "Link expired or access limit reached" }, { status: 410 });
  }

  // Fetch the actual content
  let content = null;
  switch (result.targetType) {
    case "POST":
      content = await prisma.post.findUnique({
        where: { id: result.targetId },
        include: { author: { select: { name: true } }, category: true },
      });
      break;
    case "NOTE":
      content = await prisma.note.findUnique({
        where: { id: result.targetId },
        include: { author: { select: { name: true } }, category: true },
      });
      break;
    case "QUIZSET":
      content = await prisma.quizSet.findUnique({
        where: { id: result.targetId },
        include: { questions: { orderBy: { order: "asc" } } },
      });
      break;
  }

  return NextResponse.json({ type: result.targetType, content });
}
