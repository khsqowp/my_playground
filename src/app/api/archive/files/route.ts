import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { unlink } from "fs/promises";
import path from "path";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = request.nextUrl;
  const search = searchParams.get("search") || "";
  const folder = searchParams.get("folder") || "";
  const folderList = searchParams.get("folderList") === "1";
  const page = parseInt(searchParams.get("page") || "1");
  const limit = parseInt(searchParams.get("limit") || "50");

  // Return unique folder list
  if (folderList) {
    const rows = await prisma.archiveFile.findMany({
      where: { authorId: session.user.id },
      select: { folder: true },
      distinct: ["folder"],
      orderBy: { folder: "asc" },
    });
    const folders = rows.map((r: { folder: string }) => r.folder);
    return NextResponse.json({ folders });
  }

  const where: any = { authorId: session.user.id };
  if (folder) where.folder = folder;
  if (search) {
    where.OR = [
      { fileName: { contains: search, mode: "insensitive" } },
      { aiSummary: { contains: search, mode: "insensitive" } },
      { aiTags: { contains: search, mode: "insensitive" } },
    ];
  }

  const [files, total] = await Promise.all([
    prisma.archiveFile.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.archiveFile.count({ where }),
  ]);

  return NextResponse.json({ files, total, page, totalPages: Math.ceil(total / limit) });
}

export async function PATCH(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id, folder } = await request.json();
  if (!id || !folder?.trim()) {
    return NextResponse.json({ error: "id and folder are required" }, { status: 400 });
  }

  const file = await prisma.archiveFile.findFirst({
    where: { id, authorId: session.user.id },
  });
  if (!file) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const updated = await prisma.archiveFile.update({
    where: { id },
    data: { folder: folder.trim() },
  });
  return NextResponse.json(updated);
}

export async function DELETE(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await request.json();
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });

  const file = await prisma.archiveFile.findFirst({
    where: { id, authorId: session.user.id },
  });
  if (!file) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const absPath = path.join(process.cwd(), "public", file.filePath);
  try {
    await unlink(absPath);
  } catch {
    // File might not exist on disk, continue with DB deletion
  }

  await prisma.archiveFile.delete({ where: { id } });
  return NextResponse.json({ success: true });
}
