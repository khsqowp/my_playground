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
  const andClauses: any[] = [];

  // 폴더 필터: 정확히 일치 OR 하위 폴더 (부모 클릭 시 자식 파일 포함)
  if (folder) {
    andClauses.push({
      OR: [
        { folder: folder },
        { folder: { startsWith: folder + "/" } },
      ],
    });
  }

  if (search === "분석 실패") {
    // 특수 키워드: FAILED 상태 파일만 (SKIPPED 제외)
    where.aiStatus = "FAILED";
  } else if (search) {
    andClauses.push({
      OR: [
        { fileName: { contains: search, mode: "insensitive" } },
        { aiSummary: { contains: search, mode: "insensitive" } },
        { aiTags: { contains: search, mode: "insensitive" } },
      ],
    });
  }

  if (andClauses.length > 0) {
    where.AND = andClauses;
  }

  const files = await prisma.archiveFile.findMany({
    where,
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ files, total: files.length });
}

export async function PATCH(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const folder: string = body.folder?.trim();
  if (!folder) return NextResponse.json({ error: "folder is required" }, { status: 400 });

  // 단일: { id, folder } | 다중: { ids, folder }
  if (body.ids && Array.isArray(body.ids) && body.ids.length > 0) {
    // 소유권 확인
    const owned = await prisma.archiveFile.findMany({
      where: { id: { in: body.ids }, authorId: session.user.id },
      select: { id: true },
    });
    const ownedIds = owned.map((f: { id: string }) => f.id);
    await prisma.archiveFile.updateMany({
      where: { id: { in: ownedIds } },
      data: { folder },
    });
    return NextResponse.json({ updated: ownedIds.length });
  }

  const id: string = body.id;
  if (!id) return NextResponse.json({ error: "id or ids required" }, { status: 400 });

  const file = await prisma.archiveFile.findFirst({
    where: { id, authorId: session.user.id },
  });
  if (!file) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const updated = await prisma.archiveFile.update({
    where: { id },
    data: { folder },
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
