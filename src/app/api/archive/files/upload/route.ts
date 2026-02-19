import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { writeFile, mkdir } from "fs/promises";
import path from "path";
import crypto from "crypto";
import {
  inferFolderFromFilename,
  extractTextContent,
  analyzeWithGemini,
} from "@/lib/archive-utils";

const ALLOWED_EXTENSIONS = ["zip", "pdf", "txt", "md", "docx", "xlsx", "pptx"];
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

function getExtension(filename: string): string {
  return filename.split(".").pop()?.toLowerCase() || "";
}

function generateStorageName(ext: string): string {
  const ts = Date.now();
  const rand = crypto.randomBytes(4).toString("hex");
  return `${ts}-${rand}.${ext}`;
}

interface ZipEntry {
  name: string;
  path: string;
  size: number;
  isDir: boolean;
  children?: ZipEntry[];
}

async function buildZipTree(buffer: Buffer): Promise<ZipEntry[]> {
  const JSZip = (await import("jszip")).default;
  const zip = await JSZip.loadAsync(buffer);
  const pathMap: Record<string, ZipEntry> = {};
  const roots: ZipEntry[] = [];
  const entries = Object.keys(zip.files).sort();

  for (const entryPath of entries) {
    const zipObj = zip.files[entryPath];
    const parts = entryPath.replace(/\/$/, "").split("/");
    const name = parts[parts.length - 1];
    if (!name) continue;

    const entry: ZipEntry = {
      name,
      path: entryPath,
      size: zipObj.dir ? 0 : (zipObj as any)._data?.uncompressedSize || 0,
      isDir: zipObj.dir,
      children: zipObj.dir ? [] : undefined,
    };
    pathMap[entryPath.replace(/\/$/, "")] = entry;

    if (parts.length === 1 || (parts.length === 2 && parts[0] === "")) {
      roots.push(entry);
    } else {
      const parentPath = parts.slice(0, -1).join("/");
      const parent = pathMap[parentPath];
      if (parent?.children) {
        parent.children.push(entry);
      } else {
        roots.push(entry);
      }
    }
  }
  return roots;
}

export async function POST(request: NextRequest) {
  try {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const formData = await request.formData();
  const file = formData.get("file") as File | null;

  if (!file) {
    return NextResponse.json({ error: "file is required" }, { status: 400 });
  }

  const ext = getExtension(file.name);
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return NextResponse.json(
      { error: `지원하지 않는 파일 형식입니다. 허용: ${ALLOWED_EXTENSIONS.join(", ")}` },
      { status: 400 }
    );
  }

  if (file.size > MAX_FILE_SIZE) {
    return NextResponse.json(
      { error: `파일 크기(${(file.size / 1024 / 1024).toFixed(1)}MB)가 50MB 제한을 초과했습니다.` },
      { status: 400 }
    );
  }

  // 중복 파일 체크 (같은 사용자, 같은 파일명)
  const duplicate = await prisma.archiveFile.findFirst({
    where: { fileName: file.name, authorId: session.user.id },
    select: { id: true },
  });
  if (duplicate) {
    return NextResponse.json(
      { error: "이미 동일한 파일이 존재합니다.", code: "DUPLICATE", fileId: duplicate.id },
      { status: 409 }
    );
  }

  const storageName = generateStorageName(ext);
  const uploadDir = path.join(process.cwd(), "public", "uploads", "archive");
  const filePath = `/uploads/archive/${storageName}`;
  const absPath = path.join(uploadDir, storageName);

  await mkdir(uploadDir, { recursive: true });
  const buffer = Buffer.from(await file.arrayBuffer());
  await writeFile(absPath, buffer);

  let zipTree: ZipEntry[] | null = null;
  if (ext === "zip") {
    try {
      zipTree = await buildZipTree(buffer);
    } catch (err) {
      console.error("[ZIP_TREE_ERROR]", err);
    }
  }

  const isSkipped = ["pdf", "pptx"].includes(ext);
  const record = await prisma.archiveFile.create({
    data: {
      fileName: file.name,
      storageName,
      filePath,
      fileType: file.type || `application/${ext}`,
      fileSize: file.size,
      extension: ext,
      folder: isSkipped ? inferFolderFromFilename(file.name, ext) : "미분류",
      aiStatus: isSkipped ? "SKIPPED" : "PROCESSING",
      zipTree: zipTree ? (zipTree as any) : undefined,
      authorId: session.user.id,
    },
  });

  if (!isSkipped) {
    const content = await extractTextContent(buffer, ext);
    const { summary, tags, folder, status } = await analyzeWithGemini(file.name, ext, content);

    await prisma.archiveFile.update({
      where: { id: record.id },
      data: {
        aiSummary: summary || null,
        aiTags: tags || null,
        folder: folder || inferFolderFromFilename(file.name, ext),
        aiStatus: status as any,
      },
    });

    return NextResponse.json(
      { ...record, aiSummary: summary, aiTags: tags, folder, aiStatus: status },
      { status: 201 }
    );
  }

  return NextResponse.json(record, { status: 201 });
  } catch (e: any) {
    console.error("[UPLOAD_ERROR]", e.message);
    return NextResponse.json({ error: e.message || "업로드 중 오류 발생" }, { status: 500 });
  }
}
