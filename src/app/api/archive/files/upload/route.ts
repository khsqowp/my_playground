import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { callGemini } from "@/lib/ai";
import { writeFile, mkdir } from "fs/promises";
import path from "path";
import crypto from "crypto";

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

  // Sort entries to process directories before files
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

async function extractTextContent(buffer: Buffer, ext: string): Promise<string | null> {
  try {
    if (ext === "txt" || ext === "md") {
      return buffer.toString("utf-8").substring(0, 3000);
    }

    if (ext === "docx") {
      const mammoth = await import("mammoth");
      const result = await mammoth.extractRawText({ buffer });
      return result.value.substring(0, 3000);
    }

    if (ext === "xlsx") {
      const XLSX = await import("xlsx");
      const workbook = XLSX.read(buffer, { type: "buffer" });
      let text = "";
      for (const sheetName of workbook.SheetNames) {
        const sheet = workbook.Sheets[sheetName];
        const csv = XLSX.utils.sheet_to_csv(sheet);
        text += `[${sheetName}]\n${csv}\n\n`;
        if (text.length > 3000) break;
      }
      return text.substring(0, 3000);
    }

    if (ext === "zip") {
      // For ZIP, return the file list as content
      const JSZip = (await import("jszip")).default;
      const zip = await JSZip.loadAsync(buffer);
      const fileList = Object.keys(zip.files)
        .filter((k) => !zip.files[k].dir)
        .join("\n");
      return `ZIP 파일 목록:\n${fileList}`.substring(0, 3000);
    }
  } catch (err) {
    console.error(`[EXTRACT_ERROR] ${ext}:`, err);
  }

  return null; // pdf, pptx — skipped
}

async function analyzeWithGemini(
  fileName: string,
  ext: string,
  content: string | null
): Promise<{ summary: string; tags: string; status: string }> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || !content) {
    return { summary: "", tags: "", status: "SKIPPED" };
  }

  const prompt = `다음 파일을 분석해서 한국어로 요약과 태그를 JSON으로 반환해줘.

파일명: ${fileName}
내용:
${content}

반드시 아래 JSON 형식으로만 응답해줘 (마크다운 없이 순수 JSON):
{"summary": "한국어 요약 2-3문장", "tags": "태그1,태그2,태그3,태그4,태그5"}`;

  try {
    const raw = await callGemini(prompt, apiKey);
    const cleaned = raw.replace(/```json\n?|\n?```/g, "").trim();

    let parsed: { summary: string; tags: string };
    try {
      parsed = JSON.parse(cleaned);
    } catch {
      // Fallback regex extraction
      const summaryMatch = cleaned.match(/"summary"\s*:\s*"([^"]+)"/);
      const tagsMatch = cleaned.match(/"tags"\s*:\s*"([^"]+)"/);
      parsed = {
        summary: summaryMatch?.[1] || "",
        tags: tagsMatch?.[1] || "",
      };
    }

    return {
      summary: parsed.summary || "",
      tags: parsed.tags || "",
      status: "DONE",
    };
  } catch (err) {
    console.error("[GEMINI_ARCHIVE_ERROR]", err);
    return { summary: "", tags: "", status: "FAILED" };
  }
}

export async function POST(request: NextRequest) {
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
    return NextResponse.json({ error: "파일 크기는 50MB를 초과할 수 없습니다." }, { status: 400 });
  }

  const storageName = generateStorageName(ext);
  const uploadDir = path.join(process.cwd(), "public", "uploads", "archive");
  const filePath = `/uploads/archive/${storageName}`;
  const absPath = path.join(uploadDir, storageName);

  await mkdir(uploadDir, { recursive: true });
  const buffer = Buffer.from(await file.arrayBuffer());
  await writeFile(absPath, buffer);

  // Build ZIP tree
  let zipTree: ZipEntry[] | null = null;
  if (ext === "zip") {
    try {
      zipTree = await buildZipTree(buffer);
    } catch (err) {
      console.error("[ZIP_TREE_ERROR]", err);
    }
  }

  // Create initial DB record with PROCESSING status
  const record = await prisma.archiveFile.create({
    data: {
      fileName: file.name,
      storageName,
      filePath,
      fileType: file.type || `application/${ext}`,
      fileSize: file.size,
      extension: ext,
      aiStatus: ["pdf", "pptx"].includes(ext) ? "SKIPPED" : "PROCESSING",
      zipTree: zipTree ? (zipTree as any) : undefined,
      authorId: session.user.id,
    },
  });

  // AI analysis (for supported types)
  if (!["pdf", "pptx"].includes(ext)) {
    const content = await extractTextContent(buffer, ext);
    const { summary, tags, status } = await analyzeWithGemini(file.name, ext, content);

    await prisma.archiveFile.update({
      where: { id: record.id },
      data: {
        aiSummary: summary || null,
        aiTags: tags || null,
        aiStatus: status as any,
      },
    });

    return NextResponse.json(
      { ...record, aiSummary: summary, aiTags: tags, aiStatus: status },
      { status: 201 }
    );
  }

  return NextResponse.json(record, { status: 201 });
}
