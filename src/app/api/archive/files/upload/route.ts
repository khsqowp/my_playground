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

/** 파일명/확장자로 폴더를 추론 (텍스트 추출 불가 파일용 fallback) */
function inferFolderFromFilename(fileName: string, ext: string): string {
  const name = fileName.toLowerCase().replace(/\.[^.]+$/, "");

  const keywordMap: [string[], string][] = [
    [["typescript", " ts ", "_ts_", "-ts-"], "개발/TypeScript"],
    [["javascript", " js ", "_js_", "-js-"], "개발/JavaScript"],
    [["python", " py ", "_py_"], "개발/Python"],
    [["react", "nextjs", "next.js", "vue", "angular"], "개발/프론트엔드"],
    [["docker", "kubernetes", "k8s", "devops", "ci-cd", "cicd"], "개발/DevOps"],
    [["database", "db", "sql", "mysql", "postgres", "mongodb"], "개발/데이터베이스"],
    [["api", "rest", "graphql", "swagger", "openapi"], "개발/API"],
    [["report", "보고서", "리포트"], "문서/보고서"],
    [["meeting", "회의", "미팅", "minutes"], "문서/회의록"],
    [["proposal", "기획", "제안"], "문서/기획"],
    [["resume", "이력서", "cv", "portfolio", "포트폴리오"], "문서/이력서"],
    [["lecture", "강의", "tutorial", "튜토리얼", "course"], "학습/강의자료"],
    [["note", "노트", "study", "공부", "학습"], "학습/노트"],
    [["quiz", "퀴즈", "exam", "시험", "test"], "학습/시험"],
    [["design", "디자인", "ui", "ux", "figma", "wireframe"], "디자인"],
    [["data", "dataset", "분석", "analysis", "chart", "graph"], "데이터/분석"],
    [["log", "로그", "backup", "백업"], "시스템/로그"],
    [["config", "설정", "settings", "env"], "시스템/설정"],
  ];

  for (const [keywords, folder] of keywordMap) {
    if (keywords.some((k) => name.includes(k))) return folder;
  }

  const extMap: Record<string, string> = {
    pdf: "문서/PDF",
    pptx: "문서/발표자료",
    xlsx: "데이터/스프레드시트",
    docx: "문서",
    zip: "아카이브",
    txt: "문서/텍스트",
    md: "개발/문서",
  };
  return extMap[ext] || "미분류";
}

async function analyzeWithGemini(
  fileName: string,
  ext: string,
  content: string | null
): Promise<{ summary: string; tags: string; folder: string; status: string }> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || !content) {
    return { summary: "", tags: "", folder: inferFolderFromFilename(fileName, ext), status: "SKIPPED" };
  }

  const prompt = `다음 파일을 분석해서 한국어로 요약, 태그, 폴더를 JSON으로 반환해줘.

파일명: ${fileName}
내용:
${content}

폴더는 계층 구조로 "상위폴더/하위폴더" 형식으로 지정해줘. 예시: "개발/TypeScript", "문서/보고서", "학습/노트", "데이터/분석", "디자인", "아카이브", "미분류"

반드시 아래 JSON 형식으로만 응답해줘 (마크다운 없이 순수 JSON):
{"summary": "한국어 요약 2-3문장", "tags": "태그1,태그2,태그3,태그4,태그5", "folder": "상위/하위"}`;

  try {
    const raw = await callGemini(prompt, apiKey);
    const cleaned = raw.replace(/```json\n?|\n?```/g, "").trim();

    let parsed: { summary: string; tags: string; folder?: string };
    try {
      parsed = JSON.parse(cleaned);
    } catch {
      const summaryMatch = cleaned.match(/"summary"\s*:\s*"([^"]+)"/);
      const tagsMatch = cleaned.match(/"tags"\s*:\s*"([^"]+)"/);
      const folderMatch = cleaned.match(/"folder"\s*:\s*"([^"]+)"/);
      parsed = {
        summary: summaryMatch?.[1] || "",
        tags: tagsMatch?.[1] || "",
        folder: folderMatch?.[1] || "",
      };
    }

    return {
      summary: parsed.summary || "",
      tags: parsed.tags || "",
      folder: parsed.folder || inferFolderFromFilename(fileName, ext),
      status: "DONE",
    };
  } catch (err) {
    console.error("[GEMINI_ARCHIVE_ERROR]", err);
    return { summary: "", tags: "", folder: inferFolderFromFilename(fileName, ext), status: "FAILED" };
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

  // Create initial DB record
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

  // AI analysis (for supported types)
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
}
