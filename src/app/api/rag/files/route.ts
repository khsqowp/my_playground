import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import fs from "fs";
import { mkdir, unlink, writeFile } from "fs/promises";
import path from "path";
import mime from "mime";

const SUPPORTED_EXTENSIONS = new Set([
  ".pdf",
  ".docx",
  ".pptx",
  ".xlsx",
  ".md",
  ".txt",
  ".hwp",
  ".hwpx",
  ".mp3",
  ".m4a",
  ".wav",
  ".flac",
  ".aac",
  ".ogg",
  ".opus",
  ".mp4",
  ".mov",
  ".mkv",
  ".avi",
  ".webm",
  ".m4v",
]);

function getDataRoot() {
  return path.resolve(process.env.RAG_DATA_ROOT || "/Volumes/SSD T7/AI/data");
}

function cleanSegment(value: string) {
  const trimmed = value.trim();
  if (!trimmed || trimmed === "." || trimmed === ".." || trimmed.includes("/") || trimmed.includes("\\")) {
    throw new Error("Invalid path segment");
  }
  return trimmed;
}

function resolveProjectPath(project: string, relativePath = "") {
  const root = getDataRoot();
  const safeProject = cleanSegment(project);
  const projectRoot = path.resolve(root, safeProject);
  const rel = relativePath.trim().replace(/^\/+/, "");
  if (rel.includes("\0")) throw new Error("Invalid path");

  const target = path.resolve(projectRoot, rel || ".");
  if (!target.startsWith(projectRoot + path.sep) && target !== projectRoot) {
    throw new Error("Path traversal blocked");
  }

  return { root, projectRoot, target, relative: rel };
}

function toProjectRelative(projectRoot: string, target: string) {
  const rel = path.relative(projectRoot, target);
  return rel === "" ? "" : rel.split(path.sep).join("/");
}

async function requireUser(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  return null;
}

function listProjects() {
  const root = getDataRoot();
  if (!fs.existsSync(root)) return [];
  try {
    return fs
      .readdirSync(root, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))
      .map((entry) => entry.name)
      .sort((a, b) => a.localeCompare(b));
  } catch (error) {
    console.error("[RAG_LIST_PROJECTS_ERROR]", error);
    return [];
  }
}

function summarizeProject(project: string) {
  const { projectRoot } = resolveProjectPath(project);
  const summary = {
    project,
    fileCount: 0,
    directoryCount: 0,
    supportedCount: 0,
    totalSize: 0,
    updatedAt: null as string | null,
    extensions: {} as Record<string, number>,
    warnings: [] as Array<{ path: string; error: string }>,
  };

  if (!fs.existsSync(projectRoot)) return summary;

  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error: any) {
      summary.warnings.push({
        path: toProjectRelative(projectRoot, dir) || ".",
        error: error.message || "Failed to read directory",
      });
      return;
    }

    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;
      const absolute = path.join(dir, entry.name);
      let stats: fs.Stats;
      try {
        stats = fs.statSync(absolute);
      } catch (error: any) {
        summary.warnings.push({
          path: toProjectRelative(projectRoot, absolute),
          error: error.message || "Failed to read file stats",
        });
        continue;
      }
      const mtime = stats.mtime.toISOString();
      if (!summary.updatedAt || mtime > summary.updatedAt) {
        summary.updatedAt = mtime;
      }

      if (entry.isDirectory()) {
        summary.directoryCount += 1;
        walk(absolute);
        continue;
      }

      const ext = path.extname(entry.name).toLowerCase();
      const key = ext ? ext.replace(/^\./, "") : "file";
      summary.fileCount += 1;
      summary.totalSize += stats.size;
      summary.extensions[key] = (summary.extensions[key] || 0) + 1;
      if (SUPPORTED_EXTENSIONS.has(ext)) summary.supportedCount += 1;
    }
  };

  walk(projectRoot);
  return summary;
}

export async function GET(request: NextRequest) {
  const unauthorized = await requireUser(request);
  if (unauthorized) return unauthorized;

  const params = request.nextUrl.searchParams;
  const action = params.get("action") || "list";
  const project = params.get("project") || process.env.RAG_DEFAULT_PROJECT || "inbox";
  const requestedPath = params.get("path") || "";

  try {
    if (action === "projects") {
      return NextResponse.json({
        root: getDataRoot(),
        projects: listProjects(),
        defaultProject: process.env.RAG_DEFAULT_PROJECT || "inbox",
      });
    }

    if (action === "stats") {
      const projects = listProjects();
      const summaries = projects.map((name) => summarizeProject(name));
      return NextResponse.json({
        root: getDataRoot(),
        defaultProject: process.env.RAG_DEFAULT_PROJECT || "inbox",
        projects: summaries,
        totals: summaries.reduce(
          (acc, item) => ({
            fileCount: acc.fileCount + item.fileCount,
            directoryCount: acc.directoryCount + item.directoryCount,
            supportedCount: acc.supportedCount + item.supportedCount,
            totalSize: acc.totalSize + item.totalSize,
          }),
          { fileCount: 0, directoryCount: 0, supportedCount: 0, totalSize: 0 }
        ),
      });
    }

    const { projectRoot, target } = resolveProjectPath(project, requestedPath);

    if (action === "list") {
      if (!fs.existsSync(target)) {
        return NextResponse.json({ error: "Path not found" }, { status: 404 });
      }
      const stats = fs.statSync(target);
      if (!stats.isDirectory()) {
        return NextResponse.json({ error: "Not a directory" }, { status: 400 });
      }

      const items = fs
        .readdirSync(target, { withFileTypes: true })
        .filter((entry) => !entry.name.startsWith("."))
        .map((entry) => {
          const absolute = path.join(target, entry.name);
          const itemStats = fs.statSync(absolute);
          const ext = entry.isDirectory() ? "" : path.extname(entry.name).toLowerCase();
          return {
            name: entry.name,
            path: toProjectRelative(projectRoot, absolute),
            isDirectory: entry.isDirectory(),
            size: itemStats.size,
            updatedAt: itemStats.mtime.toISOString(),
            extension: ext.replace(/^\./, ""),
            supported: entry.isDirectory() || SUPPORTED_EXTENSIONS.has(ext),
          };
        })
        .sort((a, b) => {
          if (a.isDirectory === b.isDirectory) return a.name.localeCompare(b.name);
          return a.isDirectory ? -1 : 1;
        });

      return NextResponse.json({
        project,
        path: toProjectRelative(projectRoot, target),
        items,
      });
    }

    if (action === "content") {
      if (!fs.existsSync(target)) {
        return NextResponse.json({ error: "File not found" }, { status: 404 });
      }
      const stats = fs.statSync(target);
      if (stats.isDirectory()) {
        return NextResponse.json({ error: "Cannot preview directory" }, { status: 400 });
      }

      const mimeType = mime.getType(target) || "application/octet-stream";
      const ext = path.extname(target).toLowerCase();
      const isText =
        mimeType.startsWith("text/") ||
        ["application/json", "application/xml"].includes(mimeType) ||
        [".md", ".txt", ".csv", ".json", ".xml", ".yaml", ".yml"].includes(ext);

      if (isText) {
        if (stats.size > 2 * 1024 * 1024) {
          return NextResponse.json({ type: "binary", mimeType, size: stats.size });
        }
        return NextResponse.json({
          type: "text",
          mimeType,
          content: fs.readFileSync(target, "utf-8"),
        });
      }

      if (mimeType.startsWith("image/")) {
        const buffer = fs.readFileSync(target);
        return NextResponse.json({
          type: "image",
          mimeType,
          content: `data:${mimeType};base64,${buffer.toString("base64")}`,
        });
      }

      if (mimeType === "application/pdf") {
        return NextResponse.json({ type: "pdf", mimeType, size: stats.size });
      }

      return NextResponse.json({ type: "binary", mimeType, size: stats.size });
    }

    if (action === "download" || action === "view") {
      if (!fs.existsSync(target)) {
        return NextResponse.json({ error: "File not found" }, { status: 404 });
      }
      if (fs.statSync(target).isDirectory()) {
        return NextResponse.json({ error: "Cannot download directory" }, { status: 400 });
      }
      const buffer = fs.readFileSync(target);
      const mimeType = mime.getType(target) || "application/octet-stream";
      const disposition = action === "view" ? "inline" : "attachment";
      return new NextResponse(buffer, {
        headers: {
          "Content-Type": mimeType,
          "Content-Disposition": `${disposition}; filename="${encodeURIComponent(path.basename(target))}"`,
          "Cache-Control": "private, max-age=60",
        },
      });
    }

    return NextResponse.json({ error: "Invalid action" }, { status: 400 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || "RAG file API error" }, { status: 400 });
  }
}

export async function POST(request: NextRequest) {
  const unauthorized = await requireUser(request);
  if (unauthorized) return unauthorized;

  const params = request.nextUrl.searchParams;
  const action = params.get("action") || "upload";

  try {
    if (action === "reindex") {
      const body = await request.json().catch(() => ({}));
      const project = String(body.project || process.env.RAG_DEFAULT_PROJECT || "inbox").normalize("NFC");
      const serviceUrl = process.env.RAG_SERVICE_URL || "http://rag-web:8088";
      const res = await fetch(`${serviceUrl}/api/reindex`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ project, recreate: body.recreate ?? true }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return NextResponse.json(
          {
            error: data.detail || data.error || "RAG 재색인 요청 실패",
            project,
            serviceStatus: res.status,
          },
          { status: res.status }
        );
      }
      return NextResponse.json(data, { status: res.status });
    }

    const form = await request.formData();
    const project = String(form.get("project") || process.env.RAG_DEFAULT_PROJECT || "inbox");
    const relativePath = String(form.get("path") || "");
    const files = form.getAll("files").filter((file): file is File => file instanceof File);
    const { target, projectRoot } = resolveProjectPath(project, relativePath);

    if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
      return NextResponse.json({ error: "Upload folder not found" }, { status: 404 });
    }

    const uploaded = [];
    for (const file of files) {
      const fileName = cleanSegment(file.name);
      const ext = path.extname(fileName).toLowerCase();
      if (!SUPPORTED_EXTENSIONS.has(ext)) {
        return NextResponse.json({ error: `Unsupported file type: ${fileName}` }, { status: 400 });
      }
      const destination = path.resolve(target, fileName);
      if (!destination.startsWith(projectRoot + path.sep)) {
        return NextResponse.json({ error: "Invalid upload path" }, { status: 400 });
      }
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, Buffer.from(await file.arrayBuffer()));
      uploaded.push({ name: fileName, path: toProjectRelative(projectRoot, destination) });
    }

    return NextResponse.json({ uploaded });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || "RAG file upload failed" }, { status: 400 });
  }
}

export async function DELETE(request: NextRequest) {
  const unauthorized = await requireUser(request);
  if (unauthorized) return unauthorized;

  try {
    const body = await request.json();
    const project = body.project || process.env.RAG_DEFAULT_PROJECT || "inbox";
    const requestedPath = String(body.path || "");
    if (!requestedPath) {
      return NextResponse.json({ error: "path is required" }, { status: 400 });
    }

    const { target } = resolveProjectPath(project, requestedPath);
    if (!fs.existsSync(target)) {
      return NextResponse.json({ error: "File not found" }, { status: 404 });
    }
    if (fs.statSync(target).isDirectory()) {
      return NextResponse.json({ error: "Directory deletion is not allowed here" }, { status: 400 });
    }

    await unlink(target);
    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || "RAG file delete failed" }, { status: 400 });
  }
}
