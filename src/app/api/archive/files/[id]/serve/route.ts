import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { stat, open } from "fs/promises";
import path from "path";

const MIME_MAP: Record<string, string> = {
  pdf: "application/pdf",
  txt: "text/plain; charset=utf-8",
  md: "text/plain; charset=utf-8",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  zip: "application/zip",
};

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  const file = await prisma.archiveFile.findFirst({
    where: { id, authorId: session.user.id },
  });
  if (!file) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const absPath = path.join(process.cwd(), "public", file.filePath);

  let fileStat: Awaited<ReturnType<typeof stat>>;
  try {
    fileStat = await stat(absPath);
  } catch {
    return NextResponse.json({ error: "File not found on disk" }, { status: 404 });
  }

  const mimeType = MIME_MAP[file.extension] || "application/octet-stream";
  const contentDisposition = `inline; filename*=UTF-8''${encodeURIComponent(file.fileName)}`;

  // Handle range requests (needed for large PDFs / seeking)
  const rangeHeader = request.headers.get("range");
  const fileSize = fileStat.size;

  if (rangeHeader) {
    const match = rangeHeader.match(/bytes=(\d+)-(\d*)/);
    if (match) {
      const start = parseInt(match[1]);
      const end = match[2] ? parseInt(match[2]) : fileSize - 1;
      const chunkSize = end - start + 1;

      const fh = await open(absPath, "r");
      const buf = Buffer.alloc(chunkSize);
      await fh.read(buf, 0, chunkSize, start);
      await fh.close();

      return new Response(buf, {
        status: 206,
        headers: {
          "Content-Type": mimeType,
          "Content-Disposition": contentDisposition,
          "Content-Range": `bytes ${start}-${end}/${fileSize}`,
          "Accept-Ranges": "bytes",
          "Content-Length": String(chunkSize),
          "Cache-Control": "private, max-age=3600",
        },
      });
    }
  }

  // Full file response using a readable stream
  const fh = await open(absPath, "r");
  const nodeStream = fh.createReadStream();

  const webStream = new ReadableStream({
    start(controller) {
      nodeStream.on("data", (chunk: Buffer) => controller.enqueue(chunk));
      nodeStream.on("end", () => {
        controller.close();
        fh.close().catch(() => {});
      });
      nodeStream.on("error", (err) => {
        controller.error(err);
        fh.close().catch(() => {});
      });
    },
    cancel() {
      nodeStream.destroy();
      fh.close().catch(() => {});
    },
  });

  return new Response(webStream, {
    status: 200,
    headers: {
      "Content-Type": mimeType,
      "Content-Disposition": contentDisposition,
      "Content-Length": String(fileSize),
      "Accept-Ranges": "bytes",
      "Cache-Control": "private, max-age=3600",
    },
  });
}
