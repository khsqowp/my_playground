import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { readFile } from "fs/promises";
import path from "path";

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

  const ext = file.extension;
  const absPath = path.join(process.cwd(), "public", file.filePath);

  try {
    const buffer = await readFile(absPath);

    if (ext === "txt") {
      return NextResponse.json({
        type: "text",
        content: buffer.toString("utf-8").substring(0, 50000),
      });
    }

    if (ext === "md") {
      return NextResponse.json({
        type: "markdown",
        content: buffer.toString("utf-8").substring(0, 50000),
      });
    }

    if (ext === "docx") {
      const mammoth = await import("mammoth");
      const result = await mammoth.convertToHtml({ buffer });
      return NextResponse.json({
        type: "html",
        content: result.value.substring(0, 100000),
      });
    }

    if (ext === "xlsx") {
      const XLSX = await import("xlsx");
      const workbook = XLSX.read(buffer, { type: "buffer" });
      const sheets: Record<string, string[][]> = {};
      for (const sheetName of workbook.SheetNames) {
        const sheet = workbook.Sheets[sheetName];
        const rows = XLSX.utils.sheet_to_json<string[]>(sheet, {
          header: 1,
          defval: "",
        });
        sheets[sheetName] = rows.slice(0, 200) as string[][];
      }
      return NextResponse.json({ type: "table", sheets });
    }

    return NextResponse.json({ error: "Preview not supported for this file type" }, { status: 415 });
  } catch (err) {
    console.error("[PREVIEW_ERROR]", err);
    return NextResponse.json({ error: "Failed to read file" }, { status: 500 });
  }
}
