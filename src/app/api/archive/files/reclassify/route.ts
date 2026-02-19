import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { readFile } from "fs/promises";
import path from "path";
import {
  inferFolderFromFilename,
  extractTextContent,
  analyzeWithGemini,
} from "@/lib/archive-utils";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  // ids: 특정 파일 ID 배열 | unclassifiedOnly: 미분류 전체 | failedOnly: 분석 실패 전체
  const ids: string[] | undefined = body.ids;
  const unclassifiedOnly: boolean = body.unclassifiedOnly === true;
  const failedOnly: boolean = body.failedOnly === true;

  let files: { id: string; fileName: string; extension: string; filePath: string }[];

  if (ids && ids.length > 0) {
    files = await prisma.archiveFile.findMany({
      where: { id: { in: ids }, authorId: session.user.id },
      select: { id: true, fileName: true, extension: true, filePath: true },
    });
  } else if (unclassifiedOnly) {
    files = await prisma.archiveFile.findMany({
      where: { authorId: session.user.id, folder: "미분류" },
      select: { id: true, fileName: true, extension: true, filePath: true },
    });
  } else if (failedOnly) {
    files = await prisma.archiveFile.findMany({
      where: { authorId: session.user.id, aiStatus: "FAILED" },
      select: { id: true, fileName: true, extension: true, filePath: true },
    });
  } else {
    return NextResponse.json({ error: "ids or unclassifiedOnly or failedOnly required" }, { status: 400 });
  }

  if (files.length === 0) {
    return NextResponse.json({ queued: 0, message: "대상 파일이 없습니다." });
  }

  const queued = files.length;

  // 백그라운드에서 순차 처리 (Gemini rate limit 고려)
  ;(async () => {
    for (const file of files) {
      try {
        const absPath = path.join(process.cwd(), "public", file.filePath);
        const ext = file.extension;
        const isSkipped = ["pdf", "pptx"].includes(ext);

        if (isSkipped) {
          // 파일명 기반 폴더 추론만 수행
          const folder = inferFolderFromFilename(file.fileName, ext);
          await prisma.archiveFile.update({
            where: { id: file.id },
            data: { folder },
          });
        } else {
          let buffer: Buffer;
          try {
            buffer = await readFile(absPath);
          } catch {
            console.warn(`[RECLASSIFY] 파일 없음: ${absPath}`);
            continue;
          }

          const content = await extractTextContent(buffer, ext);
          const { summary, tags, folder, status } = await analyzeWithGemini(
            file.fileName,
            ext,
            content
          );

          await prisma.archiveFile.update({
            where: { id: file.id },
            data: {
              folder: folder || inferFolderFromFilename(file.fileName, ext),
              aiSummary: summary || undefined,
              aiTags: tags || undefined,
              aiStatus: status as any,
            },
          });
        }

        // Gemini rate limit 방지 딜레이 (20 RPM = 3s/req, 라운드로빈으로 분산되므로 3.5s 유지)
        await new Promise((r) => setTimeout(r, 3500));
      } catch (e: any) {
        console.error(`[RECLASSIFY] id=${file.id}`, e.message);
      }
    }
    console.log(`[RECLASSIFY] 완료: ${queued}건`);
  })().catch((e) => console.error("[RECLASSIFY_ERROR]", e));

  return NextResponse.json({
    queued,
    message: `${queued}개 파일을 백그라운드에서 재분류합니다.`,
  });
}
