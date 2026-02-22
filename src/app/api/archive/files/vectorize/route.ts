import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { extractTextFromFile, chunkText, generateEmbedding } from "@/lib/vector-utils";
import path from "path";

/**
 * 아카이브 파일 일괄 벡터화 API (브라우저 접속 허용을 위해 GET 지원)
 */
export async function GET(req: NextRequest) {
  try {
    const session = await auth();
    if (!session) return new NextResponse("Unauthorized", { status: 401 });

    // 1. 처리 대상 파일 조회 (실패했던 파일도 재시도 포함)
    const pendingFiles = await prisma.archiveFile.findMany({
      where: {
        aiStatus: { in: ["PENDING", "SKIPPED", "FAILED"] },
        extension: { in: [".pdf", ".md", ".txt", "pdf", "md", "txt"] }
      },
      take: 10
    });

    if (pendingFiles.length === 0) {
      return NextResponse.json({ message: "더 이상 처리할 파일이 없습니다." });
    }

    const results = [];
    const errors = [];

    for (const file of pendingFiles) {
      try {
        // 파일 간 1초 지연 (API 할당량 보호)
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const fullPath = path.join(process.cwd(), "public", "uploads", "archive", file.storageName);
        
        // 2. 텍스트 추출
        const text = await extractTextFromFile(fullPath);
        if (!text || text.trim().length === 0) {
          // 텍스트가 없으면 완료 처리하되 aiStatus를 DONE으로 바꿔서 다시 검색되지 않게 함
          await prisma.archiveFile.update({
            where: { id: file.id },
            data: { aiStatus: "DONE", aiSummary: "내용이 없는 파일입니다." }
          });
          errors.push({ fileName: file.fileName, reason: "내용 없음" });
          continue;
        }

        // 3. 청킹
        const chunks = chunkText(text);

        // 4. 각 청크 임베딩 및 저장
        for (const content of chunks) {
          const embedding = await generateEmbedding(content);
          const vectorStr = `[${embedding.join(",")}]`;
          await prisma.$executeRawUnsafe(
            `INSERT INTO "FileChunk" ("id", "content", "fileId", "embedding", "createdAt") 
             VALUES ($1, $2, $3, $4::vector, NOW())`,
            crypto.randomUUID(),
            content,
            file.id,
            vectorStr
          );
        }

        // 5. 상태 업데이트
        await prisma.archiveFile.update({
          where: { id: file.id },
          data: { aiStatus: "DONE" }
        });

        results.push({ id: file.id, fileName: file.fileName, chunks: chunks.length });
      } catch (err: any) {
        console.error(`[VECTORIZE_FILE_ERROR] ${file.fileName}:`, err.message);
        await prisma.archiveFile.update({
          where: { id: file.id },
          data: { aiStatus: "FAILED" }
        });
        errors.push({ fileName: file.fileName, reason: err.message });
      }
    }

    return NextResponse.json({ 
      message: "벡터화 작업 결과",
      processedCount: results.length,
      processed: results,
      failed: errors
    });

  } catch (error: any) {
    console.error("[ARCHIVE_VECTORIZE_ERROR]", error);
    return new NextResponse(error.message || "Internal Server Error", { status: 500 });
  }
}
