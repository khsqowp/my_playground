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

    // 1. 처리 대상 파일 조회
    const pendingFiles = await prisma.archiveFile.findMany({
      where: {
        aiStatus: "PENDING",
        extension: { in: [".pdf", ".md", ".txt"] }
      },
      take: 10 // 한 번에 너무 많이 처리하지 않도록 제한
    });

    if (pendingFiles.length === 0) {
      return NextResponse.json({ message: "처리할 파일이 없습니다." });
    }

    const results = [];

    for (const file of pendingFiles) {
      try {
        const fullPath = path.join(process.cwd(), "public", "uploads", "archive", file.storageName);
        
        // 2. 텍스트 추출
        const text = await extractTextFromFile(fullPath);
        if (!text || text.trim().length === 0) {
          await prisma.archiveFile.update({
            where: { id: file.id },
            data: { aiStatus: "SKIPPED" }
          });
          continue;
        }

        // 3. 청킹
        const chunks = chunkText(text);

        // 4. 각 청크 임베딩 및 저장
        for (const content of chunks) {
          const embedding = await generateEmbedding(content);
          
          // pgvector 컬럼 저장을 위해 executeRaw 사용
          const vectorStr = `[${embedding.join(",")}]`;
          await prisma.$executeRawUnsafe(
            `INSERT INTO "FileChunk" ("id", "content", "fileId", "embedding", "createdAt") 
             VALUES ($1, $2, $3, $4::vector, NOW())`,
            crypto.randomUUID(), // id
            content,             // content
            file.id,             // fileId
            vectorStr            // embedding
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
      }
    }

    return NextResponse.json({ 
      message: "벡터화 작업이 완료되었습니다.",
      processed: results 
    });

  } catch (error: any) {
    console.error("[ARCHIVE_VECTORIZE_ERROR]", error);
    return new NextResponse(error.message || "Internal Server Error", { status: 500 });
  }
}
