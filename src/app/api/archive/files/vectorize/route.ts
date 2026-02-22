import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { extractTextFromFile, chunkText, generateEmbedding } from "@/lib/vector-utils";
import path from "path";
import crypto from "crypto";

/**
 * 아카이브 파일 조각 단위(Chunk-by-Chunk) 벡터화 API
 * 타임아웃 방지를 위해 한 번에 최대 5개의 청크만 처리함
 */
export async function GET(req: NextRequest) {
  try {
    const session = await auth();
    if (!session) return new NextResponse("Unauthorized", { status: 401 });

    // 1. 현재 진행 중(PROCESSING)인 파일을 먼저 찾거나, 없으면 대기 중(PENDING/SKIPPED/FAILED)인 파일 하나를 가져옴
    let file = await prisma.archiveFile.findFirst({
      where: { aiStatus: "PROCESSING" },
      orderBy: { updatedAt: "asc" }
    });

    if (!file) {
      file = await prisma.archiveFile.findFirst({
        where: {
          aiStatus: { in: ["PENDING", "SKIPPED", "FAILED"] },
          extension: { in: [".pdf", ".md", ".txt", "pdf", "md", "txt"] }
        },
        orderBy: { createdAt: "asc" }
      });
    }

    if (!file) {
      return NextResponse.json({ message: "더 이상 처리할 파일이 없습니다.", processedCount: 0 });
    }

    console.log(`[VECTORIZE] 대상 파일 선정: ${file.fileName} (ID: ${file.id})`);
    const fullPath = path.join(process.cwd(), "public", "uploads", "archive", file.storageName);

    // 2. 만약 조각(FileChunk) 데이터가 하나도 없다면, 먼저 텍스트를 추출하여 조각들을 생성함
    const chunkCountResult: any[] = await prisma.$queryRawUnsafe(
      `SELECT COUNT(*)::int as count FROM "FileChunk" WHERE "fileId" = $1`,
      file.id
    );
    const existingChunkCount = chunkCountResult[0]?.count || 0;
    
    if (existingChunkCount === 0) {
      console.log(`[VECTORIZE] 텍스트 추출 시작: ${file.fileName}`);
      const text = await extractTextFromFile(fullPath);
      if (!text || text.trim().length === 0) {
        console.log(`[VECTORIZE] 텍스트 없음: ${file.fileName}`);
        await prisma.archiveFile.update({
          where: { id: file.id },
          data: { aiStatus: "DONE", aiSummary: "내용이 없는 파일입니다." }
        });
        return NextResponse.json({ message: "내용 없음 처리 완료", processedCount: 1, fileName: file.fileName });
      }

      const chunks = chunkText(text);
      console.log(`[VECTORIZE] 조각 생성 완료 (${chunks.length}개): ${file.fileName}`);
      
      // 모든 조각을 embedding 없이 먼저 DB에 저장 (안전한 처리를 위해 순차 저장)
      for (const content of chunks) {
        await prisma.fileChunk.create({
          data: {
            id: crypto.randomUUID(),
            content,
            fileId: file.id
          }
        });
      }

      await prisma.archiveFile.update({
        where: { id: file.id },
        data: { aiStatus: "PROCESSING" }
      });

      return NextResponse.json({ 
        message: "조각 생성 완료", 
        processedCount: 0, 
        fileName: file.fileName,
        totalChunks: chunks.length,
        remainingChunks: chunks.length
      });
    }

    // 3. 아직 임베딩이 없는 조각들을 최대 2개만 가져와서 처리함 (타임아웃 방지)
    const pendingChunks: any[] = await prisma.$queryRawUnsafe(
      `SELECT id, content FROM "FileChunk" WHERE "fileId" = $1 AND "embedding" IS NULL ORDER BY "createdAt" ASC LIMIT 2`,
      file.id
    );

    if (pendingChunks.length > 0) {
      console.log(`[VECTORIZE] 임베딩 생성 중: ${file.fileName} (${pendingChunks.length}개 조각)`);
      for (const chunk of pendingChunks) {
        const embedding = await generateEmbedding(chunk.content);
        const vectorStr = `[${embedding.join(",")}]`;
        
        await prisma.$executeRawUnsafe(
          `UPDATE "FileChunk" SET "embedding" = $1::vector WHERE "id" = $2`,
          vectorStr,
          chunk.id
        );
      }
    }

    // 4. 남은 조각 확인
    const remainingResult: any[] = await prisma.$queryRawUnsafe(
      `SELECT COUNT(*)::int as count FROM "FileChunk" WHERE "fileId" = $1 AND "embedding" IS NULL`,
      file.id
    );
    const remainingCount = remainingResult[0]?.count || 0;

    if (remainingCount === 0) {
      // 모든 조각 완료 시 상태를 DONE으로 변경
      await prisma.archiveFile.update({
        where: { id: file.id },
        data: { aiStatus: "DONE" }
      });
      
      return NextResponse.json({ 
        message: "파일 벡터화 완료", 
        processedCount: 1, 
        fileName: file.fileName,
        isFinished: true 
      });
    }

    return NextResponse.json({ 
      message: "벡터화 진행 중...", 
      processedCount: 0, 
      fileName: file.fileName,
      remainingChunks: remainingCount,
      totalChunks: existingChunkCount
    });

  } catch (error: any) {
    console.error("[ARCHIVE_VECTORIZE_ERROR]", error);
    return new NextResponse(error.message || "Internal Server Error", { status: 500 });
  }
}
