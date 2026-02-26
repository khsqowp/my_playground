import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { extractTextFromFile, chunkText, generateEmbedding } from "@/lib/vector-utils";
import { callAI } from "@/lib/ai";
import path from "path";
import crypto from "crypto";

/**
 * 아카이브 파일 조각 단위(Chunk-by-Chunk) 벡터화 및 AI 요약 API
 */
export async function GET(req: NextRequest) {
  try {
    const session = await auth();
    if (!session) return new NextResponse("Unauthorized", { status: 401 });

    // 1. 현재 진행 중(PROCESSING)인 파일을 먼저 찾거나, 없으면 대기 중 또는 요약 누락된 파일을 가져옴
    let file = await prisma.archiveFile.findFirst({
      where: { aiStatus: "PROCESSING" },
      orderBy: { updatedAt: "asc" }
    });

    if (!file) {
      file = await prisma.archiveFile.findFirst({
        where: {
          OR: [
            { aiStatus: { in: ["PENDING", "SKIPPED", "FAILED"] } },
            { 
              AND: [
                { aiStatus: "DONE" },
                { OR: [{ aiSummary: null }, { aiSummary: "" }] }
              ]
            }
          ],
          extension: { in: [".pdf", ".md", ".txt", "pdf", "md", "txt"] }
        },
        orderBy: { createdAt: "asc" }
      });
    }

    if (!file) {
      return NextResponse.json({ message: "더 이상 처리할 파일이 없습니다.", processedCount: 0 });
    }

    console.log(`[VECTORIZE] 대상 파일 선정: ${file.fileName} (ID: ${file.id}, Status: ${file.aiStatus})`);
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

    // 3. 아직 임베딩이 없는 조각들을 최대 3개씩 처리함
    const pendingChunks: any[] = await prisma.$queryRawUnsafe(
      `SELECT id, content FROM "FileChunk" WHERE "fileId" = $1 AND "embedding" IS NULL ORDER BY "createdAt" ASC LIMIT 3`,
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
      // 모든 조각 임베딩 완료 시 AI 요약 및 태그 생성
      console.log(`[VECTORIZE] AI 요약 및 태그 생성 시작: ${file.fileName}`);
      
      const allChunks = await prisma.fileChunk.findMany({
        where: { fileId: file.id },
        orderBy: { createdAt: "asc" },
        select: { content: true }
      });
      
      // 요약을 위해 텍스트 일부 결합 (너무 길면 상위 3000자만 사용)
      const combinedText = allChunks.map(c => c.content).join("\n").substring(0, 5000);
      
      try {
        const aiResponse = await callAI(`다음 파일 내용을 분석하여 핵심 요약(3문장 이내)과 관련 태그(5개, 쉼표 구분)를 생성해줘.

파일명: ${file.fileName}
내용:
${combinedText}

형식:
요약: [내용]
태그: [태그1, 태그2, ...]`);

        const summaryMatch = aiResponse.match(/요약:\s*(.*)/);
        const tagsMatch = aiResponse.match(/태그:\s*(.*)/);
        
        const aiSummary = summaryMatch ? summaryMatch[1].trim() : "요약 생성 실패";
        const aiTags = tagsMatch ? tagsMatch[1].trim() : "";

        await prisma.archiveFile.update({
          where: { id: file.id },
          data: { 
            aiStatus: "DONE",
            aiSummary,
            aiTags
          }
        });
        
        return NextResponse.json({ 
          message: "파일 분석 및 요약 완료", 
          processedCount: 1, 
          fileName: file.fileName,
          isFinished: true,
          aiSummary
        });
      } catch (aiErr) {
        console.error("[VECTORIZE_AI_SUMMARY_ERROR]", aiErr);
        // 요약 실패해도 상태는 DONE으로 바꿈 (무한 루프 방지 위해)
        await prisma.archiveFile.update({
          where: { id: file.id },
          data: { aiStatus: "DONE", aiSummary: "요약 생성 중 오류가 발생했습니다." }
        });
      }
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
