import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { callAI } from "@/lib/ai";
import { normalizeFolder } from "@/lib/archive-utils";

const BATCH_SIZE = 60; // 프롬프트 크기 제한을 위해 배치 처리

/**
 * 파일 배치를 Gemini에 보내 폴더 재분류 요청
 * taxonomy: 이미 결정된 폴더 목록 (일관성 유지)
 */
async function classifyBatch(
  batch: Array<{ id: string; fileName: string; aiSummary: string | null }>,
  taxonomy: string[]
): Promise<Array<{ id: string; folder: string }>> {
  const fileList = batch
    .map((f, i) => {
      const summary = f.aiSummary ? f.aiSummary.substring(0, 50) : "(요약 없음)";
      return `${i + 1}. ID:${f.id} | ${f.fileName} | ${summary}`;
    })
    .join("\n");

  const taxonomyHint =
    taxonomy.length > 0
      ? `\n사용 가능한 폴더 목록 (이 중에서 선택, 없으면 새로 생성):\n${taxonomy.join(", ")}\n`
      : "";

  const prompt = `다음 파일들을 일관성 있는 폴더 구조로 분류해줘.

파일 목록:
${fileList}
${taxonomyHint}
분류 규칙:
1. 비슷한 주제는 같은 폴더로 통합 (예: 웹보안/웹해킹/웹취약점 → 보안/웹보안)
2. 폴더명은 공백, 언더스코어 없이 붙여쓰기 (웹보안 O, 웹 보안 X)
3. "상위/하위" 2단계 계층 구조
4. 상위 폴더 7~10개 이내
5. 한국어 우선 (단, CTF, AWS, ISMS-P, Python, SQLD, SQL, AI 등 고유명사 영문 유지)

반드시 JSON 배열로만 응답 (마크다운 없이):
[{"id":"파일ID","folder":"폴더경로"},...]`;

  const raw = await callAI(prompt);
  const cleaned = raw.replace(/```json\n?|\n?```/g, "").trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    const match = cleaned.match(/\[[\s\S]+\]/);
    if (!match) throw new Error("JSON 파싱 실패: " + cleaned.substring(0, 200));
    return JSON.parse(match[0]);
  }
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 전체 파일 조회 (최대 150개, DONE 파일 우선)
  const files = await prisma.archiveFile.findMany({
    where: { authorId: session.user.id },
    select: {
      id: true,
      fileName: true,
      aiSummary: true,
      folder: true,
      aiStatus: true,
    },
    orderBy: [
      { aiStatus: "asc" }, // DONE 먼저
      { createdAt: "desc" },
    ],
    take: 150,
  });

  if (files.length === 0) {
    return NextResponse.json({ updated: 0, message: "파일이 없습니다." });
  }

  const validIds = new Set(files.map((f) => f.id));
  const allAssignments: Array<{ id: string; folder: string }> = [];
  let taxonomy: string[] = [];

  // 배치 처리 (BATCH_SIZE개씩 나눠서 Gemini 호출)
  for (let i = 0; i < files.length; i += BATCH_SIZE) {
    const batch = files.slice(i, i + BATCH_SIZE);
    try {
      const batchResult = await classifyBatch(batch, taxonomy);
      if (Array.isArray(batchResult)) {
        const valid = batchResult.filter(
          (a) => a.id && typeof a.folder === "string" && validIds.has(a.id)
        );
        allAssignments.push(...valid);
        // 이 배치에서 나온 폴더들을 taxonomy에 추가 (중복 제거)
        const newFolders = valid.map((a) => normalizeFolder(a.folder)).filter(Boolean);
        taxonomy = [...new Set([...taxonomy, ...newFolders])];
      }
    } catch (e: any) {
      console.error(`[REORGANIZE] 배치 ${i / BATCH_SIZE + 1} 실패:`, e.message);
      // 배치 실패 시 해당 배치 스킵, 나머지 계속
    }

    // 배치 간 딜레이 (rate limit 방지)
    if (i + BATCH_SIZE < files.length) {
      await new Promise((r) => setTimeout(r, 1500));
    }
  }

  if (allAssignments.length === 0) {
    return NextResponse.json({ error: "AI가 폴더를 재분류하지 못했습니다. 잠시 후 다시 시도해주세요." }, { status: 500 });
  }

  // 배치 DB 업데이트
  let updated = 0;
  for (const { id, folder } of allAssignments) {
    const normalized = normalizeFolder(folder);
    if (!normalized) continue;
    try {
      await prisma.archiveFile.updateMany({
        where: { id, authorId: session.user.id },
        data: { folder: normalized },
      });
      updated++;
    } catch (e) {
      console.error(`[REORGANIZE] update failed for id=${id}`, e);
    }
  }

  return NextResponse.json({
    updated,
    total: files.length,
    message: `${updated}개 파일의 폴더를 재구성했습니다.`,
  });
}
