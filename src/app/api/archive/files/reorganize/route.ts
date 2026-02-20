import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { callAI } from "@/lib/ai";
import { normalizeFolder } from "@/lib/archive-utils";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 전체 파일 조회 (최대 200개, 요약 있는 파일 우선)
  const files = await prisma.archiveFile.findMany({
    where: { authorId: session.user.id },
    select: {
      id: true,
      fileName: true,
      extension: true,
      aiSummary: true,
      aiTags: true,
      folder: true,
      aiStatus: true,
    },
    orderBy: [
      { aiStatus: "asc" }, // DONE 먼저
      { createdAt: "desc" },
    ],
    take: 200,
  });

  if (files.length === 0) {
    return NextResponse.json({ updated: 0, message: "파일이 없습니다." });
  }

  // 파일 목록 → 프롬프트용 텍스트 (요약 80자 truncate)
  const fileList = files
    .map((f, i) => {
      const summary = f.aiSummary ? f.aiSummary.substring(0, 80) : "(요약 없음)";
      const tags = f.aiTags ? `[${f.aiTags}]` : "";
      return `${i + 1}. ID:${f.id} | ${f.fileName} | ${summary} ${tags}`;
    })
    .join("\n");

  const prompt = `다음은 파일 아카이브의 전체 파일 목록이야. 이 파일들을 일관성 있는 폴더 구조로 최적 재분류해줘.

파일 목록:
${fileList}

재분류 규칙:
1. 비슷한 주제의 파일은 반드시 같은 폴더로 통합 (예: 웹보안, 웹해킹, 웹취약점 → 보안/웹보안으로 통합)
2. 폴더명은 공백, 언더스코어 없이 붙여쓰기 (예: 웹보안 O, 웹 보안 X)
3. "상위/하위" 2단계 계층 구조 유지
4. 상위 폴더는 7~10개 이내로 최소화
5. 한국어 폴더명 원칙 (단, CTF, AWS, ISMS-P, Python, SQLD, SQL, AI 등 고유명사는 영문 그대로)
6. 공백/언더스코어 차이만 있는 유사 폴더는 하나로 통합

반드시 아래 JSON 배열 형식으로만 응답 (마크다운 코드블록 없이, 순수 JSON):
[{"id":"파일ID","folder":"폴더경로"},...]`;

  try {
    const raw = await callAI(prompt);
    const cleaned = raw.replace(/```json\n?|\n?```/g, "").trim();

    let assignments: Array<{ id: string; folder: string }>;
    try {
      assignments = JSON.parse(cleaned);
    } catch {
      // JSON 배열 추출 시도
      const match = cleaned.match(/\[[\s\S]+\]/);
      if (!match) {
        console.error("[REORGANIZE] JSON parse failed. Raw:", cleaned.substring(0, 500));
        return NextResponse.json({ error: "AI 응답 파싱 실패. 다시 시도해주세요." }, { status: 500 });
      }
      assignments = JSON.parse(match[0]);
    }

    if (!Array.isArray(assignments)) {
      return NextResponse.json({ error: "AI 응답이 올바르지 않습니다." }, { status: 500 });
    }

    // 검증: 실제 파일 ID만 허용
    const validIds = new Set(files.map((f) => f.id));
    const validAssignments = assignments.filter(
      (a) => a.id && typeof a.folder === "string" && validIds.has(a.id)
    );

    // 배치 업데이트
    let updated = 0;
    for (const { id, folder } of validAssignments) {
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
  } catch (e: any) {
    console.error("[REORGANIZE_ERROR]", e);
    return NextResponse.json({ error: e.message || "재구성 중 오류 발생" }, { status: 500 });
  }
}
