import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { fetchGitHubBranches, fetchGitHubCommits } from "@/lib/code-review";

/**
 * POST /api/automation/code-review/sync
 * 모든 브랜치의 커밋을 가져와 SHA 기준으로 중복 제거 후 리뷰 여부와 함께 반환.
 * DB에 실제 저장은 하지 않음 — 리뷰 시 trigger 호출로 저장.
 */
export async function POST(request: NextRequest) {
  try {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const { configId } = body as any;
  if (!configId) return NextResponse.json({ error: "configId required" }, { status: 400 });

  const config = await prisma.codeReviewConfig.findFirst({
    where: { id: configId, userId: session.user.id },
  });
  if (!config) return NextResponse.json({ error: "Config not found" }, { status: 404 });
  if (!config.githubRepo) {
    return NextResponse.json(
      { error: "GitHub 레포지토리가 설정되지 않았습니다. 설정에서 githubRepo를 입력하세요." },
      { status: 400 }
    );
  }

  // 모든 브랜치 조회 (최대 100개)
  const branches = await fetchGitHubBranches(config.githubRepo);

  // 브랜치별 커밋을 SHA 기준으로 병합 (중복 제거, branches[] 추적)
  const commitMap = new Map<
    string,
    { sha: string; message: string; author: string; date: string; branches: string[] }
  >();

  for (const branch of branches) {
    const branchCommits = await fetchGitHubCommits(config.githubRepo, branch);
    for (const c of branchCommits) {
      const existing = commitMap.get(c.sha);
      if (existing) {
        if (!existing.branches.includes(branch)) existing.branches.push(branch);
      } else {
        commitMap.set(c.sha, { ...c, branches: [branch] });
      }
    }
  }

  // 날짜 내림차순 정렬
  const commits = Array.from(commitMap.values()).sort(
    (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
  );

  // 이미 리뷰된 SHA 목록 조회
  const reviewLogs = await prisma.codeReviewLog.findMany({
    where: { configId },
    select: { commitSha: true, reviewText: true, createdAt: true },
  });
  const reviewMap = new Map(reviewLogs.map((r) => [r.commitSha, r]));

  const result = commits.map((c) => {
    const log = reviewMap.get(c.sha);
    return {
      ...c,
      reviewed: !!(log?.reviewText),
      reviewText: log?.reviewText ?? null,
      reviewedAt: log?.createdAt ?? null,
    };
  });

  return NextResponse.json({
    commits: result,
    branches,
    total: result.length,
    reviewed: result.filter((c) => c.reviewed).length,
    unreviewed: result.filter((c) => !c.reviewed).length,
  });
  } catch (e: any) {
    console.error("[CODE_REVIEW_SYNC_ERROR]", e.message);
    return NextResponse.json({ error: e.message || "동기화 중 오류 발생" }, { status: 500 });
  }
}
