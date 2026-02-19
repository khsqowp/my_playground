import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { fetchGitHubCommits } from "@/lib/code-review";

/**
 * POST /api/automation/code-review/sync
 * GitHub API로 레포 전체 커밋 목록을 가져와 리뷰 여부와 함께 반환.
 * DB에 실제 저장은 하지 않음 — 리뷰 시 trigger 호출로 저장.
 */
export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { configId } = await request.json();
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

  // GitHub API로 전체 커밋 목록 조회
  const commits = await fetchGitHubCommits(config.githubRepo);

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
    total: result.length,
    reviewed: result.filter((c) => c.reviewed).length,
    unreviewed: result.filter((c) => !c.reviewed).length,
  });
}
