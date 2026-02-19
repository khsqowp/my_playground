import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import {
  performCodeReview,
  performCodeReviewFromGitHub,
  isPushPayload,
} from "@/lib/code-review";

export async function POST(request: NextRequest) {
  try {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const { configId, commitShas, webhookLogIds } = body as any;
  if (!configId) return NextResponse.json({ error: "configId required" }, { status: 400 });

  const config = await prisma.codeReviewConfig.findFirst({
    where: { id: configId, userId: session.user.id },
  });
  if (!config) return NextResponse.json({ error: "Config not found" }, { status: 404 });

  // ── GitHub API 모드: commitShas 배열로 직접 처리 ─────────────
  if (Array.isArray(commitShas) && commitShas.length > 0) {
    if (!config.githubRepo) {
      return NextResponse.json(
        { error: "GitHub 레포지토리가 설정되지 않았습니다." },
        { status: 400 }
      );
    }

    ;(async () => {
      for (const sha of commitShas as string[]) {
        try {
          await performCodeReviewFromGitHub(config, sha);
          await new Promise((r) => setTimeout(r, 1500));
        } catch (e: any) {
          console.error(`[CODE_REVIEW_GH] sha=${sha}`, e.message);
        }
      }
      console.log(`[CODE_REVIEW_GH] 완료: ${commitShas.length}건`);
    })().catch((e) => console.error("[CODE_REVIEW_GH_ERROR]", e));

    return NextResponse.json({
      queued: commitShas.length,
      message: `${commitShas.length}개 커밋 리뷰를 백그라운드에서 처리합니다.`,
    });
  }

  // ── 웹훅 로그 모드: 기존 방식 ────────────────────────────────
  const allLogs = await prisma.webhookLog.findMany({
    where: { incomingWebhookId: config.incomingWebhookId },
    orderBy: { createdAt: "asc" },
  });
  const pushLogs = allLogs.filter((l) => isPushPayload(l.payload));

  if (pushLogs.length === 0) {
    return NextResponse.json({ queued: 0, message: "수신된 push 이벤트가 없습니다." });
  }

  // 이미 리뷰된 SHA 세트 (중복 방지)
  const reviewed = await prisma.codeReviewLog.findMany({
    where: { configId: config.id },
    select: { commitSha: true },
  });
  const reviewedShas = new Set(reviewed.map((r) => r.commitSha));

  let pending: typeof pushLogs;
  if (Array.isArray(webhookLogIds) && webhookLogIds.length > 0) {
    const selectedSet = new Set(webhookLogIds as string[]);
    pending = pushLogs.filter((l) => selectedSet.has(l.id));
  } else {
    // 미검토 전체: commitSha 기준으로 필터
    pending = pushLogs.filter((l) => {
      const sha = (l.payload as any)?.head_commit?.id;
      return sha ? !reviewedShas.has(sha) : true;
    });
  }

  if (pending.length === 0) {
    return NextResponse.json({ queued: 0, message: "새로운 커밋이 없습니다." });
  }

  ;(async () => {
    for (const log of pending) {
      try {
        await performCodeReview(log.payload as any, config, log.id);
        await new Promise((r) => setTimeout(r, 1500));
      } catch (e: any) {
        console.error(`[CODE_REVIEW_BATCH] logId=${log.id}`, e.message);
      }
    }
    console.log(`[CODE_REVIEW_BATCH] 완료: ${pending.length}건`);
  })().catch((e) => console.error("[CODE_REVIEW_BATCH_ERROR]", e));

  return NextResponse.json({
    queued: pending.length,
    total: pushLogs.length,
    alreadyReviewed: reviewedShas.size,
    message: `${pending.length}개 커밋 리뷰를 백그라운드에서 처리합니다.`,
  });
  } catch (e: any) {
    console.error("[CODE_REVIEW_TRIGGER_ERROR]", e);
    return NextResponse.json({ error: e.message || "서버 오류" }, { status: 500 });
  }
}
