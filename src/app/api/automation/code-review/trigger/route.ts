import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { performCodeReview, isPushPayload } from "@/lib/code-review";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { configId, webhookLogIds } = await request.json();
  if (!configId) return NextResponse.json({ error: "configId required" }, { status: 400 });

  const config = await prisma.codeReviewConfig.findFirst({
    where: { id: configId, userId: session.user.id },
  });
  if (!config) return NextResponse.json({ error: "Config not found" }, { status: 404 });

  // ── 해당 인입 웹훅의 전체 로그 조회 (오래된 순) ─────────────
  const allLogs = await prisma.webhookLog.findMany({
    where: { incomingWebhookId: config.incomingWebhookId },
    orderBy: { createdAt: "asc" },
  });

  // push 이벤트만 필터
  const pushLogs = allLogs.filter((l) => isPushPayload(l.payload));

  if (pushLogs.length === 0) {
    return NextResponse.json({ error: "수신된 push 이벤트가 없습니다." }, { status: 404 });
  }

  // ── 이미 검토된 webhookLogId 세트 조회 ─────────────────────
  const reviewed = await prisma.codeReviewLog.findMany({
    where: { configId: config.id },
    select: { webhookLogId: true },
  });
  const reviewedIds = new Set(reviewed.map((r: { webhookLogId: string }) => r.webhookLogId));

  // ── 개별 선택이면 해당 로그만, 아니면 미검토 전체 ────────────
  let pending: typeof pushLogs;
  if (Array.isArray(webhookLogIds) && webhookLogIds.length > 0) {
    const selectedSet = new Set(webhookLogIds as string[]);
    pending = pushLogs.filter((l) => selectedSet.has(l.id));
  } else {
    pending = pushLogs.filter((l) => !reviewedIds.has(l.id));
  }

  if (pending.length === 0) {
    return NextResponse.json({ queued: 0, message: "새로운 커밋이 없습니다." });
  }

  // ── 백그라운드에서 순차 처리 (Gemini rate limit 고려) ────────
  ;(async () => {
    for (const log of pending) {
      try {
        await performCodeReview(log.payload as any, config, log.id);
        // Gemini 과부하 방지 딜레이
        await new Promise((r) => setTimeout(r, 1500));
      } catch (e: any) {
        console.error(`[CODE_REVIEW_BATCH] logId=${log.id}`, e.message);
      }
    }
    console.log(`[CODE_REVIEW_BATCH] done: ${pending.length}건 처리 완료`);
  })().catch((e) => console.error("[CODE_REVIEW_BATCH_ERROR]", e));

  return NextResponse.json({
    queued: pending.length,
    total: pushLogs.length,
    alreadyReviewed: reviewedIds.size,
    message: `${pending.length}개 커밋 리뷰를 백그라운드에서 처리합니다.`,
  });
}
