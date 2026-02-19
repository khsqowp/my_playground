import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { isPushPayload } from "@/lib/code-review";

/**
 * GET /api/automation/code-review/logs?configId=xxx
 * 해당 config의 모든 push 웹훅 로그 + 리뷰 여부/내용 반환
 */
export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const configId = request.nextUrl.searchParams.get("configId");
  if (!configId) return NextResponse.json({ error: "configId required" }, { status: 400 });

  const config = await prisma.codeReviewConfig.findFirst({
    where: { id: configId, userId: session.user.id },
  });
  if (!config) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const [allLogs, reviewLogs] = await Promise.all([
    prisma.webhookLog.findMany({
      where: { incomingWebhookId: config.incomingWebhookId },
      orderBy: { createdAt: "desc" },
    }),
    prisma.codeReviewLog.findMany({
      where: { configId },
      select: { webhookLogId: true, commitSha: true, reviewText: true, createdAt: true },
    }),
  ]);

  const pushLogs = allLogs.filter((l) => isPushPayload(l.payload));
  const reviewMap = new Map(reviewLogs.map((r) => [r.webhookLogId, r]));

  const logs = pushLogs.map((log) => {
    const payload = log.payload as any;
    const commit = payload?.head_commit;
    const review = reviewMap.get(log.id);
    return {
      id: log.id,
      createdAt: log.createdAt,
      ref: payload?.ref || "",
      repo: payload?.repository?.full_name || "",
      commitSha: commit?.id || null,
      commitMessage: commit?.message || "",
      author: commit?.author?.name || "",
      added: commit?.added || [],
      modified: commit?.modified || [],
      removed: commit?.removed || [],
      reviewed: !!review,
      reviewText: review?.reviewText || null,
      reviewedAt: review?.createdAt || null,
    };
  });

  return NextResponse.json({ logs, total: logs.length });
}
