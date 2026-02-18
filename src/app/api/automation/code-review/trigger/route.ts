import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { performCodeReview } from "@/lib/code-review";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { configId } = await request.json();
  if (!configId) return NextResponse.json({ error: "configId required" }, { status: 400 });

  const config = await prisma.codeReviewConfig.findFirst({
    where: { id: configId, userId: session.user.id },
  });
  if (!config) return NextResponse.json({ error: "Config not found" }, { status: 404 });

  // Get the latest webhook log for this incoming webhook
  const latestLog = await prisma.webhookLog.findFirst({
    where: { incomingWebhookId: config.incomingWebhookId },
    orderBy: { createdAt: "desc" },
  });

  if (!latestLog) {
    return NextResponse.json({ error: "수신된 웹훅 로그가 없습니다." }, { status: 404 });
  }

  try {
    await performCodeReview(latestLog.payload as any, config);
    return NextResponse.json({ success: true });
  } catch (error: any) {
    console.error("[CODE_REVIEW_TRIGGER_ERROR]", error);
    return NextResponse.json(
      { error: error.message || "코드 리뷰 실행 중 오류" },
      { status: 500 }
    );
  }
}
