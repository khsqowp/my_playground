import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET() {
  try {
    const session = await auth();
    if (!session) return new NextResponse("Unauthorized", { status: 401 });

    // 1. 웹훅 로그
    const webhookLogs = await prisma.webhookLog.findMany({
      include: {
        webhook: { select: { name: true, platform: true } },
        incomingWebhook: { select: { name: true } }
      },
      orderBy: { createdAt: "desc" },
      take: 50
    });

    // 2. 프로젝트 활동 로그 (수집된 실제 데이터)
    const projectLogs = await prisma.projectActivityLog.findMany({
      include: { project: { select: { name: true } } },
      orderBy: { eventTime: "desc" },
      take: 50
    });

    const unifiedLogs = [
      ...webhookLogs.map(l => ({
        id: l.id,
        source: l.webhook?.name || l.incomingWebhook?.name || "시스템 웹훅",
        platform: l.webhook?.platform || "EXTERNAL",
        content: `상태: ${l.status}`,
        status: l.status,
        createdAt: l.createdAt,
        type: 'SYSTEM',
        raw: l.payload
      })),
      ...projectLogs.map(l => ({
        id: l.id,
        source: l.project?.name || "미지정 프로젝트",
        platform: l.platform,
        content: l.content,
        status: 'SUCCEEDED',
        createdAt: l.eventTime,
        type: 'COLLECTION',
        raw: l.rawPayload
      }))
    ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    return NextResponse.json(unifiedLogs);
  } catch (error) {
    console.error("[LOGS_API_ERROR]", error);
    return new NextResponse("Internal Error", { status: 500 });
  }
}
