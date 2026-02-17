import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET() {
  try {
    const session = await auth();
    if (!session) return new NextResponse("Unauthorized", { status: 401 });

    // 1. 웹훅 로그 (시스템 수신/발신)
    const webhookLogs = await prisma.webhookLog.findMany({
      include: {
        webhook: { select: { name: true, platform: true } },
        incomingWebhook: { select: { name: true } }
      },
      orderBy: { createdAt: "desc" },
      take: 50
    });

    // 2. 프로젝트 활동 로그 (사용자가 수집한 실제 데이터)
    const projectLogs = await prisma.projectActivityLog.findMany({
      include: { project: { select: { name: true } } },
      orderBy: { eventTime: "desc" },
      take: 50
    });

    // 두 로그 형식을 통일하여 합치기
    const unifiedLogs = [
      ...webhookLogs.map(l => ({
        id: l.id,
        source: l.webhook?.name || l.incomingWebhook?.name || "WEBHOOK",
        platform: l.webhook?.platform || "EXTERNAL",
        content: JSON.stringify(l.payload).substring(0, 100),
        status: l.status,
        createdAt: l.createdAt,
        type: 'WEBHOOK',
        raw: l.payload
      })),
      ...projectLogs.map(l => ({
        id: l.id,
        source: l.project.name,
        platform: l.platform,
        content: l.content,
        status: 'SUCCEEDED',
        createdAt: l.eventTime,
        type: 'ACTIVITY',
        raw: l.rawPayload
      }))
    ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    return NextResponse.json(unifiedLogs);
  } catch (error) {
    return new NextResponse("Internal Server Error", { status: 500 });
  }
}
