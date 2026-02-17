import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET() {
  try {
    const session = await auth();
    if (!session) return new NextResponse("Unauthorized", { status: 401 });

    // 웹훅 로그 가져오기
    const logs = await prisma.webhookLog.findMany({
      include: {
        webhook: { select: { name: true, platform: true } },
        incomingWebhook: { select: { name: true } }
      },
      orderBy: { createdAt: "desc" },
      take: 100
    });

    return NextResponse.json(logs);
  } catch (error) {
    return new NextResponse("Internal Server Error", { status: 500 });
  }
}
