import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { callAI } from "@/lib/ai";

async function sendToDiscord(url: string, content: string): Promise<void> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Discord 전송 실패: ${res.status} ${text}`);
  }
}

async function chunkAndSend(url: string, text: string): Promise<number> {
  const CHUNK_SIZE = 1950;
  const chunks: string[] = [];
  for (let i = 0; i < text.length; i += CHUNK_SIZE) {
    chunks.push(text.slice(i, i + CHUNK_SIZE));
  }
  for (const chunk of chunks) {
    await sendToDiscord(url, chunk);
    await new Promise((r) => setTimeout(r, 500));
  }
  return chunks.length;
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const { type, webhookId, dateFrom, dateTo } = body as {
    type: "raw" | "ai";
    webhookId: string;
    dateFrom: string;
    dateTo: string;
  };

  if (!type || !webhookId || !dateFrom || !dateTo) {
    return NextResponse.json({ error: "type, webhookId, dateFrom, dateTo are required" }, { status: 400 });
  }

  // Validate webhook ownership (SSRF prevention)
  const webhook = await prisma.webhookConfig.findFirst({
    where: { id: webhookId, userId: session.user.id },
  });
  if (!webhook) {
    return NextResponse.json({ error: "Webhook not found" }, { status: 404 });
  }

  const from = new Date(dateFrom);
  from.setHours(0, 0, 0, 0);
  const to = new Date(dateTo);
  to.setHours(23, 59, 59, 999);

  // Fetch logs in date range
  const [webhookLogs, activityLogs] = await Promise.all([
    prisma.webhookLog.findMany({
      where: { createdAt: { gte: from, lte: to } },
      include: {
        webhook: { select: { name: true, platform: true } },
        incomingWebhook: { select: { name: true } },
      },
      orderBy: { createdAt: "asc" },
      take: 200,
    }),
    prisma.projectActivityLog.findMany({
      where: { eventTime: { gte: from, lte: to } },
      include: { project: { select: { name: true } } },
      orderBy: { eventTime: "asc" },
      take: 200,
    }),
  ]);

  const dateStr = `${dateFrom} ~ ${dateTo}`;

  if (type === "raw") {
    let text = `📋 **활동 로그 보고서 (${dateStr})**\n`;
    text += `웹훅 로그: ${webhookLogs.length}건 | 활동 로그: ${activityLogs.length}건\n\n`;

    if (webhookLogs.length > 0) {
      text += "**[웹훅 로그]**\n";
      webhookLogs.forEach((l) => {
        const name = l.webhook?.name || l.incomingWebhook?.name || "시스템";
        text += `• [${new Date(l.createdAt).toLocaleString("ko-KR")}] ${name} - ${l.status}\n`;
      });
      text += "\n";
    }

    if (activityLogs.length > 0) {
      text += "**[프로젝트 활동 로그]**\n";
      activityLogs.forEach((l) => {
        text += `• [${new Date(l.eventTime).toLocaleString("ko-KR")}] [${l.platform}] [${l.action}] ${l.content}\n`;
      });
    }

    const sentMessages = await chunkAndSend(webhook.url, text);
    return NextResponse.json({ success: true, sentMessages });
  }

  // AI report
  let logsText = `날짜 범위: ${dateStr}\n`;
  logsText += `웹훅 로그 ${webhookLogs.length}건, 활동 로그 ${activityLogs.length}건\n\n`;
  activityLogs.forEach((l) => {
    logsText += `[${new Date(l.eventTime).toLocaleString("ko-KR")}] [${l.platform}] [${l.action}] ${l.content}\n`;
  });
  webhookLogs.forEach((l) => {
    const name = l.webhook?.name || l.incomingWebhook?.name || "시스템";
    logsText += `[${new Date(l.createdAt).toLocaleString("ko-KR")}] ${name} - ${l.status}\n`;
  });

  const truncated = logsText.substring(0, 8000);
  const prompt = `다음 개발 활동 로그를 한국어로 간결하게 요약해줘. 주요 사건, 이슈, 성과를 중심으로 3~5문장으로 작성해줘.\n\n${truncated}`;
  const summary = await callAI(prompt);

  const message = `🤖 **AI 활동 보고서 (${dateStr})**\n\n${summary}`;
  await sendToDiscord(webhook.url, message.substring(0, 1950));

  return NextResponse.json({ success: true, sentMessages: 1 });
}
