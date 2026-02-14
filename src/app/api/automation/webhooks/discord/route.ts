import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { processWithAI } from "@/lib/ai";
import { sendDiscordWebhook } from "@/lib/webhook";
import { logWebhook } from "@/lib/webhook";

export async function POST(request: NextRequest) {
  try {
    const payload = await request.json();
    const content = payload.content || payload.message || "";

    // Find active Discord webhook config
    const webhook = await prisma.webhookConfig.findFirst({
      where: { platform: "DISCORD", enabled: true },
    });

    if (!webhook) {
      return NextResponse.json({ error: "No active Discord webhook" }, { status: 404 });
    }

    await logWebhook(webhook.id, "INBOUND", payload, "SUCCESS");

    // Process with AI if content exists
    if (content) {
      try {
        const aiResponse = await processWithAI(content);
        await sendDiscordWebhook(webhook.url, aiResponse);
        await logWebhook(webhook.id, "OUTBOUND", { response: aiResponse }, "SUCCESS", aiResponse);
        return NextResponse.json({ response: aiResponse });
      } catch {
        await logWebhook(webhook.id, "OUTBOUND", { error: "AI processing failed" }, "FAILED");
      }
    }

    return NextResponse.json({ received: true });
  } catch {
    return NextResponse.json({ error: "Processing failed" }, { status: 500 });
  }
}
