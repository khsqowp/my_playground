import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { processWithAI } from "@/lib/ai";
import { sendSlackWebhook, logWebhook } from "@/lib/webhook";

export async function POST(request: NextRequest) {
  try {
    const payload = await request.json();

    // Handle Slack URL verification
    if (payload.type === "url_verification") {
      return NextResponse.json({ challenge: payload.challenge });
    }

    const text = payload.event?.text || payload.text || "";

    const webhook = await prisma.webhookConfig.findFirst({
      where: { platform: "SLACK", enabled: true },
    });

    if (!webhook) {
      return NextResponse.json({ error: "No active Slack webhook" }, { status: 404 });
    }

    await logWebhook(webhook.id, "INBOUND", payload, "SUCCESS");

    if (text) {
      try {
        const aiResponse = await processWithAI(text);
        await sendSlackWebhook(webhook.url, aiResponse);
        await logWebhook(webhook.id, "OUTBOUND", { response: aiResponse }, "SUCCESS", aiResponse);
        return NextResponse.json({ response: aiResponse });
      } catch {
        await logWebhook(webhook.id, "OUTBOUND", { error: "AI failed" }, "FAILED");
      }
    }

    return NextResponse.json({ received: true });
  } catch {
    return NextResponse.json({ error: "Processing failed" }, { status: 500 });
  }
}
