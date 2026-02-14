import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export async function POST(
    request: NextRequest,
    { params }: { params: Promise<{ slug: string }> }
) {
    const slug = (await params).slug;

    const webhook = await prisma.incomingWebhook.findUnique({
        where: { slug },
    });

    if (!webhook || !webhook.enabled) {
        return NextResponse.json({ error: "Webhook not found or disabled" }, { status: 404 });
    }

    // Parse payload
    let payload = {};
    try {
        const text = await request.text();
        if (text) {
            try {
                payload = JSON.parse(text);
            } catch {
                payload = { raw: text };
            }
        }
    } catch (e) {
        console.error("Failed to parse webhook payload", e);
    }

    // Create log
    await prisma.webhookLog.create({
        data: {
            incomingWebhookId: webhook.id,
            direction: "INCOMING",
            status: "SUCCEEDED",
            payload: payload as any,
            response: "200 OK",
        },
    });

    return NextResponse.json({ success: true });
}
