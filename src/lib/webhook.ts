import crypto from "crypto";
import prisma from "@/lib/prisma";

export async function sendDiscordWebhook(
  url: string,
  content: string
): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function sendSlackWebhook(
  url: string,
  text: string
): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export function verifyWebhookSecret(
  payload: string,
  signature: string,
  secret: string
): boolean {
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(payload);
  const expected = hmac.digest("hex");
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

export async function logWebhook(
  webhookId: string,
  direction: string,
  payload: unknown,
  status: string,
  response?: string
): Promise<void> {
  await prisma.webhookLog.create({
    data: {
      webhookId,
      direction,
      payload: payload as object,
      status,
      response,
    },
  });
}
