import { NextRequest, NextResponse } from "next/server";
import {
  SECURITY_COLLECTIONS,
  createSecurityRecord,
  listSecurityRecords,
  nowIso,
} from "@/lib/manual-security-store";

type ManualSession = {
  kind: "manual-session";
  ownerId: string;
  title: string;
  target: string;
  scope: string;
  status: "ACTIVE" | "PAUSED" | "CLOSED";
  callbackToken: string;
  createdAt: string;
  updatedAt: string;
};

type RouteContext = {
  params: Promise<{ token: string }>;
};

async function parseBody(request: NextRequest) {
  try {
    const contentType = request.headers.get("content-type") || "";
    if (contentType.includes("application/json")) return await request.json();
    if (contentType.includes("form-urlencoded")) {
      return Object.fromEntries((await request.formData()).entries());
    }
    const raw = await request.text();
    return raw ? { raw } : null;
  } catch {
    return { error: "failed to parse request body" };
  }
}

async function handleCallback(request: NextRequest, context: RouteContext) {
  const { token } = await context.params;
  if (!/^oob_[a-f0-9]{24}$/.test(token)) {
    return NextResponse.json({ error: "invalid callback token" }, { status: 400 });
  }

  const matchingSessions = await listSecurityRecords<ManualSession>(SECURITY_COLLECTIONS.sessions, {
    where: (record) => record.kind === "manual-session" && record.callbackToken === token,
    take: 1,
  });
  const matchedSession = matchingSessions[0] || null;
  const url = new URL(request.url);

  await createSecurityRecord(SECURITY_COLLECTIONS.oob, {
    kind: "oob-callback",
    token,
    sessionRecordId: matchedSession?.id || null,
    method: request.method,
    path: url.pathname,
    params: Object.fromEntries(url.searchParams.entries()),
    body: await parseBody(request),
    ip: request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "unknown",
    userAgent: request.headers.get("user-agent"),
    createdAt: nowIso(),
  });

  return new NextResponse("OK", { status: 200 });
}

export async function GET(request: NextRequest, context: RouteContext) {
  return handleCallback(request, context);
}

export async function POST(request: NextRequest, context: RouteContext) {
  return handleCallback(request, context);
}

export async function PUT(request: NextRequest, context: RouteContext) {
  return handleCallback(request, context);
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  return handleCallback(request, context);
}

export async function DELETE(request: NextRequest, context: RouteContext) {
  return handleCallback(request, context);
}
