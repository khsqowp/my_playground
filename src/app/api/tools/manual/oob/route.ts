import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import {
  SECURITY_COLLECTIONS,
  listSecurityRecords,
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

type OobCallback = {
  kind: "oob-callback";
  token: string;
  sessionRecordId: string | null;
  method: string;
  path: string;
  params: Record<string, string>;
  body: unknown;
  ip: string;
  userAgent: string | null;
  createdAt: string;
};

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const sessionId = request.nextUrl.searchParams.get("sessionId");
  const sessions = await listSecurityRecords<ManualSession>(SECURITY_COLLECTIONS.sessions, {
    where: (record) => record.kind === "manual-session" && record.ownerId === session.user.id,
  });
  const ownedSessionIds = new Set(sessions.map((row) => row.id));
  const ownedTokens = new Set(sessions.map((row) => row.data.callbackToken));

  if (sessionId && !ownedSessionIds.has(sessionId)) {
    return NextResponse.json({ error: "session not found" }, { status: 404 });
  }

  const callbacks = await listSecurityRecords<OobCallback>(SECURITY_COLLECTIONS.oob, {
    take: 200,
    where: (record) => {
      if (record.kind !== "oob-callback") return false;
      if (sessionId) return record.sessionRecordId === sessionId;
      return ownedTokens.has(record.token);
    },
  });

  return NextResponse.json({ callbacks });
}
