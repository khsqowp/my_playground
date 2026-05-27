import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import {
  SECURITY_COLLECTIONS,
  createSecurityRecord,
  createToken,
  listSecurityRecords,
  nowIso,
  updateSecurityRecord,
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

function normalizeStatus(value: unknown): ManualSession["status"] {
  if (value === "PAUSED" || value === "CLOSED") return value;
  return "ACTIVE";
}

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const sessions = await listSecurityRecords<ManualSession>(SECURITY_COLLECTIONS.sessions, {
    where: (record) => record.kind === "manual-session" && record.ownerId === session.user.id,
  });

  return NextResponse.json({ sessions });
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null);
  const title = String(body?.title || "").trim();
  const target = String(body?.target || "").trim();
  const scope = String(body?.scope || "").trim();

  if (!title || !target) {
    return NextResponse.json({ error: "title and target are required" }, { status: 400 });
  }

  if (title.length > 120 || target.length > 500 || scope.length > 3000) {
    return NextResponse.json({ error: "input is too long" }, { status: 400 });
  }

  const timestamp = nowIso();
  const record = await createSecurityRecord<ManualSession>(SECURITY_COLLECTIONS.sessions, {
    kind: "manual-session",
    ownerId: session.user.id,
    title,
    target,
    scope,
    status: normalizeStatus(body?.status),
    callbackToken: createToken("oob"),
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  return NextResponse.json({ session: record }, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null);
  const id = String(body?.id || "");
  if (!id) return NextResponse.json({ error: "id is required" }, { status: 400 });

  const rows = await listSecurityRecords<ManualSession>(SECURITY_COLLECTIONS.sessions, {
    where: (record, recordId) =>
      recordId === id && record.kind === "manual-session" && record.ownerId === session.user.id,
  });

  const current = rows[0];
  if (!current) return NextResponse.json({ error: "session not found" }, { status: 404 });

  const nextData: ManualSession = {
    ...current.data,
    title: String(body?.title || current.data.title).trim().slice(0, 120),
    target: String(body?.target || current.data.target).trim().slice(0, 500),
    scope: String(body?.scope ?? current.data.scope).slice(0, 3000),
    status: normalizeStatus(body?.status || current.data.status),
    updatedAt: nowIso(),
  };

  const updated = await updateSecurityRecord(id, nextData);
  return NextResponse.json({ session: updated });
}
