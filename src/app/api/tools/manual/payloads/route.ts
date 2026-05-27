import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import {
  SECURITY_COLLECTIONS,
  createSecurityRecord,
  listSecurityRecords,
  nowIso,
  updateSecurityRecord,
} from "@/lib/manual-security-store";

type PayloadRecord = {
  kind: "payload";
  ownerId: string;
  title: string;
  category: string;
  payload: string;
  context: string;
  expectedSignal: string;
  tags: string[];
  risk: "LOW" | "MEDIUM" | "HIGH";
  createdAt: string;
  updatedAt: string;
};

const CATEGORIES = new Set(["sqli", "xss", "ssrf", "ssti", "lfi", "xxe", "cmdi", "auth", "recon", "other"]);

function normalizeTags(value: unknown) {
  if (Array.isArray(value)) {
    return value.map(String).map((tag) => tag.trim()).filter(Boolean).slice(0, 12);
  }
  return String(value || "")
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean)
    .slice(0, 12);
}

function normalizeRisk(value: unknown): PayloadRecord["risk"] {
  if (value === "LOW" || value === "HIGH") return value;
  return "MEDIUM";
}

function normalizeCategory(value: unknown) {
  const category = String(value || "other").toLowerCase();
  return CATEGORIES.has(category) ? category : "other";
}

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const category = request.nextUrl.searchParams.get("category");
  const query = request.nextUrl.searchParams.get("q")?.toLowerCase() || "";

  const payloads = await listSecurityRecords<PayloadRecord>(SECURITY_COLLECTIONS.payloads, {
    where: (record) => {
      if (record.kind !== "payload" || record.ownerId !== session.user.id) return false;
      if (category && category !== "all" && record.category !== category) return false;
      if (!query) return true;
      return [record.title, record.payload, record.context, record.expectedSignal, record.tags.join(" ")]
        .join(" ")
        .toLowerCase()
        .includes(query);
    },
  });

  return NextResponse.json({ payloads });
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null);
  const title = String(body?.title || "").trim();
  const payload = String(body?.payload || "").trim();
  const context = String(body?.context || "").trim();
  const expectedSignal = String(body?.expectedSignal || "").trim();

  if (!title || !payload) {
    return NextResponse.json({ error: "title and payload are required" }, { status: 400 });
  }
  if (title.length > 120 || payload.length > 5000 || context.length > 3000 || expectedSignal.length > 1000) {
    return NextResponse.json({ error: "input is too long" }, { status: 400 });
  }

  const timestamp = nowIso();
  const record = await createSecurityRecord<PayloadRecord>(SECURITY_COLLECTIONS.payloads, {
    kind: "payload",
    ownerId: session.user.id,
    title,
    category: normalizeCategory(body?.category),
    payload,
    context,
    expectedSignal,
    tags: normalizeTags(body?.tags),
    risk: normalizeRisk(body?.risk),
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  return NextResponse.json({ payload: record }, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null);
  const id = String(body?.id || "");
  if (!id) return NextResponse.json({ error: "id is required" }, { status: 400 });

  const rows = await listSecurityRecords<PayloadRecord>(SECURITY_COLLECTIONS.payloads, {
    where: (record, recordId) => recordId === id && record.kind === "payload" && record.ownerId === session.user.id,
    take: 1,
  });
  const current = rows[0];
  if (!current) return NextResponse.json({ error: "payload not found" }, { status: 404 });

  const nextData: PayloadRecord = {
    ...current.data,
    title: String(body?.title || current.data.title).trim().slice(0, 120),
    category: normalizeCategory(body?.category || current.data.category),
    payload: String(body?.payload || current.data.payload).trim().slice(0, 5000),
    context: String(body?.context ?? current.data.context).slice(0, 3000),
    expectedSignal: String(body?.expectedSignal ?? current.data.expectedSignal).slice(0, 1000),
    tags: normalizeTags(body?.tags ?? current.data.tags),
    risk: normalizeRisk(body?.risk || current.data.risk),
    updatedAt: nowIso(),
  };

  const updated = await updateSecurityRecord(id, nextData);
  return NextResponse.json({ payload: updated });
}
