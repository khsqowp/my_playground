import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import {
  SECURITY_COLLECTIONS,
  createSecurityRecord,
  listSecurityRecords,
  nowIso,
  updateSecurityRecord,
} from "@/lib/manual-security-store";

type ReconNote = {
  kind: "recon-note";
  ownerId: string;
  title: string;
  target: string;
  assetType: "DOMAIN" | "IP" | "URL" | "API" | "ACCOUNT" | "OTHER";
  observation: string;
  evidence: string;
  risk: "INFO" | "LOW" | "MEDIUM" | "HIGH";
  status: "OPEN" | "REVIEWING" | "CLOSED";
  tags: string[];
  createdAt: string;
  updatedAt: string;
};

function normalizeTags(value: unknown) {
  const input = Array.isArray(value) ? value.join(",") : String(value || "");
  return input
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean)
    .slice(0, 12);
}

function normalizeAssetType(value: unknown): ReconNote["assetType"] {
  if (value === "DOMAIN" || value === "IP" || value === "URL" || value === "API" || value === "ACCOUNT") return value;
  return "OTHER";
}

function normalizeRisk(value: unknown): ReconNote["risk"] {
  if (value === "LOW" || value === "MEDIUM" || value === "HIGH") return value;
  return "INFO";
}

function normalizeStatus(value: unknown): ReconNote["status"] {
  if (value === "REVIEWING" || value === "CLOSED") return value;
  return "OPEN";
}

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const status = request.nextUrl.searchParams.get("status");
  const query = request.nextUrl.searchParams.get("q")?.toLowerCase() || "";

  const notes = await listSecurityRecords<ReconNote>(SECURITY_COLLECTIONS.recon, {
    where: (record) => {
      if (record.kind !== "recon-note" || record.ownerId !== session.user.id) return false;
      if (status && status !== "all" && record.status !== status) return false;
      if (!query) return true;
      return [
        record.title,
        record.target,
        record.assetType,
        record.observation,
        record.evidence,
        record.tags.join(" "),
      ].join(" ").toLowerCase().includes(query);
    },
  });

  return NextResponse.json({ notes });
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null);
  const title = String(body?.title || "").trim();
  const target = String(body?.target || "").trim();
  const observation = String(body?.observation || "").trim();
  const evidence = String(body?.evidence || "").trim();

  if (!title || !target || !observation) {
    return NextResponse.json({ error: "title, target and observation are required" }, { status: 400 });
  }
  if (title.length > 120 || target.length > 500 || observation.length > 5000 || evidence.length > 5000) {
    return NextResponse.json({ error: "input is too long" }, { status: 400 });
  }

  const timestamp = nowIso();
  const note = await createSecurityRecord<ReconNote>(SECURITY_COLLECTIONS.recon, {
    kind: "recon-note",
    ownerId: session.user.id,
    title,
    target,
    assetType: normalizeAssetType(body?.assetType),
    observation,
    evidence,
    risk: normalizeRisk(body?.risk),
    status: normalizeStatus(body?.status),
    tags: normalizeTags(body?.tags),
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  return NextResponse.json({ note }, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null);
  const id = String(body?.id || "");
  if (!id) return NextResponse.json({ error: "id is required" }, { status: 400 });

  const rows = await listSecurityRecords<ReconNote>(SECURITY_COLLECTIONS.recon, {
    where: (record, recordId) => recordId === id && record.kind === "recon-note" && record.ownerId === session.user.id,
    take: 1,
  });
  const current = rows[0];
  if (!current) return NextResponse.json({ error: "recon note not found" }, { status: 404 });

  const nextData: ReconNote = {
    ...current.data,
    title: String(body?.title || current.data.title).trim().slice(0, 120),
    target: String(body?.target || current.data.target).trim().slice(0, 500),
    assetType: normalizeAssetType(body?.assetType || current.data.assetType),
    observation: String(body?.observation || current.data.observation).trim().slice(0, 5000),
    evidence: String(body?.evidence ?? current.data.evidence).slice(0, 5000),
    risk: normalizeRisk(body?.risk || current.data.risk),
    status: normalizeStatus(body?.status || current.data.status),
    tags: normalizeTags(body?.tags ?? current.data.tags),
    updatedAt: nowIso(),
  };

  const updated = await updateSecurityRecord(id, nextData);
  return NextResponse.json({ note: updated });
}
