import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import {
  SECURITY_COLLECTIONS,
  createSecurityRecord,
  listSecurityRecords,
  nowIso,
} from "@/lib/manual-security-store";

type ArchiveRule = {
  kind: "archive-rule";
  ownerId: string;
  name: string;
  folder: string;
  keywords: string[];
  extensions: string[];
  createdAt: string;
  updatedAt: string;
};

function splitList(value: unknown, maxItems = 20) {
  const input = Array.isArray(value) ? value.join(",") : String(value || "");
  return input
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)
    .slice(0, maxItems);
}

function matchRule(file: { fileName: string; extension: string; aiSummary: string | null; aiTags: string | null }, rule: ArchiveRule) {
  const haystack = [file.fileName, file.extension, file.aiSummary || "", file.aiTags || ""].join(" ").toLowerCase();
  const extensionMatched = rule.extensions.length === 0 || rule.extensions.includes(file.extension.toLowerCase());
  const keywordMatched = rule.keywords.length === 0 || rule.keywords.some((keyword) => haystack.includes(keyword));
  return extensionMatched && keywordMatched;
}

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const [rules, files] = await Promise.all([
    listSecurityRecords<ArchiveRule>(SECURITY_COLLECTIONS.archiveRules, {
      where: (record) => record.kind === "archive-rule" && record.ownerId === session.user.id,
    }),
    prisma.archiveFile.findMany({
      where: { authorId: session.user.id },
      orderBy: { updatedAt: "desc" },
      take: 200,
      select: {
        id: true,
        fileName: true,
        extension: true,
        folder: true,
        aiSummary: true,
        aiTags: true,
        fileSize: true,
        updatedAt: true,
      },
    }),
  ]);

  const enrichedFiles = files.map((file) => ({
    ...file,
    suggestedRules: rules
      .filter((rule) => matchRule(file, rule.data))
      .map((rule) => ({ id: rule.id, name: rule.data.name, folder: rule.data.folder })),
  }));

  return NextResponse.json({ rules, files: enrichedFiles });
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null);
  const name = String(body?.name || "").trim();
  const folder = String(body?.folder || "").trim();
  const keywords = splitList(body?.keywords);
  const extensions = splitList(body?.extensions, 10).map((ext) => ext.replace(/^\./, ""));

  if (!name || !folder) {
    return NextResponse.json({ error: "name and folder are required" }, { status: 400 });
  }
  if (name.length > 80 || folder.length > 80) {
    return NextResponse.json({ error: "input is too long" }, { status: 400 });
  }
  if (keywords.length === 0 && extensions.length === 0) {
    return NextResponse.json({ error: "at least one keyword or extension is required" }, { status: 400 });
  }

  const timestamp = nowIso();
  const rule = await createSecurityRecord<ArchiveRule>(SECURITY_COLLECTIONS.archiveRules, {
    kind: "archive-rule",
    ownerId: session.user.id,
    name,
    folder,
    keywords,
    extensions,
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  return NextResponse.json({ rule }, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null);
  const fileId = String(body?.fileId || "");
  const ruleId = String(body?.ruleId || "");
  if (!fileId || !ruleId) {
    return NextResponse.json({ error: "fileId and ruleId are required" }, { status: 400 });
  }

  const rules = await listSecurityRecords<ArchiveRule>(SECURITY_COLLECTIONS.archiveRules, {
    where: (record, id) => id === ruleId && record.kind === "archive-rule" && record.ownerId === session.user.id,
    take: 1,
  });
  const rule = rules[0];
  if (!rule) return NextResponse.json({ error: "rule not found" }, { status: 404 });

  const file = await prisma.archiveFile.findFirst({
    where: { id: fileId, authorId: session.user.id },
  });
  if (!file) return NextResponse.json({ error: "file not found" }, { status: 404 });

  if (!matchRule(file, rule.data)) {
    return NextResponse.json({ error: "rule does not match this file" }, { status: 400 });
  }

  const existingTags = file.aiTags
    ? file.aiTags.split(",").map((tag) => tag.trim()).filter(Boolean)
    : [];
  const nextTags = Array.from(new Set([...existingTags, "security", `rule:${rule.data.name}`])).join(", ");

  const updated = await prisma.archiveFile.update({
    where: { id: file.id },
    data: {
      folder: rule.data.folder,
      aiTags: nextTags,
    },
  });

  return NextResponse.json({ file: updated });
}
