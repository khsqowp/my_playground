import crypto from "crypto";
import { mkdir, writeFile } from "fs/promises";
import path from "path";
import prisma from "@/lib/prisma";

export const SITE_ARCHIVE_COLLECTIONS = {
  watchlist: "site_archive_watchlist",
  captures: "site_archive_captures",
  logs: "site_archive_logs",
} as const;

const ARCHIVE_ROOT = path.join(process.cwd(), "data", "site-archive");
const MAX_HTML_CHARS = 2_000_000;
const MAX_TEXT_CHARS = 500_000;
const FETCH_TIMEOUT_MS = 20_000;

export type SiteArchiveWatch = {
  kind: "site-archive-watch";
  ownerId: string;
  url: string;
  title: string;
  folder: string;
  tags: string[];
  enabled: boolean;
  schedule: "manual" | "daily";
  captureHour: number;
  lastCapturedAt: string | null;
  lastContentHash: string | null;
  createdAt: string;
  updatedAt: string;
};

export type SiteArchiveCapture = {
  kind: "site-archive-capture";
  ownerId: string;
  watchId: string | null;
  sourceUrl: string;
  title: string;
  folder: string;
  tags: string[];
  statusCode: number;
  contentHash: string;
  changed: boolean;
  capturedAt: string;
  storageDir: string;
  htmlPath: string;
  textPath: string;
  metadataPath: string;
  textPreview: string;
};

export function nowIso() {
  return new Date().toISOString();
}

export function normalizeUrl(input: string) {
  const url = new URL(input.trim());
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("http 또는 https URL만 저장할 수 있습니다.");
  }
  url.hash = "";
  return url.toString();
}

export function parseTags(value: unknown) {
  const raw = Array.isArray(value) ? value.join(",") : String(value || "");
  return raw
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean)
    .slice(0, 12);
}

export function normalizeFolder(value: unknown, fallback = "web/unsorted") {
  const folder = String(value || fallback)
    .split("/")
    .map((part) => part.trim().replace(/[^\w가-힣.-]+/g, "-"))
    .filter(Boolean)
    .join("/")
    .replace(/-+/g, "-")
    .slice(0, 120);
  return folder || fallback;
}

export function classifyPage(url: string, title: string, text: string) {
  const haystack = `${url} ${title} ${text.slice(0, 5000)}`.toLowerCase();
  const rules: { folder: string; tags: string[]; keywords: string[] }[] = [
    { folder: "security/advisory", tags: ["security", "advisory"], keywords: ["cve", "vulnerability", "security advisory", "보안", "취약점"] },
    { folder: "development/docs", tags: ["docs"], keywords: ["documentation", "docs", "api reference", "guide", "manual"] },
    { folder: "development/changelog", tags: ["changelog"], keywords: ["release notes", "changelog", "change log", "릴리즈"] },
    { folder: "news", tags: ["news"], keywords: ["news", "article", "뉴스", "기사"] },
    { folder: "research", tags: ["research"], keywords: ["paper", "research", "study", "논문", "연구"] },
  ];

  const matched = rules.find((rule) => rule.keywords.some((keyword) => haystack.includes(keyword)));
  if (matched) return { folder: matched.folder, tags: matched.tags };

  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    return { folder: `web/${host}`, tags: [host] };
  } catch {
    return { folder: "web/unsorted", tags: [] };
  }
}

async function ensureCollection(name: string, description: string) {
  return prisma.dataCollection.upsert({
    where: { name },
    update: {},
    create: {
      name,
      description,
      schema: { kind: "site-archive", storage: "json" },
    },
  });
}

export async function ensureSiteArchiveCollections() {
  const [watchlist, captures, logs] = await Promise.all([
    ensureCollection(SITE_ARCHIVE_COLLECTIONS.watchlist, "Site archive watchlist"),
    ensureCollection(SITE_ARCHIVE_COLLECTIONS.captures, "Local page captures"),
    ensureCollection(SITE_ARCHIVE_COLLECTIONS.logs, "Site archive job logs"),
  ]);
  return { watchlist, captures, logs };
}

export async function listWatchlist(ownerId: string) {
  const { watchlist } = await ensureSiteArchiveCollections();
  const rows = await prisma.dataRecord.findMany({
    where: { collectionId: watchlist.id },
    orderBy: { createdAt: "desc" },
  });
  return rows
    .map((row) => ({ id: row.id, data: row.data as SiteArchiveWatch, createdAt: row.createdAt, updatedAt: row.updatedAt }))
    .filter((row) => row.data.kind === "site-archive-watch" && row.data.ownerId === ownerId);
}

export async function listCaptures(ownerId: string, watchId?: string | null) {
  const { captures } = await ensureSiteArchiveCollections();
  const rows = await prisma.dataRecord.findMany({
    where: { collectionId: captures.id },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  return rows
    .map((row) => ({ id: row.id, data: row.data as SiteArchiveCapture, createdAt: row.createdAt, updatedAt: row.updatedAt }))
    .filter((row) => {
      if (row.data.kind !== "site-archive-capture" || row.data.ownerId !== ownerId) return false;
      return watchId ? row.data.watchId === watchId : true;
    });
}

export async function createWatch(ownerId: string, input: {
  url: string;
  title?: string;
  folder?: string;
  tags?: unknown;
  enabled?: boolean;
  schedule?: "manual" | "daily";
  captureHour?: number;
}) {
  const { watchlist } = await ensureSiteArchiveCollections();
  const url = normalizeUrl(input.url);
  const timestamp = nowIso();
  const data: SiteArchiveWatch = {
    kind: "site-archive-watch",
    ownerId,
    url,
    title: String(input.title || "").trim().slice(0, 160),
    folder: normalizeFolder(input.folder),
    tags: parseTags(input.tags),
    enabled: input.enabled !== false,
    schedule: input.schedule === "daily" ? "daily" : "manual",
    captureHour: Math.min(23, Math.max(0, Number(input.captureHour ?? 3) || 3)),
    lastCapturedAt: null,
    lastContentHash: null,
    createdAt: timestamp,
    updatedAt: timestamp,
  };

  const record = await prisma.dataRecord.create({
    data: { collectionId: watchlist.id, data: data as any },
  });
  return { id: record.id, data, createdAt: record.createdAt, updatedAt: record.updatedAt };
}

export async function findWatch(ownerId: string, watchId: string) {
  const watch = (await listWatchlist(ownerId)).find((item) => item.id === watchId);
  if (!watch) throw new Error("아카이브 대상이 없습니다.");
  return watch;
}

function extractTitle(html: string) {
  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || "";
  return decodeHtml(title.replace(/\s+/g, " ").trim()).slice(0, 180);
}

function htmlToText(html: string) {
  return decodeHtml(
    html
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
  );
}

function decodeHtml(text: string) {
  return text
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'");
}

function slugPart(value: string) {
  return value
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^\w가-힣.-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80) || "page";
}

async function fetchPage(url: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "88motorcycle-site-archive/1.0",
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
      },
    });
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("text/html") && !contentType.includes("text/plain")) {
      throw new Error(`지원하지 않는 콘텐츠 타입입니다: ${contentType || "unknown"}`);
    }
    const html = (await response.text()).slice(0, MAX_HTML_CHARS);
    return { html, statusCode: response.status };
  } finally {
    clearTimeout(timeout);
  }
}

export async function capturePage(ownerId: string, options: { watchId?: string; url?: string }) {
  const { captures } = await ensureSiteArchiveCollections();
  const watch = options.watchId ? await findWatch(ownerId, options.watchId) : null;
  const sourceUrl = watch?.data.url || normalizeUrl(options.url || "");
  const { html, statusCode } = await fetchPage(sourceUrl);
  const extractedTitle = extractTitle(html);
  const text = htmlToText(html).slice(0, MAX_TEXT_CHARS);
  const contentHash = crypto.createHash("sha256").update(text || html).digest("hex");
  const capturedAt = nowIso();
  const autoClass = classifyPage(sourceUrl, extractedTitle, text);
  const folder = watch?.data.folder && watch.data.folder !== "web/unsorted" ? watch.data.folder : autoClass.folder;
  const tags = Array.from(new Set([...(watch?.data.tags || []), ...autoClass.tags])).slice(0, 16);
  const changed = watch ? watch.data.lastContentHash !== contentHash : true;

  const date = capturedAt.slice(0, 10);
  const dir = path.join(ARCHIVE_ROOT, normalizeFolder(folder), date, slugPart(sourceUrl), contentHash.slice(0, 12));
  await mkdir(dir, { recursive: true });

  const metadata = {
    sourceUrl,
    title: extractedTitle || watch?.data.title || sourceUrl,
    capturedAt,
    statusCode,
    contentHash,
    folder,
    tags,
    changed,
  };

  const htmlPath = path.join(dir, "page.html");
  const textPath = path.join(dir, "text.md");
  const metadataPath = path.join(dir, "metadata.json");
  await Promise.all([
    writeFile(htmlPath, html, "utf-8"),
    writeFile(textPath, `# ${metadata.title}\n\nSource: ${sourceUrl}\nCaptured: ${capturedAt}\n\n${text}\n`, "utf-8"),
    writeFile(metadataPath, JSON.stringify(metadata, null, 2), "utf-8"),
  ]);

  const capture: SiteArchiveCapture = {
    kind: "site-archive-capture",
    ownerId,
    watchId: watch?.id || null,
    sourceUrl,
    title: metadata.title,
    folder,
    tags,
    statusCode,
    contentHash,
    changed,
    capturedAt,
    storageDir: path.relative(process.cwd(), dir),
    htmlPath: path.relative(process.cwd(), htmlPath),
    textPath: path.relative(process.cwd(), textPath),
    metadataPath: path.relative(process.cwd(), metadataPath),
    textPreview: text.slice(0, 800),
  };

  const record = await prisma.dataRecord.create({
    data: { collectionId: captures.id, data: capture as any },
  });

  if (watch) {
    const nextWatch: SiteArchiveWatch = {
      ...watch.data,
      title: watch.data.title || capture.title,
      folder,
      tags,
      lastCapturedAt: capturedAt,
      lastContentHash: contentHash,
      updatedAt: capturedAt,
    };
    await prisma.dataRecord.update({
      where: { id: watch.id },
      data: { data: nextWatch as any },
    });
  }

  return { id: record.id, data: capture, createdAt: record.createdAt, updatedAt: record.updatedAt };
}

export async function runDueCaptures(ownerId: string, hour = new Date().getHours()) {
  const watches = await listWatchlist(ownerId);
  const due = watches.filter((watch) => watch.data.enabled && watch.data.schedule === "daily" && watch.data.captureHour === hour);
  const results = [];
  for (const watch of due) {
    try {
      results.push({ watchId: watch.id, ok: true, capture: await capturePage(ownerId, { watchId: watch.id }) });
    } catch (error: any) {
      results.push({ watchId: watch.id, ok: false, error: error.message || "capture failed" });
    }
  }
  return results;
}
