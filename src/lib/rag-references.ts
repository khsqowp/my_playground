export interface RagContextReference {
  id?: number;
  source?: string | null;
  page?: number | string | null;
  locator?: string | null;
  score?: number;
}

export function stripGeneratedSourceSection(answer: string) {
  const marker = answer.search(/\n\s*(?:#{1,6}\s*)?(?:\*\*)?\s*(출처|참조 자료|로컬 문서 출처|references?)\s*(?:\*\*)?\s*\n/i);
  return marker >= 0 ? answer.slice(0, marker).trim() : answer.trim();
}

export function citedContextIds(answer: string) {
  return new Set(
    Array.from(answer.matchAll(/\[(\d+)\]/g))
      .map((match) => Number(match[1]))
      .filter((id) => Number.isFinite(id) && id > 0)
  );
}

export function pageNumberFromContext(context: RagContextReference) {
  if (typeof context.page === "number" && Number.isFinite(context.page)) return context.page;
  if (typeof context.page === "string") {
    const direct = Number(context.page);
    if (Number.isFinite(direct) && direct > 0) return direct;
  }
  const match = String(context.locator || "").match(/\bpage\s+(\d+)\b/i);
  return match ? Number(match[1]) : null;
}

export function ragReferenceHref(project: string, context: RagContextReference) {
  if (!context.source) return null;
  const params = new URLSearchParams({
    action: "view",
    project,
    path: context.source,
  });
  const page = pageNumberFromContext(context);
  return `/api/rag/files?${params.toString()}${page ? `#page=${page}` : ""}`;
}

export function formatRagReferences(contexts: RagContextReference[], answer: string, project: string) {
  if (!Array.isArray(contexts) || contexts.length === 0) return "";

  const citedIds = citedContextIds(answer);
  const relevantContexts = citedIds.size > 0
    ? contexts.filter((context, index) => citedIds.has(context.id ?? index + 1))
    : contexts.slice(0, 3);
  const seen = new Set<string>();
  const lines = relevantContexts
    .filter((context) => context.source)
    .map((context, index) => {
      const id = context.id ?? index + 1;
      const page = pageNumberFromContext(context);
      const location = context.locator || (page ? `page ${page}` : "");
      const key = `${context.source}|${location}`;
      if (seen.has(key)) return null;
      seen.add(key);
      const label = `[${id}] ${context.source}${location ? `, ${location}` : ""}`;
      const href = ragReferenceHref(project, context);
      return href ? `- [${label}](${href})` : `- ${label}`;
    })
    .filter(Boolean)
    .slice(0, 5);

  return lines.length > 0 ? `\n\n---\n\n**참조 자료**\n${lines.join("\n")}` : "";
}
