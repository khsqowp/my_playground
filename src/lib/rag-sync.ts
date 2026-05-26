import { mkdir, rm, writeFile } from "fs/promises";
import path from "path";

const RAG_DATA_ROOT = process.env.RAG_DATA_ROOT || "/rag-data";
const RAG_SERVICE_URL = process.env.RAG_SERVICE_URL || "";

type BlogPostForRag = {
  title: string;
  slug: string;
  content: string;
  excerpt?: string | null;
  published?: boolean;
  visibility?: string;
  category?: { name?: string | null; slug?: string | null } | null;
  tags?: Array<{ tag?: { name?: string | null } | null }> | null;
  series?: { name?: string | null } | null;
  createdAt?: Date | string;
  updatedAt?: Date | string;
};

type PortfolioForRag = {
  title: string;
  slug: string;
  description?: string | null;
  content?: string | null;
  coverImage?: string | null;
  images?: unknown;
  links?: unknown;
  techStack?: string | null;
  published?: boolean;
  visibility?: string;
  createdAt?: Date | string;
  updatedAt?: Date | string;
};

function safeSegment(value: string) {
  return value.replace(/[^a-zA-Z0-9가-힣._-]/g, "-").replace(/-+/g, "-") || "untitled";
}

function projectDir(project: string) {
  return path.join(RAG_DATA_ROOT, safeSegment(project));
}

function markdownFile(project: string, slug: string) {
  return path.join(projectDir(project), `${safeSegment(slug)}.md`);
}

function formatDate(value?: Date | string) {
  if (!value) return "";
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function frontmatter(data: Record<string, unknown>) {
  const lines = Object.entries(data).map(([key, value]) => {
    if (Array.isArray(value)) return `${key}: ${JSON.stringify(value)}`;
    if (typeof value === "boolean") return `${key}: ${value}`;
    return `${key}: ${JSON.stringify(value ?? "")}`;
  });
  return `---\n${lines.join("\n")}\n---\n\n`;
}

async function requestProjectReindex(project: string) {
  if (!RAG_SERVICE_URL) return;

  try {
    await fetch(`${RAG_SERVICE_URL.replace(/\/$/, "")}/api/reindex`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project, recreate: false }),
    });
  } catch (error) {
    console.error(`[RAG_SYNC_REINDEX_ERROR] ${project}`, error);
  }
}

async function writeRagMarkdown(project: string, slug: string, content: string) {
  await mkdir(projectDir(project), { recursive: true });
  await writeFile(markdownFile(project, slug), content, "utf8");
  await requestProjectReindex(project);
}

export async function syncBlogPostToRag(post: BlogPostForRag) {
  try {
    const tags = post.tags?.map((item) => item.tag?.name).filter(Boolean) || [];
    const document = [
      frontmatter({
        type: "blog",
        title: post.title,
        slug: post.slug,
        published: post.published ?? false,
        visibility: post.visibility ?? "",
        category: post.category?.name ?? "",
        categorySlug: post.category?.slug ?? "",
        tags,
        series: post.series?.name ?? "",
        createdAt: formatDate(post.createdAt),
        updatedAt: formatDate(post.updatedAt),
      }),
      `# ${post.title}\n\n`,
      post.excerpt ? `${post.excerpt}\n\n` : "",
      post.content,
      "\n",
    ].join("");

    await writeRagMarkdown("blog", post.slug, document);
  } catch (error) {
    console.error("[RAG_SYNC_BLOG_ERROR]", error);
  }
}

export async function syncPortfolioToRag(portfolio: PortfolioForRag) {
  try {
    const document = [
      frontmatter({
        type: "portfolio",
        title: portfolio.title,
        slug: portfolio.slug,
        published: portfolio.published ?? false,
        visibility: portfolio.visibility ?? "",
        coverImage: portfolio.coverImage ?? "",
        techStack: portfolio.techStack ?? "",
        images: portfolio.images ?? [],
        links: portfolio.links ?? [],
        createdAt: formatDate(portfolio.createdAt),
        updatedAt: formatDate(portfolio.updatedAt),
      }),
      `# ${portfolio.title}\n\n`,
      portfolio.description ? `${portfolio.description}\n\n` : "",
      portfolio.techStack ? `## Tech Stack\n\n${portfolio.techStack}\n\n` : "",
      portfolio.content || "",
      "\n",
    ].join("");

    await writeRagMarkdown("portfolio", portfolio.slug, document);
  } catch (error) {
    console.error("[RAG_SYNC_PORTFOLIO_ERROR]", error);
  }
}

export async function removeRagDocument(project: "blog" | "portfolio", slug: string) {
  try {
    await rm(markdownFile(project, slug), { force: true });
    await requestProjectReindex(project);
  } catch (error) {
    console.error(`[RAG_SYNC_REMOVE_ERROR] ${project}/${slug}`, error);
  }
}
