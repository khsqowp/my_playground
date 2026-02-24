import { callAI } from "@/lib/ai";

export interface CodeReviewConfig {
  id: string;
  discordWebhookUrl: string;
  githubRepo?: string | null;
}

interface GitHubPushPayload {
  ref?: string;
  head_commit?: {
    id?: string;
    message?: string;
    author?: { name?: string };
    added?: string[];
    modified?: string[];
    removed?: string[];
  };
  repository?: { full_name?: string };
}

// ── GitHub API 타입 ─────────────────────────────────────────

export interface GitHubCommitSummary {
  sha: string;
  message: string;
  author: string;
  date: string;
  branches?: string[];
}

interface GitHubCommitFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
  patch?: string;
}

// ── Discord 전송 ────────────────────────────────────────────

async function sendDiscordMessage(url: string, content: string): Promise<void> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: content.substring(0, 1900) }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Discord 전송 실패: ${res.status} ${text}`);
  }
}

// ── GitHub API 헬퍼 ─────────────────────────────────────────

function githubHeaders(): Record<string, string> {
  return { Accept: "application/vnd.github.v3+json" };
}

/**
 * GitHub 레포의 브랜치 목록 반환 (최대 100개)
 */
export async function fetchGitHubBranches(repo: string): Promise<string[]> {
  const branches: string[] = [];
  let page = 1;

  while (true) {
    const res = await fetch(
      `https://api.github.com/repos/${repo}/branches?per_page=100&page=${page}`,
      { headers: githubHeaders() }
    );
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(`GitHub API 오류: ${res.status} ${(err as any).message || ""}`);
    }
    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) break;
    branches.push(...data.map((b: any) => b.name as string));
    if (data.length < 100) break;
    page++;
  }

  return branches;
}

/**
 * GitHub 레포의 커밋 목록을 최신순으로 반환 (페이지네이션 자동 처리)
 * branch를 지정하면 해당 브랜치의 커밋만 반환.
 */
export async function fetchGitHubCommits(
  repo: string,
  branch?: string
): Promise<GitHubCommitSummary[]> {
  const commits: GitHubCommitSummary[] = [];
  let page = 1;
  const branchParam = branch ? `&sha=${encodeURIComponent(branch)}` : "";

  while (true) {
    const res = await fetch(
      `https://api.github.com/repos/${repo}/commits?per_page=100&page=${page}${branchParam}`,
      { headers: githubHeaders() }
    );
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(`GitHub API 오류: ${res.status} ${(err as any).message || ""}`);
    }
    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) break;

    for (const c of data) {
      commits.push({
        sha: c.sha,
        message: c.commit?.message || "",
        author: c.commit?.author?.name || "",
        date: c.commit?.author?.date || "",
      });
    }
    if (data.length < 100) break;
    page++;
  }

  return commits;
}

/**
 * 특정 커밋의 상세 정보 + diff(patch) 조회
 */
async function fetchCommitDetail(
  repo: string,
  sha: string
): Promise<{ message: string; author: string; date: string; files: GitHubCommitFile[] }> {
  const res = await fetch(
    `https://api.github.com/repos/${repo}/commits/${sha}`,
    { headers: githubHeaders() }
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`GitHub API 오류: ${res.status} ${(err as any).message || ""}`);
  }
  const data = await res.json();
  return {
    message: data.commit?.message || "",
    author: data.commit?.author?.name || "",
    date: data.commit?.author?.date || "",
    files: (data.files || []) as GitHubCommitFile[],
  };
}

// ── GitHub API 기반 코드 리뷰 ───────────────────────────────

/**
 * GitHub API로 커밋 diff를 조회하고 AI 분석 후 DB에 저장 + Discord 전송
 */
export async function performCodeReviewFromGitHub(
  config: CodeReviewConfig,
  sha: string
): Promise<void> {
  const prisma = (await import("@/lib/prisma")).default;
  const repo = config.githubRepo;
  if (!repo) throw new Error("githubRepo가 설정되지 않았습니다.");

  // 중복 체크 (이미 reviewText 존재하면 skip)
  const existing = await prisma.codeReviewLog.findUnique({
    where: { configId_commitSha: { configId: config.id, commitSha: sha } },
    select: { reviewText: true },
  });
  if (existing?.reviewText) {
    console.log(`[CODE_REVIEW_GH] skip (already reviewed): ${sha}`);
    return;
  }

  // 커밋 상세 + diff 조회
  const { message, author, date, files } = await fetchCommitDetail(repo, sha);

  // diff 텍스트 구성 (파일당 최대 800자, 전체 최대 5000자)
  const diffText = files
    .map((f) => {
      let line = `[${f.status}] ${f.filename} (+${f.additions}/-${f.deletions})`;
      if (f.patch) line += `\n${f.patch.substring(0, 800)}`;
      return line;
    })
    .join("\n\n")
    .substring(0, 5000);

  const prompt = `다음 GitHub 커밋과 실제 코드 변경 내용을 분석하여 상세한 코드 리뷰를 작성해줘.

저장소: ${repo}
커밋 SHA: ${sha.substring(0, 7)}
커밋 메시지: ${message.split("\n")[0]}
작성자: ${author}
날짜: ${date}
변경 파일 수: ${files.length}개

[코드 변경사항 (diff)]
${diffText || "변경사항 없음"}

아래 형식으로 한국어로 작성해줘:
🎯 역할/기능: 이 커밋이 하는 일 (2-3줄)
✅ 강점: 코드에서 잘된 점 (2-3줄)
⚠️ 개선점: 개선할 수 있는 부분 (2-3줄)
💡 제안: 추가 제안사항 (2-3줄)`;

  const review = await callAI(prompt);

  // Discord 전송
  const discordMessage =
    `🔍 **코드 리뷰** \`${sha.substring(0, 7)}\` — \`${repo}\`\n` +
    `> ${message.split("\n")[0]}\n> by ${author}\n\n${review}`;
  await sendDiscordMessage(config.discordWebhookUrl, discordMessage);

  // DB upsert (재분석 시 덮어쓰기 허용)
  await prisma.codeReviewLog.upsert({
    where: { configId_commitSha: { configId: config.id, commitSha: sha } },
    create: {
      configId: config.id,
      commitSha: sha,
      commitMessage: message,
      commitAuthor: author,
      reviewText: review,
    },
    update: { reviewText: review },
  });

  await prisma.codeReviewConfig.update({
    where: { id: config.id },
    data: { lastReviewAt: new Date() },
  });
}

// ── 웹훅 수신 기반 코드 리뷰 (자동 트리거용) ─────────────────

/**
 * 웹훅 payload로부터 코드 리뷰 수행 (자동 트리거).
 * commitSha 기준으로 중복 방지.
 */
export async function performCodeReview(
  payload: GitHubPushPayload,
  config: CodeReviewConfig,
  webhookLogId?: string
): Promise<void> {
  const prisma = (await import("@/lib/prisma")).default;

  const branch = payload.ref?.split("/").pop() || "unknown";
  const commit = payload.head_commit;
  const commitSha = commit?.id || webhookLogId || "";
  const message = commit?.message || "No message";
  const author = commit?.author?.name || "Unknown";
  const repo = payload.repository?.full_name || config.githubRepo || "unknown/repo";

  if (!commitSha) {
    console.warn("[CODE_REVIEW] commitSha 없음, 스킵");
    return;
  }

  // 중복 체크
  const existing = await prisma.codeReviewLog.findUnique({
    where: { configId_commitSha: { configId: config.id, commitSha } },
    select: { reviewText: true },
  });
  if (existing?.reviewText) {
    console.log(`[CODE_REVIEW] skip (already reviewed): ${commitSha}`);
    return;
  }

  // GitHub API로 diff 조회 가능하면 상세 분석, 아니면 파일명 기반 분석
  let prompt: string;
  if (config.githubRepo) {
    try {
      const { files } = await fetchCommitDetail(config.githubRepo, commitSha);
      const diffText = files
        .map((f) => {
          let line = `[${f.status}] ${f.filename} (+${f.additions}/-${f.deletions})`;
          if (f.patch) line += `\n${f.patch.substring(0, 600)}`;
          return line;
        })
        .join("\n\n")
        .substring(0, 4000);

      prompt = `다음 GitHub 커밋과 실제 코드 변경 내용을 분석하여 코드 리뷰를 작성해줘.

저장소: ${repo} | 브랜치: ${branch}
커밋: ${message.split("\n")[0]} | 작성자: ${author}

[코드 변경사항]
${diffText || "없음"}

형식 (한국어, 각 2-3줄):
🎯 역할/기능:
✅ 강점:
⚠️ 개선점:
💡 제안:`;
    } catch {
      // diff 조회 실패 시 파일명 기반 fallback
      prompt = buildSimplePrompt(branch, message, author, repo, commit);
    }
  } else {
    prompt = buildSimplePrompt(branch, message, author, repo, commit);
  }

  const review = await callAI(prompt);

  // Discord 전송
  const shaLabel = commitSha ? ` \`${commitSha.substring(0, 7)}\`` : "";
  const discordMessage =
    `🔍 **코드 리뷰**${shaLabel} — \`${repo}\` (${branch})\n` +
    `> ${message.split("\n")[0]}\n> by ${author}\n\n${review}`;
  await sendDiscordMessage(config.discordWebhookUrl, discordMessage);

  // DB upsert
  await prisma.codeReviewLog.upsert({
    where: { configId_commitSha: { configId: config.id, commitSha } },
    create: {
      configId: config.id,
      webhookLogId: webhookLogId || null,
      commitSha,
      commitMessage: message,
      commitAuthor: author,
      reviewText: review,
    },
    update: { reviewText: review },
  });

  await prisma.codeReviewConfig.update({
    where: { id: config.id },
    data: { lastReviewAt: new Date() },
  });
}

function buildSimplePrompt(
  branch: string,
  message: string,
  author: string,
  repo: string,
  commit: GitHubPushPayload["head_commit"]
): string {
  const added = (commit?.added || []).join(", ") || "없음";
  const modified = (commit?.modified || []).join(", ") || "없음";
  const removed = (commit?.removed || []).join(", ") || "없음";
  return `다음 GitHub 커밋 정보를 분석해서 코드 리뷰를 작성해줘.

브랜치: ${branch} | 커밋: ${message} | 작성자: ${author}
저장소: ${repo}
변경 파일 - 추가: ${added} / 수정: ${modified} / 삭제: ${removed}

형식 (한국어, 각 2-3줄):
🎯 역할/기능:
✅ 강점:
⚠️ 개선점:
💡 제안:`;
}

/**
 * push 이벤트인지 판별 (ping·기타 이벤트 제외)
 */
export function isPushPayload(payload: any): boolean {
  return !!(payload?.head_commit || (payload?.ref && Array.isArray(payload?.commits)));
}
