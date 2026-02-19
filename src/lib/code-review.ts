import { callAI } from "@/lib/ai";

export interface CodeReviewConfig {
  id: string;
  discordWebhookUrl: string;
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

/**
 * 단일 커밋에 대한 코드 리뷰 수행.
 * webhookLogId 가 주어진 경우 중복 여부를 확인하고, 완료 후 CodeReviewLog 에 기록.
 */
export async function performCodeReview(
  payload: GitHubPushPayload,
  config: CodeReviewConfig,
  webhookLogId?: string
): Promise<void> {
  const prisma = (await import("@/lib/prisma")).default;

  // ── 중복 체크 ──────────────────────────────────────────────
  if (webhookLogId) {
    const existing = await prisma.codeReviewLog.findUnique({
      where: { configId_webhookLogId: { configId: config.id, webhookLogId } },
    });
    if (existing) {
      console.log(`[CODE_REVIEW] skip (already reviewed): ${webhookLogId}`);
      return;
    }
  }

  const branch = payload.ref?.split("/").pop() || "unknown";
  const commit = payload.head_commit;
  const commitSha = commit?.id || "";
  const message = commit?.message || "No message";
  const author = commit?.author?.name || "Unknown";
  const repo = payload.repository?.full_name || "unknown/repo";

  const added = (commit?.added || []).join(", ") || "없음";
  const modified = (commit?.modified || []).join(", ") || "없음";
  const removed = (commit?.removed || []).join(", ") || "없음";

  const prompt = `다음 GitHub 커밋 정보를 분석해서 간결한 코드 리뷰를 작성해줘.

브랜치: ${branch} | 커밋: ${message} | 작성자: ${author}
저장소: ${repo}
변경 파일 - 추가: ${added} / 수정: ${modified} / 삭제: ${removed}

아래 형식으로 한국어로 작성해줘 (각 섹션 2-3줄 이내):
🎯 역할/기능: 이 커밋이 하는 일
✅ 강점: 잘된 점
⚠️ 개선점: 개선할 수 있는 부분
💡 제안: 추가 제안`;

  const review = await callAI(prompt);

  // ── Discord 전송 ──────────────────────────────────────────
  const shaLabel = commitSha ? ` \`${commitSha.substring(0, 7)}\`` : "";
  const discordMessage =
    `🔍 **코드 리뷰**${shaLabel} — \`${repo}\` (${branch})\n` +
    `> ${message}\n> by ${author}\n\n${review}`;
  await sendDiscordMessage(config.discordWebhookUrl, discordMessage);

  // ── DB 기록 ────────────────────────────────────────────────
  await prisma.codeReviewConfig.update({
    where: { id: config.id },
    data: { lastReviewAt: new Date() },
  });

  if (webhookLogId) {
    await prisma.codeReviewLog.create({
      data: {
        configId: config.id,
        webhookLogId,
        commitSha: commitSha || null,
        reviewText: review,
      },
    });
  }
}

/**
 * push 이벤트인지 판별 (ping·기타 이벤트 제외)
 */
export function isPushPayload(payload: any): boolean {
  return !!(payload?.head_commit || (payload?.ref && Array.isArray(payload?.commits)));
}
