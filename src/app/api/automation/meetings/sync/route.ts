import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const projectName = searchParams.get("project") || "SK_ROOKIES_FINAL_PJT";
  
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const sendStatus = (progress: number, status: string) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ progress, status })}\n\n`));
      };

      try {
        sendStatus(5, "동기화 준비 중...");

        const project = await prisma.project.upsert({
          where: { name: projectName },
          update: {},
          create: { name: projectName },
          include: { settings: true }
        });

        const getSecret = (keyPart: string) => project.settings.find(s => s.key.includes(keyPart))?.value;
        const notionKey = getSecret("NOTION_API_KEY");
        const notionPageId = getSecret("NOTION_PAGE_ID");
        const githubRepo = getSecret("GITHUB_REPO") || "khsqowp/my_playground";

        // --- 1. GitHub 수집 (최근 50개) ---
        sendStatus(20, "GitHub 기록 수집 중...");
        try {
          const ghRes = await fetch(`https://api.github.com/repos/${githubRepo}/commits?per_page=50`);
          if (ghRes.ok) {
            const commits = await ghRes.json();
            for (const c of commits) {
              await prisma.projectActivityLog.upsert({
                where: { projectId_platform_externalId: { projectId: project.id, platform: "GITHUB", externalId: c.sha } },
                update: {},
                create: {
                  projectId: project.id, platform: "GITHUB", action: "COMMIT", content: `[${githubRepo}] ${c.commit.message}`,
                  externalId: c.sha, eventTime: new Date(c.commit.author.date), rawPayload: c
                }
              });
            }
            sendStatus(50, "GitHub 완료");
          }
        } catch (e) { sendStatus(50, "GitHub 오류 발생"); }

        // --- 2. Notion 수집 (Search + Direct Page Lookup) ---
        if (notionKey) {
          sendStatus(60, "Notion 데이터 탐색 중...");
          
          // A. 설정된 Page ID를 직접 조회 (가장 확실함)
          if (notionPageId) {
            try {
              const pageRes = await fetch(`https://api.notion.com/v1/blocks/${notionPageId}/children?page_size=100`, {
                headers: { "Authorization": `Bearer ${notionKey}`, "Notion-Version": "2022-06-28" }
              });
              if (pageRes.ok) {
                const data = await pageRes.json();
                for (const block of data.results) {
                  // 수정 시간을 ID에 포함하여 변경될 때마다 새 로그 생성
                  const timeAwareId = `${block.id}_${new Date(block.last_edited_time).getTime()}`;
                  const type = block.type;
                  const text = block[type]?.rich_text?.[0]?.plain_text || "내용 수정됨";
                  
                  await prisma.projectActivityLog.upsert({
                    where: { projectId_platform_externalId: { projectId: project.id, platform: "NOTION", externalId: timeAwareId } },
                    update: {},
                    create: {
                      projectId: project.id, platform: "NOTION", action: "BLOCK_UPDATE",
                      content: `[Notion] ${type}: ${text.substring(0, 50)}`,
                      externalId: timeAwareId, eventTime: new Date(block.last_edited_time), rawPayload: block
                    }
                  });
                }
              }
            } catch (e) { console.error("Notion Direct Lookup Error", e); }
          }

          // B. Search API로 워크스페이스 내 최근 수정 사항 전체 탐색
          try {
            const searchRes = await fetch(`https://api.notion.com/v1/search`, {
              method: "POST",
              headers: { "Authorization": `Bearer ${notionKey}`, "Notion-Version": "2022-06-28", "Content-Type": "application/json" },
              body: JSON.stringify({ sort: { direction: "descending", timestamp: "last_edited_time" }, page_size: 50 })
            });
            if (searchRes.ok) {
              const data = await searchRes.json();
              for (const item of data.results) {
                const timeAwareId = `${item.id}_${new Date(item.last_edited_time).getTime()}`;
                let title = item.object === "page" ? (item.properties?.title?.title?.[0]?.plain_text || item.properties?.Name?.title?.[0]?.plain_text || "제목 없음") : "데이터베이스";
                
                await prisma.projectActivityLog.upsert({
                  where: { projectId_platform_externalId: { projectId: project.id, platform: "NOTION", externalId: timeAwareId } },
                  update: {},
                  create: {
                    projectId: project.id, platform: "NOTION", action: item.object.toUpperCase(),
                    content: `[Notion] ${item.object} 수정: ${title}`,
                    externalId: timeAwareId, eventTime: new Date(item.last_edited_time), rawPayload: item
                  }
                });
              }
            }
          } catch (e) { sendStatus(90, "Notion 탐색 중 오류"); }
          sendStatus(90, "Notion 완료");
        }

        sendStatus(100, "전체 동기화 완료!");
        controller.close();
      } catch (error: any) {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ error: error.message })}\n\n`));
        controller.close();
      }
    },
  });

  return new NextResponse(stream, {
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive" },
  });
}
