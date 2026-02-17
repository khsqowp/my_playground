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

        // --- 1. GitHub 수집 ---
        sendStatus(20, "GitHub 수집 중...");
        try {
          const branchesRes = await fetch(`https://api.github.com/repos/${githubRepo}/branches`);
          if (branchesRes.ok) {
            const branches = await branchesRes.json();
            for (const branch of branches) {
              const commitsRes = await fetch(`https://api.github.com/repos/${githubRepo}/commits?sha=${branch.name}&per_page=10`);
              if (commitsRes.ok) {
                const commits = await commitsRes.json();
                for (const c of commits) {
                  await prisma.projectActivityLog.upsert({
                    where: { projectId_platform_externalId: { projectId: project.id, platform: "GITHUB", externalId: c.sha } },
                    update: {},
                    create: {
                      projectId: project.id, platform: "GITHUB", action: "COMMIT",
                      content: `[${branch.name}] ${c.commit.message}`,
                      externalId: c.sha, eventTime: new Date(c.commit.author.date), rawPayload: c
                    }
                  });
                }
              }
            }
          }
        } catch (e) { console.error(e); }
        sendStatus(50, "GitHub 완료");

        // --- 2. Notion 수집 (재귀적 탐색 및 인라인 DB 지원) ---
        if (notionKey && notionPageId) {
          sendStatus(60, "Notion 정밀 탐색 중...");
          const headers = { "Authorization": `Bearer ${notionKey}`, "Notion-Version": "2022-06-28", "Content-Type": "application/json" };

          const processNotionItem = async (id: string, isDatabase: boolean) => {
            if (isDatabase) {
              const queryRes = await fetch(`https://api.notion.com/v1/databases/${id}/query`, { method: "POST", headers, body: JSON.stringify({ page_size: 20 }) });
              if (queryRes.ok) {
                const data = await queryRes.json();
                for (const page of data.results) {
                  const timeAwareId = `page_${page.id}_${new Date(page.last_edited_time).getTime()}`;
                  const title = page.properties?.제목?.title?.[0]?.plain_text || page.properties?.Name?.title?.[0]?.plain_text || "이름 없음";
                  await prisma.projectActivityLog.upsert({
                    where: { projectId_platform_externalId: { projectId: project.id, platform: "NOTION", externalId: timeAwareId } },
                    update: {},
                    create: {
                      projectId: project.id, platform: "NOTION", action: "DB_RECORD",
                      content: `[Notion DB 항목] ${title}`,
                      externalId: timeAwareId, eventTime: new Date(page.last_edited_time), rawPayload: page
                    }
                  });
                }
              }
            } else {
              // 페이지인 경우: 블록을 조회하고, 그 안에 데이터베이스가 있는지 확인
              const blocksRes = await fetch(`https://api.notion.com/v1/blocks/${id}/children`, { headers });
              if (blocksRes.ok) {
                const data = await blocksRes.json();
                for (const block of data.results) {
                  if (block.type === 'child_database') {
                    await processNotionItem(block.id, true); // 인라인 DB 발견 시 재귀 호출
                  } else {
                    const text = block[block.type]?.rich_text?.[0]?.plain_text;
                    if (text) {
                      const timeAwareId = `block_${block.id}_${new Date(block.last_edited_time).getTime()}`;
                      await prisma.projectActivityLog.upsert({
                        where: { projectId_platform_externalId: { projectId: project.id, platform: "NOTION", externalId: timeAwareId } },
                        update: {},
                        create: {
                          projectId: project.id, platform: "NOTION", action: "PAGE_CONTENT",
                          content: `[Notion 내용] ${text.substring(0, 50)}`,
                          externalId: timeAwareId, eventTime: new Date(block.last_edited_time), rawPayload: block
                        }
                      });
                    }
                  }
                }
              }
            }
          };

          // 루트 ID부터 시작 (데이터베이스인지 페이지인지 자동 판별 시도)
          const checkRes = await fetch(`https://api.notion.com/v1/databases/${notionPageId}`, { headers });
          await processNotionItem(notionPageId, checkRes.ok);
          
          // Search API로 보조 수집
          const searchRes = await fetch(`https://api.notion.com/v1/search`, { method: "POST", headers, body: JSON.stringify({ sort: { direction: "descending", timestamp: "last_edited_time" }, page_size: 10 }) });
          if (searchRes.ok) {
            const searchData = await searchRes.json();
            for (const item of searchData.results) {
              const timeAwareId = `search_${item.id}_${new Date(item.last_edited_time).getTime()}`;
              await prisma.projectActivityLog.upsert({
                where: { projectId_platform_externalId: { projectId: project.id, platform: "NOTION", externalId: timeAwareId } },
                update: {},
                create: {
                  projectId: project.id, platform: "NOTION", action: "SEARCH_RESULT",
                  content: `[Notion 최근수정] ${item.object === 'page' ? (item.properties?.title?.title?.[0]?.plain_text || "제목없음") : "데이터베이스"}`,
                  externalId: timeAwareId, eventTime: new Date(item.last_edited_time), rawPayload: item
                }
              });
            }
          }
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
