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
        sendStatus(20, "GitHub 데이터 수집 중...");
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

        // --- 2. Notion 정밀 수집 ---
        if (notionKey) {
          sendStatus(60, "Notion 깊은 탐색 시작...");
          const headers = { "Authorization": `Bearer ${notionKey}`, "Notion-Version": "2022-06-28", "Content-Type": "application/json" };

          // [함수] 페이지 내부 블록(본문) 수집
          const fetchPageContent = async (pageId: string, pageTitle: string) => {
            const blocksRes = await fetch(`https://api.notion.com/v1/blocks/${pageId}/children?page_size=50`, { headers });
            if (blocksRes.ok) {
              const data = await blocksRes.json();
              for (const block of data.results) {
                const text = block[block.type]?.rich_text?.[0]?.plain_text;
                if (text) {
                  const timeAwareId = `content_${block.id}_${new Date(block.last_edited_time).getTime()}`;
                  await prisma.projectActivityLog.upsert({
                    where: { projectId_platform_externalId: { projectId: project.id, platform: "NOTION", externalId: timeAwareId } },
                    update: {},
                    create: {
                      projectId: project.id, platform: "NOTION", action: "PAGE_CONTENT",
                      content: `[${pageTitle}] 내용: ${text.substring(0, 100)}`,
                      externalId: timeAwareId, eventTime: new Date(block.last_edited_time), rawPayload: block
                    }
                  });
                }
                // 만약 페이지 안에 또 다른 데이터베이스가 있다면? (재귀)
                if (block.type === 'child_database') {
                  await fetchDatabaseRecords(block.id);
                }
              }
            }
          };

          // [함수] 데이터베이스 레코드 수집
          const fetchDatabaseRecords = async (dbId: string) => {
            const queryRes = await fetch(`https://api.notion.com/v1/databases/${dbId}/query`, {
              method: "POST", headers, body: JSON.stringify({ page_size: 30 })
            });
            if (queryRes.ok) {
              const data = await queryRes.json();
              for (const page of data.results) {
                // 1. 동적 제목 찾기 (type이 title인 속성 검색)
                let title = "이름 없는 항목";
                for (const prop of Object.values(page.properties as any)) {
                  if ((prop as any).type === 'title') {
                    title = (prop as any).title?.[0]?.plain_text || title;
                    break;
                  }
                }

                // 2. 주요 속성 요약 (Status, Priority 등)
                const status = (page.properties.Status as any)?.status?.name || (page.properties.상태 as any)?.status?.name || "";
                const priority = (page.properties.Priority as any)?.select?.name || "";
                const summary = `${title}${status ? ` (${status})` : ""}${priority ? ` [${priority}]` : ""}`;

                const timeAwareId = `db_rec_${page.id}_${new Date(page.last_edited_time).getTime()}`;
                await prisma.projectActivityLog.upsert({
                  where: { projectId_platform_externalId: { projectId: project.id, platform: "NOTION", externalId: timeAwareId } },
                  update: {},
                  create: {
                    projectId: project.id, platform: "NOTION", action: "DB_RECORD",
                    content: `[Notion DB] ${summary}`,
                    externalId: timeAwareId, eventTime: new Date(page.last_edited_time), rawPayload: page
                  }
                });

                // 3. 이 레코드(페이지) 내부의 본문도 긁어오기
                await fetchPageContent(page.id, title);
              }
            }
          };

          // --- 실행 순서 ---
          if (notionPageId) {
            // 입력된 ID가 DB인지 페이지인지 판별 후 수집
            const checkRes = await fetch(`https://api.notion.com/v1/databases/${notionPageId}`, { headers });
            if (checkRes.ok) {
              await fetchDatabaseRecords(notionPageId);
            } else {
              // 페이지인 경우 제목을 먼저 가져오고 본문 수집
              const pageInfoRes = await fetch(`https://api.notion.com/v1/pages/${notionPageId}`, { headers });
              let rootTitle = "루트 페이지";
              if (pageInfoRes.ok) {
                const info = await pageInfoRes.json();
                for (const prop of Object.values(info.properties as any)) {
                  if ((prop as any).type === 'title') rootTitle = (prop as any).title?.[0]?.plain_text || rootTitle;
                }
              }
              await fetchPageContent(notionPageId, rootTitle);
            }
          }
          
          sendStatus(90, "Notion 수집 완료");
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
