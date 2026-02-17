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

        // --- 1. GitHub 모든 브랜치 커밋 수집 ---
        sendStatus(20, "GitHub 모든 브랜치 탐색 중...");
        try {
          const branchesRes = await fetch(`https://api.github.com/repos/${githubRepo}/branches`);
          if (branchesRes.ok) {
            const branches = await branchesRes.ok ? await branchesRes.json() : [];
            let totalAdded = 0;

            for (const branch of branches) {
              const bName = branch.name;
              sendStatus(30, `GitHub [${bName}] 브랜치 수집 중...`);
              const commitsRes = await fetch(`https://api.github.com/repos/${githubRepo}/commits?sha=${bName}&per_page=20`);
              if (commitsRes.ok) {
                const commits = await commitsRes.json();
                for (const c of commits) {
                  const result = await prisma.projectActivityLog.upsert({
                    where: { projectId_platform_externalId: { projectId: project.id, platform: "GITHUB", externalId: c.sha } },
                    update: {},
                    create: {
                      projectId: project.id, platform: "GITHUB", action: "COMMIT",
                      content: `[${bName}] ${c.commit.message} (by ${c.commit.author.name})`,
                      externalId: c.sha, eventTime: new Date(c.commit.author.date), rawPayload: c
                    }
                  });
                  if (result) totalAdded++;
                }
              }
            }
            sendStatus(50, `GitHub 완료 (${totalAdded}건 체크됨)`);
          }
        } catch (e) { sendStatus(50, "GitHub 수집 실패"); }

        // --- 2. Notion 상세 내용 및 DB 레코드 수집 ---
        if (notionKey) {
          sendStatus(60, "Notion 상세 데이터 수집 중...");
          const headers = { "Authorization": `Bearer ${notionKey}`, "Notion-Version": "2022-06-28", "Content-Type": "application/json" };

          // A. 데이터베이스 내부 레코드 수집 (Notion Page ID가 DB인 경우)
          if (notionPageId) {
            try {
              // 먼저 데이터베이스인지 확인
              const dbCheck = await fetch(`https://api.notion.com/v1/databases/${notionPageId}`, { headers });
              if (dbCheck.ok) {
                const dbInfo = await dbCheck.json();
                // 데이터베이스라면 내부 페이지들 쿼리
                const queryRes = await fetch(`https://api.notion.com/v1/databases/${notionPageId}/query`, {
                  method: "POST",
                  headers,
                  body: JSON.stringify({ page_size: 50 })
                });
                if (queryRes.ok) {
                  const data = await queryRes.json();
                  for (const page of data.results) {
                    const timeAwareId = `page_${page.id}_${new Date(page.last_edited_time).getTime()}`;
                    const title = page.properties?.제목?.title?.[0]?.plain_text || 
                                  page.properties?.Name?.title?.[0]?.plain_text || "이름 없는 항목";
                    
                    await prisma.projectActivityLog.upsert({
                      where: { projectId_platform_externalId: { projectId: project.id, platform: "NOTION", externalId: timeAwareId } },
                      update: {},
                      create: {
                        projectId: project.id, platform: "NOTION", action: "DB_RECORD",
                        content: `[Notion DB] ${dbInfo.title?.[0]?.plain_text || "데이터베이스"} - ${title}`,
                        externalId: timeAwareId, eventTime: new Date(page.last_edited_time), rawPayload: page
                      }
                    });
                  }
                }
              } else {
                // 페이지인 경우 하위 블록의 텍스트 수집
                const blocksRes = await fetch(`https://api.notion.com/v1/blocks/${notionPageId}/children`, { headers });
                if (blocksRes.ok) {
                  const blocks = await blocksRes.json();
                  for (const b of blocks.results) {
                    const timeAwareId = `block_${b.id}_${new Date(b.last_edited_time).getTime()}`;
                    const type = b.type;
                    const text = b[type]?.rich_text?.[0]?.plain_text;
                    if (text) {
                      await prisma.projectActivityLog.upsert({
                        where: { projectId_platform_externalId: { projectId: project.id, platform: "NOTION", externalId: timeAwareId } },
                        update: {},
                        create: {
                          projectId: project.id, platform: "NOTION", action: "PAGE_CONTENT",
                          content: `[Notion 내용] ${text.substring(0, 50)}`,
                          externalId: timeAwareId, eventTime: new Date(b.last_edited_time), rawPayload: b
                        }
                      });
                    }
                  }
                }
              }
            } catch (e) { console.error(e); }
          }
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
