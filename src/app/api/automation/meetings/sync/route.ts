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
        const githubRepo = getSecret("GITHUB_REPO") || "khsqowp/my_playground";

        // --- 1. GitHub 커밋 수집 (최근 50개로 확대) ---
        sendStatus(20, "GitHub 커밋 내역 수집 중...");
        try {
          const ghRes = await fetch(`https://api.github.com/repos/${githubRepo}/commits?per_page=50`, {
            headers: { "Accept": "application/vnd.github.v3+json" }
          });
          
          if (ghRes.ok) {
            const commits = await ghRes.json();
            let addedCount = 0;
            for (const c of commits) {
              const existing = await prisma.projectActivityLog.findUnique({
                where: { 
                  projectId_platform_externalId: {
                    projectId: project.id, platform: "GITHUB", externalId: c.sha
                  }
                }
              });
              if (!existing) {
                await prisma.projectActivityLog.create({
                  data: {
                    projectId: project.id,
                    platform: "GITHUB",
                    action: "COMMIT",
                    content: `[${githubRepo}] ${c.commit.message} (by ${c.commit.author.name})`,
                    externalId: c.sha,
                    eventTime: new Date(c.commit.author.date),
                    rawPayload: c
                  }
                });
                addedCount++;
              }
            }
            sendStatus(50, `GitHub 완료 (${addedCount}개 추가됨)`);
          }
        } catch (e) { console.error(e); sendStatus(50, "GitHub 오류"); }

        // --- 2. Notion 편집 내역 수집 (Search API 활용) ---
        sendStatus(60, "Notion 최근 변경 사항 탐색 중...");
        if (notionKey) {
          try {
            // Search API: 최근 수정된 순서대로 페이지/데이터베이스 조회
            const ntRes = await fetch(`https://api.notion.com/v1/search`, {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${notionKey}`,
                "Notion-Version": "2022-06-28",
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                sort: { direction: "descending", timestamp: "last_edited_time" },
                page_size: 50
              })
            });

            if (ntRes.ok) {
              const data = await ntRes.json();
              let ntAddedCount = 0;

              for (const item of data.results) {
                const externalId = item.id;
                const lastEdited = new Date(item.last_edited_time);
                
                // 페이지 제목 추출
                let title = "제목 없음";
                if (item.object === "page") {
                   title = item.properties?.title?.title?.[0]?.plain_text || 
                           item.properties?.Name?.title?.[0]?.plain_text || "이름 없는 페이지";
                } else if (item.object === "database") {
                   title = item.title?.[0]?.plain_text || "이름 없는 DB";
                }

                const content = `[Notion] ${item.object} 수정: ${title}`;

                const existing = await prisma.projectActivityLog.findUnique({
                  where: { 
                    projectId_platform_externalId: {
                      projectId: project.id, platform: "NOTION", externalId: externalId
                    }
                  }
                });

                // 기존 기록이 있더라도 마지막 수정 시간이 다르면 업데이트하거나 새로 생성
                // 여기서는 중복 방지를 위해 externalId를 'id_시간' 형태로 조합할 수도 있지만,
                // 일단은 새로운 수정사항만 잡기 위해 externalId에 수정시간을 포함하는 방안 고려
                const timeAwareId = `${externalId}_${lastEdited.getTime()}`;

                const existingWithTime = await prisma.projectActivityLog.findUnique({
                  where: { 
                    projectId_platform_externalId: {
                      projectId: project.id, platform: "NOTION", externalId: timeAwareId
                    }
                  }
                });

                if (!existingWithTime) {
                  await prisma.projectActivityLog.create({
                    data: {
                      projectId: project.id,
                      platform: "NOTION",
                      action: item.object.toUpperCase(),
                      content,
                      externalId: timeAwareId,
                      eventTime: lastEdited,
                      rawPayload: item
                    }
                  });
                  ntAddedCount++;
                }
              }
              sendStatus(90, `Notion 완료 (${ntAddedCount}개 변경 감지)`);
            }
          } catch (e) { console.error(e); sendStatus(90, "Notion 오류"); }
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
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    },
  });
}
