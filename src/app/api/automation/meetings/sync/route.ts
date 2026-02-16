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

        // --- 1. GitHub 커밋 수집 ---
        sendStatus(20, "GitHub 커밋 내역 수집 중...");
        try {
          const ghRes = await fetch(`https://api.github.com/repos/${githubRepo}/commits?per_page=30`, {
            headers: { "Accept": "application/vnd.github.v3+json" }
          });
          
          if (ghRes.ok) {
            const commits = await ghRes.json();
            let addedCount = 0;
            
            for (const c of commits) {
              const externalId = c.sha;
              const content = `[${githubRepo}] ${c.commit.message} (by ${c.commit.author.name})`;
              
              const existing = await prisma.projectActivityLog.findUnique({
                where: { 
                  projectId_platform_externalId: {
                    projectId: project.id,
                    platform: "GITHUB",
                    externalId: externalId
                  }
                }
              });

              if (!existing) {
                await prisma.projectActivityLog.create({
                  data: {
                    projectId: project.id,
                    platform: "GITHUB",
                    action: "COMMIT",
                    content,
                    externalId,
                    eventTime: new Date(c.commit.author.date),
                    rawPayload: c
                  }
                });
                addedCount++;
              }
            }
            sendStatus(50, `GitHub 동기화 완료 (${addedCount}개 추가됨)`);
          } else {
            sendStatus(50, "GitHub 접근 실패 (공개 저장소인지 확인하세요)");
          }
        } catch (e) {
          console.error("GitHub Sync Error", e);
          sendStatus(50, "GitHub 동기화 중 오류 발생");
        }

        // --- 2. Notion 편집 내역 수집 ---
        sendStatus(60, "Notion 편집 내역 수집 중...");
        if (notionKey && notionPageId) {
          try {
            // Notion API 호출 (페이지 블록 조회)
            const ntRes = await fetch(`https://api.notion.com/v1/blocks/${notionPageId}/children?page_size=100`, {
              headers: {
                "Authorization": `Bearer ${notionKey}`,
                "Notion-Version": "2022-06-28"
              }
            });

            if (ntRes.ok) {
              const data = await ntRes.json();
              let ntAddedCount = 0;

              for (const block of data.results) {
                const externalId = block.id;
                const lastEdited = new Date(block.last_edited_time);
                
                // 블록 타입에 따른 간단한 요약
                const type = block.type;
                const text = block[type]?.rich_text?.[0]?.plain_text || "내용 없음";
                const content = `[Notion] ${type} 수정: ${text.substring(0, 30)}...`;

                const existing = await prisma.projectActivityLog.findUnique({
                  where: { 
                    projectId_platform_externalId: {
                      projectId: project.id,
                      platform: "NOTION",
                      externalId: externalId
                    }
                  }
                });

                if (!existing) {
                  await prisma.projectActivityLog.create({
                    data: {
                      projectId: project.id,
                      platform: "NOTION",
                      action: "PAGE_UPDATE",
                      content,
                      externalId,
                      eventTime: lastEdited,
                      rawPayload: block
                    }
                  });
                  ntAddedCount++;
                }
              }
              sendStatus(90, `Notion 동기화 완료 (${ntAddedCount}개 항목 업데이트)`);
            } else {
              sendStatus(90, "Notion API 응답 오류 (키와 페이지ID를 확인하세요)");
            }
          } catch (e) {
            console.error("Notion Sync Error", e);
            sendStatus(90, "Notion 동기화 중 오류 발생");
          }
        } else {
          sendStatus(90, "Notion 설정이 없어 건너뜁니다.");
        }

        sendStatus(100, "전체 데이터 동기화 완료!");
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
