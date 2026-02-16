import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const sendStatus = (progress: number, status: string) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ progress, status })}

`));
      };

      try {
        sendStatus(5, "동기화 준비 중...");

        // 1. 프로젝트 찾기 (기본값으로 SK_ROOKIES_FINAL_PJT 사용)
        const project = await prisma.project.findUnique({
          where: { name: "SK_ROOKIES_FINAL_PJT" },
          include: { settings: true }
        });

        if (!project) {
          throw new Error("프로젝트를 찾을 수 없습니다.");
        }

        const notionKey = project.settings.find(s => s.key === "SK_ROOKIES_FINAL_PJT_NOTION_API_KEY")?.value;
        const notionPageId = project.settings.find(s => s.key === "SK_ROOKIES_FINAL_PJT_NOTION_PAGE_ID")?.value;
        
        // 2. Notion 데이터 수집 시뮬레이션 (실제 API 연동 전)
        sendStatus(20, "Notion 페이지 데이터 탐색 중...");
        await new Promise(r => setTimeout(r, 1000));
        
        if (notionKey && notionPageId) {
            // TODO: 실제 Notion API 연동 로직
            sendStatus(40, "Notion 변경 사항 수집 완료");
        } else {
            sendStatus(40, "Notion 설정이 없어 건너뜁니다.");
        }

        // 3. GitHub 데이터 수집 시뮬레이션
        sendStatus(60, "GitHub 커밋 기록 불러오는 중...");
        await new Promise(r => setTimeout(r, 1000));
        
        // TODO: 실제 GitHub API 연동 로직 (Octokit 등 사용)
        sendStatus(80, "활동 로그 저장 중...");
        
        // 임시 활동 로그 생성
        await prisma.projectActivityLog.create({
          data: {
            projectId: project.id,
            platform: "SYSTEM",
            action: "SYNC",
            content: "수동 동기화가 완료되었습니다.",
          }
        });

        sendStatus(100, "동기화 완료!");
        controller.close();
      } catch (error: any) {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ error: error.message })}

`));
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
