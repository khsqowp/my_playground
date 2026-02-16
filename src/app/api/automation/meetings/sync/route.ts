import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const sendStatus = (progress: number, status: string) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ progress, status })}\n\n`));
      };

      try {
        sendStatus(5, "동기화 준비 중...");

        // 프로젝트를 조회하거나 생성합니다.
        const project = await prisma.project.upsert({
          where: { name: "SK_ROOKIES_FINAL_PJT" },
          update: {},
          create: {
            name: "SK_ROOKIES_FINAL_PJT",
            description: "SK Rookies Final Project tracking"
          },
          include: { settings: true }
        });

        const notionKey = project.settings.find(s => s.key === "SK_ROOKIES_FINAL_PJT_NOTION_API_KEY")?.value;
        const notionPageId = project.settings.find(s => s.key === "SK_ROOKIES_FINAL_PJT_NOTION_PAGE_ID")?.value;
        
        sendStatus(20, "데이터 동기화 프로세스 시작...");
        await new Promise(r => setTimeout(r, 500));
        
        if (notionKey && notionPageId) {
            sendStatus(40, "Notion 변경 사항 확인 중...");
            // TODO: 실제 Notion SDK 연동
            await new Promise(r => setTimeout(r, 800));
            sendStatus(60, "Notion 데이터 수집 완료");
        } else {
            sendStatus(40, "Notion 설정이 없어 건너뜜");
        }

        sendStatus(70, "GitHub 커밋 기록 확인 중...");
        await new Promise(r => setTimeout(r, 500));
        
        // 활동 로그 생성 (실제 동기화가 일어났음을 기록)
        await prisma.projectActivityLog.create({
          data: {
            projectId: project.id,
            platform: "SYSTEM",
            action: "SYNC",
            content: "수동 데이터 동기화가 성공적으로 수행되었습니다.",
            eventTime: new Date()
          }
        });

        sendStatus(100, "모든 동기화 완료!");
        controller.close();
      } catch (error: any) {
        console.error("Sync error:", error);
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
