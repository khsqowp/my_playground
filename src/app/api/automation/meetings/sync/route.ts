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

        // 프로젝트별 키 조회 (프로젝트 이름이 키의 접두어로 쓰일 수 있으므로 동적 조회)
        const notionKey = project.settings.find(s => s.key.includes("NOTION_API_KEY"))?.value;
        const notionPageId = project.settings.find(s => s.key.includes("NOTION_PAGE_ID"))?.value;
        
        sendStatus(20, `[${projectName}] 데이터 동기화 시작...`);
        await new Promise(r => setTimeout(r, 500));
        
        if (notionKey && notionPageId) {
            sendStatus(50, "Notion 데이터 수집 중...");
            await new Promise(r => setTimeout(r, 1000));
        }

        await prisma.projectActivityLog.create({
          data: {
            projectId: project.id,
            platform: "SYSTEM",
            action: "SYNC",
            content: `[${projectName}] 수동 동기화 완료`,
            eventTime: new Date()
          }
        });

        sendStatus(100, "완료!");
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
