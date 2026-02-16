import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const projectName = searchParams.get("project") || "SK_ROOKIES_FINAL_PJT";
  const targetDate = searchParams.get("date"); // YYYY-MM-DD
  
  const { type } = await request.json();

  // 날짜 필터링 조건 설정
  const whereCondition: any = { project: { name: projectName } };
  if (targetDate) {
    whereCondition.eventTime = {
      gte: new Date(`${targetDate}T00:00:00`),
      lte: new Date(`${targetDate}T23:59:59`)
    };
  }

  const project = await prisma.project.findUnique({
    where: { name: projectName },
    include: {
      settings: true,
      activityLogs: {
        where: whereCondition.eventTime ? { eventTime: whereCondition.eventTime } : undefined,
        orderBy: { eventTime: "asc" },
        take: 500
      }
    }
  });

  if (!project) return NextResponse.json({ error: "Project not found" }, { status: 404 });

  const webhookUrl = project.settings.find(s => s.key.includes("DISCORD_WEBHOOK_URL"))?.value;
  if (!webhookUrl) return NextResponse.json({ error: "Discord 웹훅 URL이 없습니다." }, { status: 400 });

  const dateStr = targetDate || new Date().toISOString().split('T')[0];
  const formData = new FormData();

  if (type === "SUMMARY") {
    let markdown = `# 📊 [${dateStr}] ${project.name} 활동 요약\n\n`;
    const stats = project.activityLogs.reduce((acc: any, curr: any) => {
        acc[curr.platform] = (acc[curr.platform] || 0) + 1;
        return acc;
    }, {});

    markdown += `### 활동 통계\n`;
    Object.entries(stats).forEach(([p, count]) => markdown += `- ${p}: ${count}건\n`);
    markdown += `\n### 활동 내역\n`;
    project.activityLogs.forEach((l: any) => {
      markdown += `- [${l.eventTime.toLocaleTimeString()}] [${l.platform}] ${l.content}\n`;
    });

    const blob = new Blob([markdown], { type: 'text/markdown' });
    formData.append('file', blob, `summary_${project.name}_${dateStr}.md`);
    formData.append('payload_json', JSON.stringify({ content: `✅ [${project.name}] ${dateStr} 보고서가 도착했습니다.` }));
  } else {
    let textLog = `[${project.name} Activity Logs - ${dateStr}]\n\n`;
    project.activityLogs.forEach((l: any) => {
        textLog += `[${l.eventTime.toLocaleString()}] [${l.platform}] [${l.action}] ${l.content}\n`;
    });
    const textBlob = new Blob([textLog], { type: 'text/plain' });
    const jsonBlob = new Blob([JSON.stringify(project.activityLogs, null, 2)], { type: 'application/json' });

    formData.append('file0', textBlob, `logs_${project.name}_${dateStr}.txt`);
    formData.append('file1', jsonBlob, `payloads_${project.name}_${dateStr}.json`);
    formData.append('payload_json', JSON.stringify({ content: `📦 [${project.name}] ${dateStr} 원본 데이터 패키지.` }));
  }

  try {
    const res = await fetch(webhookUrl, { method: "POST", body: formData });
    return res.ok ? NextResponse.json({ success: true }) : NextResponse.json({ error: "Discord 발송 실패" }, { status: 500 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
