import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const projectName = searchParams.get("project") || "SK_ROOKIES_FINAL_PJT";
  
  const { type } = await request.json();

  const project = await prisma.project.findUnique({
    where: { name: projectName },
    include: {
      settings: true,
      activityLogs: {
        orderBy: { eventTime: "asc" },
        take: 100
      }
    }
  });

  if (!project) return NextResponse.json({ error: "Project not found" }, { status: 404 });

  // 해당 프로젝트의 디스코드 웹훅 조회
  const webhookUrl = project.settings.find(s => s.key.includes("DISCORD_WEBHOOK_URL"))?.value;

  if (!webhookUrl) {
    return NextResponse.json({ error: "Discord 웹훅 URL이 설정되지 않았습니다." }, { status: 400 });
  }

  const dateStr = new Date().toISOString().split('T')[0];
  const formData = new FormData();

  if (type === "SUMMARY") {
    let markdown = `# 📊 [${dateStr}] 활동 요약 보고서\n\n`;
    markdown += `## 프로젝트: ${project.name}\n\n`;
    
    const stats = project.activityLogs.reduce((acc: any, curr: any) => {
        acc[curr.platform] = (acc[curr.platform] || 0) + 1;
        return acc;
    }, {});

    markdown += `### 활동 통계\n`;
    Object.entries(stats).forEach(([p, count]) => markdown += `- ${p}: ${count}건\n`);

    markdown += `\n### 주요 활동 내역\n`;
    project.activityLogs.slice(-20).forEach((l: any) => {
      markdown += `- [${l.eventTime.toLocaleTimeString()}] [${l.platform}] ${l.content}\n`;
    });

    const blob = new Blob([markdown], { type: 'text/markdown' });
    formData.append('file', blob, `summary_${project.name}_${dateStr}.md`);
    formData.append('payload_json', JSON.stringify({ content: `✅ [${project.name}] 요약 보고서 도착.` }));
  } else {
    let textLog = `[${project.name} Activity Logs - ${dateStr}]\n\n`;
    project.activityLogs.forEach((l: any) => {
        textLog += `[${l.eventTime.toLocaleString()}] [${l.platform}] [${l.action}] ${l.content}\n`;
    });

    const textBlob = new Blob([textLog], { type: 'text/plain' });
    const jsonBlob = new Blob([JSON.stringify(project.activityLogs, null, 2)], { type: 'application/json' });

    formData.append('file0', textBlob, `logs_${project.name}_${dateStr}.txt`);
    formData.append('file1', jsonBlob, `payloads_${project.name}_${dateStr}.json`);
    formData.append('payload_json', JSON.stringify({ content: `📦 [${project.name}] 원본 데이터 패키지 도착.` }));
  }

  try {
    const res = await fetch(webhookUrl, {
      method: "POST",
      body: formData
    });

    if (res.ok) {
      return NextResponse.json({ success: true });
    } else {
      const errorText = await res.text();
      return NextResponse.json({ error: `Discord 발송 실패: ${errorText}` }, { status: 500 });
    }
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
