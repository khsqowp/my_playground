import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const projectName = searchParams.get("project");

  if (!projectName) return NextResponse.json({ error: "Project name is required" }, { status: 400 });

  const project = await prisma.project.findUnique({
    where: { name: projectName },
    include: {
      settings: true,
      activityLogs: {
        select: {
          platform: true,
          eventTime: true
        }
      }
    }
  });

  if (!project) return NextResponse.json({ error: "Project not found" }, { status: 404 });

  // 날짜별 그룹화
  const groups: Record<string, any> = {};
  
  project.activityLogs.forEach(log => {
    const dateStr = log.eventTime.toISOString().split('T')[0];
    if (!groups[dateStr]) {
      groups[dateStr] = {
        date: dateStr,
        dayOfWeek: new Intl.DateTimeFormat('ko-KR', { weekday: 'long' }).format(log.eventTime),
        gitCount: 0,
        notionCount: 0,
        hasStt: false
      };
    }
    if (log.platform === 'GITHUB') groups[dateStr].gitCount++;
    if (log.platform === 'NOTION') groups[dateStr].notionCount++;
  });

  const sortedGroups = Object.values(groups).sort((a: any, b: any) => 
    new Date(b.date).getTime() - new Date(a.date).getTime()
  );

  return NextResponse.json({
    dateGroups: sortedGroups,
    settings: project.settings
  });
}
