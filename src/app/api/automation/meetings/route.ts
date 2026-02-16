import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const month = searchParams.get("month"); // YYYY-MM

  const project = await prisma.project.findUnique({
    where: { name: "SK_ROOKIES_FINAL_PJT" },
    include: {
      activityLogs: {
        orderBy: { eventTime: "desc" },
        take: 50,
      },
      settings: true,
      sessions: {
        orderBy: { date: "desc" }
      }
    }
  });

  return NextResponse.json(project);
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { type, data } = await request.json();

  const project = await prisma.project.findUnique({
    where: { name: "SK_ROOKIES_FINAL_PJT" }
  });

  if (!project) return NextResponse.json({ error: "Project not found" }, { status: 404 });

  if (type === "SETTINGS") {
    const { secrets } = data;
    
    // Upsert each secret
    for (const secret of secrets) {
      if (!secret.name || !secret.value) continue;
      await prisma.projectSetting.upsert({
        where: {
          projectId_key: {
            projectId: project.id,
            key: secret.name
          }
        },
        update: { value: secret.value },
        create: {
          projectId: project.id,
          key: secret.name,
          value: secret.value,
          isSecret: true
        }
      });
    }
    return NextResponse.json({ success: true });
  }

  return NextResponse.json({ error: "Invalid type" }, { status: 400 });
}
