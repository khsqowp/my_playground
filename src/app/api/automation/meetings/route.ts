import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  // 프로젝트를 조회하고, 없으면 생성합니다. (Upsert)
  const project = await prisma.project.upsert({
    where: { name: "SK_ROOKIES_FINAL_PJT" },
    update: {},
    create: {
      name: "SK_ROOKIES_FINAL_PJT",
      description: "SK Rookies Final Project tracking"
    },
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

  const project = await prisma.project.upsert({
    where: { name: "SK_ROOKIES_FINAL_PJT" },
    update: {},
    create: {
      name: "SK_ROOKIES_FINAL_PJT",
      description: "SK Rookies Final Project tracking"
    }
  });

  if (type === "SETTINGS") {
    const { secrets } = data;
    
    for (const secret of secrets) {
      if (!secret.name || !secret.value) continue;
      // 마스킹된 값(********)은 저장하지 않음
      if (secret.value === "********") continue;

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
