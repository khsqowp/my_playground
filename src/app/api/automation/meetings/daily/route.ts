import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const projectName = searchParams.get("project");
  const dateStr = searchParams.get("date");

  if (!projectName || !dateStr) {
    return NextResponse.json({ error: "Missing parameters" }, { status: 400 });
  }

  const startDate = new Date(`${dateStr}T00:00:00`);
  const endDate = new Date(`${dateStr}T23:59:59`);

  const logs = await prisma.projectActivityLog.findMany({
    where: {
      project: { name: projectName },
      eventTime: {
        gte: startDate,
        lte: endDate
      }
    },
    orderBy: { eventTime: "asc" }
  });

  return NextResponse.json(logs);
}

export async function DELETE(request: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const projectName = searchParams.get("project");
  const dateStr = searchParams.get("date");

  if (!projectName || !dateStr) {
    return NextResponse.json({ error: "Missing parameters" }, { status: 400 });
  }

  const startDate = new Date(`${dateStr}T00:00:00`);
  const endDate = new Date(`${dateStr}T23:59:59`);

  try {
    const deleted = await prisma.projectActivityLog.deleteMany({
      where: {
        project: { name: projectName },
        eventTime: {
          gte: startDate,
          lte: endDate
        }
      }
    });

    return NextResponse.json({ success: true, count: deleted.count });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
