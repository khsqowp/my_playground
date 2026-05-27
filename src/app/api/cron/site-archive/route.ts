import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { isServiceRequest } from "@/lib/service-auth";
import { listWatchlist, runDueCaptures } from "@/lib/site-archive";

async function resolveOwnerId(request: NextRequest) {
  const session = await auth();
  if (session?.user?.id) return session.user.id;

  if (isServiceRequest(request)) {
    const owner = await prisma.user.findFirst({ where: { role: "OWNER" }, select: { id: true } });
    return owner?.id || null;
  }

  return null;
}

export async function POST(request: NextRequest) {
  const ownerId = await resolveOwnerId(request);
  if (!ownerId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const hour = typeof body?.hour === "number" ? body.hour : new Date().getHours();
  const results = await runDueCaptures(ownerId, hour);
  return NextResponse.json({ hour, results });
}

export async function GET(request: NextRequest) {
  const ownerId = await resolveOwnerId(request);
  if (!ownerId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const hour = Number(request.nextUrl.searchParams.get("hour") || new Date().getHours());
  const watches = await listWatchlist(ownerId);
  const dueCount = watches.filter((watch) => watch.data.enabled && watch.data.schedule === "daily" && watch.data.captureHour === hour).length;
  return NextResponse.json({ hour, dueCount });
}
