import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { createWatch, listWatchlist } from "@/lib/site-archive";

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const watches = await listWatchlist(session.user.id);
  return NextResponse.json({ watches });
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  try {
    const body = await request.json();
    const watch = await createWatch(session.user.id, {
      url: String(body?.url || ""),
      title: String(body?.title || ""),
      folder: body?.folder,
      tags: body?.tags,
      enabled: body?.enabled,
      schedule: body?.schedule,
      captureHour: body?.captureHour,
    });
    return NextResponse.json({ watch }, { status: 201 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || "watch creation failed" }, { status: 400 });
  }
}
