import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { capturePage } from "@/lib/site-archive";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  try {
    const body = await request.json();
    const capture = await capturePage(session.user.id, {
      watchId: body?.watchId ? String(body.watchId) : undefined,
      url: body?.url ? String(body.url) : undefined,
    });
    return NextResponse.json({ capture }, { status: 201 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || "capture failed" }, { status: 400 });
  }
}
