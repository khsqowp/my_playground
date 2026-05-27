import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { listCaptures } from "@/lib/site-archive";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const watchId = request.nextUrl.searchParams.get("watchId");
  const captures = await listCaptures(session.user.id, watchId);
  return NextResponse.json({ captures });
}
