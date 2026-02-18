import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

// 외부 서버(대상)가 내 서버로 데이터를 보낼 때 기록하는 엔드포인트
export async function ALL(req: NextRequest) {
  const url = new URL(req.url);
  const searchParams = Object.fromEntries(url.searchParams.entries());
  const headers = Object.fromEntries(req.headers.entries());
  let body = {};
  
  try {
    body = await req.json();
  } catch (e) {
    body = { raw: await req.text() };
  }

  // ActivityLog 또는 전용 테이블에 기록 (여기서는 ActivityLog 활용)
  await prisma.activityLog.create({
    data: {
      action: "OOB_CALLBACK",
      target: "SCANNER_RELAY",
      userId: "system", // 시스템 공용 기록
      targetId: JSON.stringify({
        method: req.method,
        path: url.pathname,
        params: searchParams,
        body: body,
        ip: req.headers.get("x-forwarded-for") || "unknown"
      })
    }
  });

  return new NextResponse("OK", { status: 200 });
}

export const GET = ALL;
export const POST = ALL;
export const PUT = ALL;
