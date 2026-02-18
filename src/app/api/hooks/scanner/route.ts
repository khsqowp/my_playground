import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

// 외부 서버(대상)가 내 서버로 데이터를 보낼 때 기록하는 공통 핸들러
async function handleCallback(req: NextRequest) {
  const url = new URL(req.url);
  const searchParams = Object.fromEntries(url.searchParams.entries());
  let body = {};
  
  try {
    const contentType = req.headers.get("content-type");
    if (contentType?.includes("application/json")) {
      body = await req.json();
    } else {
      body = { raw: await req.text() };
    }
  } catch (e) {
    body = { error: "Failed to parse body" };
  }

  // ActivityLog에 기록
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

export async function GET(req: NextRequest) { return await handleCallback(req); }
export async function POST(req: NextRequest) { return await handleCallback(req); }
export async function PUT(req: NextRequest) { return await handleCallback(req); }
export async function PATCH(req: NextRequest) { return await handleCallback(req); }
export async function DELETE(req: NextRequest) { return await handleCallback(req); }
export async function HEAD(req: NextRequest) { return await handleCallback(req); }
export async function OPTIONS(req: NextRequest) { return await handleCallback(req); }
