import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session) return new NextResponse("Unauthorized", { status: 401 });

  const { input } = await req.json();
  if (!input) return NextResponse.json({});

  // 툴킷의 Encoder.encode_all 로직 이식
  const result = {
    original: input,
    base64: Buffer.from(input).toString('base64'),
    url: encodeURIComponent(input),
    double_url: encodeURIComponent(encodeURIComponent(input)),
    hex: Buffer.from(input).toString('hex'),
    hex_sql: '0x' + Buffer.from(input).toString('hex'),
    html: input.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"),
  };

  return NextResponse.json(result);
}
