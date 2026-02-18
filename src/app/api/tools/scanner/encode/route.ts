import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session) return new NextResponse("Unauthorized", { status: 401 });

  const { input, mode = "encode" } = await req.json();
  if (!input) return NextResponse.json({});

  const result: Record<string, string> = { original: input };

  if (mode === "encode") {
    result["Base64"] = Buffer.from(input).toString('base64');
    result["URL"] = encodeURIComponent(input);
    result["Double URL"] = encodeURIComponent(encodeURIComponent(input));
    result["Hex"] = Buffer.from(input).toString('hex');
    result["SQL Hex"] = '0x' + Buffer.from(input).toString('hex');
    result["HTML Entity"] = input.split('').map((c: string) => `&#${c.charCodeAt(0)};`).join('');
  } else {
    // Decoding
    try {
      result["Base64 Decode"] = Buffer.from(input, 'base64').toString('utf-8');
    } catch (e) { result["Base64 Decode"] = "Invalid Base64"; }

    try {
      result["URL Decode"] = decodeURIComponent(input);
    } catch (e) { result["URL Decode"] = "Invalid URL encoding"; }

    try {
      result["Hex Decode"] = Buffer.from(input.replace(/^0x/, ''), 'hex').toString('utf-8');
    } catch (e) { result["Hex Decode"] = "Invalid Hex"; }
  }

  return NextResponse.json(result);
}
