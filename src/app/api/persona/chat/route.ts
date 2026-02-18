import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { chatWithPersona } from "@/lib/ai";
import { isServiceRequest } from "@/lib/service-auth";

export async function POST(req: NextRequest) {
  try {
    // Service-key auth (Discord bot) bypasses session auth
    if (!isServiceRequest(req)) {
      const session = await auth();
      if (!session) {
        return new NextResponse("Unauthorized", { status: 401 });
      }
    }

    const { message } = await req.json();
    if (!message) {
      return new NextResponse("Message is required", { status: 400 });
    }

    const response = await chatWithPersona(message);

    return NextResponse.json({ response });
  } catch (error: any) {
    console.error("[PERSONA_CHAT_ERROR]", error);
    return new NextResponse(error.message || "Internal Server Error", { status: 500 });
  }
}
