import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";

const execPromise = promisify(exec);
const TOOLKIT_PATH = path.join(process.cwd(), "vendor/ctf-toolkit");

export async function GET() {
  const session = await auth();
  if (!session) return new NextResponse("Unauthorized", { status: 401 });

  try {
    // 파이썬을 실행하여 치트시트 데이터를 JSON으로 추출
    const pythonScript = `
import json
import sys
import os
sys.path.append("${TOOLKIT_PATH}")
try:
    from ctf_toolkit.cheatsheets import sqli, xss, cmdi, ssrf, xxe, lfi, ssti
    data = {
        "sqli": sqli.SQLI_CHEATSHEET,
        "xss": xss.XSS_CHEATSHEET,
        "cmdi": cmdi.CMDI_CHEATSHEET,
        "ssrf": ssrf.SSRF_CHEATSHEET,
        "xxe": xxe.XXE_CHEATSHEET,
        "lfi": lfi.LFI_CHEATSHEET,
        "ssti": ssti.SSTI_CHEATSHEET
    }
    print(json.dumps(data))
except Exception as e:
    print(json.dumps({"error": str(e)}))
    `;

    const { stdout } = await execPromise(`python3 -c '${pythonScript}'`);
    const result = JSON.parse(stdout);

    if (result.error) {
      throw new Error(result.error);
    }

    return NextResponse.json({ cheatsheets: result });
  } catch (error: any) {
    console.error("[DATA_FETCH_ERROR]", error);
    return new NextResponse("Failed to load toolkit data: " + error.message, { status: 500 });
  }
}
