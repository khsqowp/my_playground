import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { exec } from "child_process";
import { promisify } from "util";
import { writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import path from "path";

const execPromise = promisify(exec);
const TOOLKIT_PATH = path.join(process.cwd(), "vendor/ctf-toolkit");

export async function GET() {
  const session = await auth();
  if (!session) return new NextResponse("Unauthorized", { status: 401 });

  const tmpFile = path.join(tmpdir(), `ctf-data-${Date.now()}.py`);

  try {
    const pythonScript = `
import json
import sys
import os
sys.path.append("${TOOLKIT_PATH}")
try:
    from ctf_toolkit.cheatsheets import sqli, xss, cmdi, ssrf, xxe, lfi, ssti
    from ctf_toolkit.guides import list_all_guides, get_guide

    cheats = {
        "sqli": sqli.SQLI_CHEATSHEET,
        "xss": xss.XSS_CHEATSHEET,
        "cmdi": cmdi.CMDI_CHEATSHEET,
        "ssrf": ssrf.SSRF_CHEATSHEET,
        "xxe": xxe.XXE_CHEATSHEET,
        "lfi": lfi.LFI_CHEATSHEET,
        "ssti": ssti.SSTI_CHEATSHEET
    }

    guides = list_all_guides()
    full_guides = {g["attack_type"]: get_guide(g["attack_type"]) for g in guides}

    print(json.dumps({
        "cheatsheets": cheats,
        "guides": full_guides
    }))
except Exception as e:
    import traceback
    print(json.dumps({"error": str(e), "trace": traceback.format_exc()}))
`;

    writeFileSync(tmpFile, pythonScript, "utf-8");

    const { stdout, stderr } = await execPromise(`python3 "${tmpFile}"`);

    if (stderr) {
      console.error("[DATA_FETCH_STDERR]", stderr);
    }

    const result = JSON.parse(stdout);

    if (result.error) {
      console.error("[DATA_FETCH_PY_ERROR]", result.error, result.trace);
      throw new Error(result.error);
    }

    return NextResponse.json(result);
  } catch (error: any) {
    console.error("[DATA_FETCH_ERROR]", error);
    return new NextResponse("Failed to load toolkit data: " + error.message, { status: 500 });
  } finally {
    try { unlinkSync(tmpFile); } catch {}
  }
}
