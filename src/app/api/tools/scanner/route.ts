import { NextRequest, NextResponse } from "next/server";
import { exec } from "child_process";
import { promisify } from "util";
import { auth } from "@/lib/auth";

import path from "path";

const execPromise = promisify(exec);

// CTF Toolkit이 설치된 경로 (상대 경로로 변경)
const TOOLKIT_PATH = path.join(process.cwd(), "vendor/ctf-toolkit");

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session) return new NextResponse("Unauthorized", { status: 401 });

  try {
    const { target, options, headers, modes } = await req.json();

    // 명령어 생성 (인자 이스케이프 처리)
    const escape = (str: string) => str.replace(/"/g, '\\"');
    
    let command = `python3 -m ctf_toolkit`;
    
    if (options.cookie) command += ` --cookie "${escape(options.cookie)}"`;
    if (options.proxy) command += ` --proxy "${escape(options.proxy)}"`;
    if (options.timeout) command += ` --timeout ${Number(options.timeout)}`;
    if (options.rateLimit) command += ` --rate-limit ${Number(options.rateLimit)}`;
    if (options.threads) command += ` --threads ${Number(options.threads)}`;
    
    headers.forEach((h: any) => {
      command += ` -H "${escape(h.name)}: ${escape(h.value)}"`;
    });

    if (modes.smart) {
      command += ` smart -u "${escape(target.url)}" -p "${escape(target.param)}"`;
    } else {
      const selectedMode = Object.keys(modes).find(m => modes[m as keyof typeof modes] && m !== 'smart');
      if (selectedMode) {
        command += ` ${selectedMode} scan -u "${escape(target.url)}" --param "${escape(target.param)}"`;
        if (target.method === "POST") command += ` -m POST -d "${escape(target.data)}"`;
      } else {
        return new NextResponse("공격 모드를 선택해주세요.", { status: 400 });
      }
    }

    command += ` --output-format json`;

    console.log("[SCANNER] Executing:", command);

    // 실제 실행 (보안상 주의: 실제 운영 환경에서는 인자 이스케이프 및 샌드박싱 필수)
    // 여기서는 제공된 도구의 GUI화를 위해 직접 실행 구조를 잡습니다.
    try {
      const { stdout, stderr } = await execPromise(command, {
        cwd: TOOLKIT_PATH,
        env: { ...process.env, PYTHONPATH: TOOLKIT_PATH }
      });

      if (stderr && !stdout) {
        console.error("[SCANNER] Stderr:", stderr);
        return new NextResponse("스캐너 실행 중 오류가 발생했습니다.", { status: 500 });
      }

      // 결과 파싱 (JSON 출력 가정)
      // 실제 toolkit이 결과를 파일로 저장한다면 해당 파일을 읽어야 함
      // 여기서는 stdout으로 결과가 나온다고 가정하고 처리
      try {
        const result = JSON.parse(stdout);
        return NextResponse.json(result);
      } catch (e) {
        // 결과가 JSON이 아닌 경우 (텍스트 로그 등)
        return NextResponse.json({ 
          raw: stdout,
          vulnerabilities: [] // 파싱 로직 추가 필요
        });
      }

    } catch (execError: any) {
      console.error("[SCANNER] Exec Error:", execError);
      return new NextResponse(execError.message, { status: 500 });
    }

  } catch (error: any) {
    console.error("[SCANNER_API_ERROR]", error);
    return new NextResponse("서버 오류가 발생했습니다.", { status: 500 });
  }
}
