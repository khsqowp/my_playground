import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import prisma from "@/lib/prisma";

export async function POST(req: Request) {
  try {
    const { name, email, phone, birthDate, password } = await req.json();

    if (!name || !email || !password) {
      return new NextResponse("필수 정보가 누락되었습니다.", { status: 400 });
    }

    // 이메일 중복 체크
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return new NextResponse("이미 가입된 이메일입니다.", { status: 400 });
    }

    // 비밀번호 암호화 (bcrypt)
    const hashedPassword = await bcrypt.hash(password, 12);

    // 사용자 생성 (기본 상태: PENDING)
    // 기본 권한 설정 (모두 false)
    const defaultPermissions = {
      dashboard: { view: false, use: false },
      blog: { view: false, use: false },
      portfolio: { view: false, use: false },
      archive: { view: false, use: false },
      data: { view: false, use: false },
      automation: { view: false, use: false },
      activity: { view: false, use: false },
      persona: { view: false, use: false },
      tools: { view: false, use: false },
      links: { view: false, use: false },
    };

    const user = await prisma.user.create({
      data: {
        name,
        email,
        phone,
        birthDate,
        password: hashedPassword,
        status: "PENDING",
        role: "USER",
        permissions: defaultPermissions,
      },
    });

    return NextResponse.json({
      message: "가입 신청이 완료되었습니다. 관리자 승인 후 이용 가능합니다.",
      user: { id: user.id, email: user.email },
    });
  } catch (error: any) {
    console.error("[REGISTER_ERROR]", error);
    return new NextResponse("서버 오류가 발생했습니다.", { status: 500 });
  }
}
