import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

// GET /api/categories - 카테고리 목록 조회
export async function GET() {
    try {
        const categories = await prisma.category.findMany({
            orderBy: { name: "asc" },
            include: {
                _count: {
                    select: { posts: true, notes: true },
                },
            },
        });
        return NextResponse.json({ categories });
    } catch (error) {
        console.error("Error fetching categories:", error);
        return NextResponse.json({ error: "Failed to fetch categories" }, { status: 500 });
    }
}

// POST /api/categories - 새 카테고리 생성
export async function POST(request: NextRequest) {
    try {
        const session = await auth();
        if (!session?.user?.id) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const body = await request.json();
        const { name, color } = body;

        if (!name?.trim()) {
            return NextResponse.json({ error: "카테고리 이름을 입력해주세요" }, { status: 400 });
        }

        const slug = name
            .toLowerCase()
            .trim()
            .replace(/[^\w\s가-힣-]/g, "")
            .replace(/[\s_-]+/g, "-")
            .replace(/^-+|-+$/g, "");

        const existing = await prisma.category.findUnique({ where: { slug } });
        if (existing) {
            return NextResponse.json({ error: "이미 존재하는 카테고리입니다" }, { status: 409 });
        }

        const category = await prisma.category.create({
            data: { name: name.trim(), slug, color: color || null },
        });

        return NextResponse.json(category, { status: 201 });
    } catch (error) {
        console.error("Error creating category:", error);
        return NextResponse.json({ error: "Failed to create category" }, { status: 500 });
    }
}
