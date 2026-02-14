import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

// GET /api/portfolio - List my portfolios (authenticated)
export async function GET(request: NextRequest) {
    try {
        const session = await auth();

        if (!session?.user?.id) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const portfolios = await prisma.portfolio.findMany({
            where: {
                authorId: session.user.id,
            },
            orderBy: {
                createdAt: "desc",
            },
        });

        return NextResponse.json({ portfolios });
    } catch (error) {
        console.error("Error fetching portfolios:", error);
        return NextResponse.json({ error: "Failed to fetch portfolios" }, { status: 500 });
    }
}

// POST /api/portfolio - Create new portfolio
export async function POST(request: NextRequest) {
    try {
        const session = await auth();

        if (!session?.user?.id) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const body = await request.json();

        if (!body.title) {
            return NextResponse.json({ error: "Title is required" }, { status: 400 });
        }

        // Generate slug
        let slug = body.title
            .toLowerCase()
            .trim()
            .replace(/[^\w\s가-힣-]/g, "")
            .replace(/[\s_-]+/g, "-");

        // Ensure unique slug
        let counter = 1;
        let uniqueSlug = slug;
        while (true) {
            const existing = await prisma.portfolio.findUnique({
                where: { slug: uniqueSlug },
            });
            if (!existing) break;
            uniqueSlug = `${slug}-${counter}`;
            counter++;
        }

        const portfolio = await prisma.portfolio.create({
            data: {
                title: body.title,
                slug: uniqueSlug,
                description: body.description,
                content: body.content,
                coverImage: body.coverImage,
                images: body.images || [], // Json
                links: body.links || [],   // Json
                techStack: body.techStack,
                published: body.published || false,
                visibility: body.visibility || "PRIVATE",
                authorId: session.user.id,
            },
        });

        return NextResponse.json(portfolio, { status: 201 });
    } catch (error) {
        console.error("Error creating portfolio:", error);
        return NextResponse.json({ error: "Failed to create portfolio" }, { status: 500 });
    }
}
