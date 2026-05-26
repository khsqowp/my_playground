import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { syncPortfolioToRag } from "@/lib/rag-sync";

type PortfolioVisibility = "PUBLIC" | "PRIVATE";

function normalizePortfolioPayload(body: any) {
    const images = Array.isArray(body.images)
        ? body.images
            .filter((item: any) => item?.url)
            .map((item: any) => ({
                url: String(item.url).trim(),
                caption: item.caption ? String(item.caption).trim() : "",
            }))
        : [];

    const links = Array.isArray(body.links)
        ? body.links
            .filter((item: any) => item?.url)
            .map((item: any) => ({
                title: item.title ? String(item.title).trim() : "",
                url: String(item.url).trim(),
                type: item.type ? String(item.type).trim() : "website",
            }))
        : [];

    return {
        title: String(body.title || "").trim(),
        description: body.description ? String(body.description).trim() : null,
        content: body.content ? String(body.content) : null,
        coverImage: body.coverImage ? String(body.coverImage).trim() : null,
        images,
        links,
        techStack: body.techStack ? String(body.techStack).trim() : null,
        published: Boolean(body.published),
        visibility: (body.visibility === "PUBLIC" ? "PUBLIC" : "PRIVATE") as PortfolioVisibility,
        sortOrder: Number.isFinite(Number(body.sortOrder)) ? Number(body.sortOrder) : 0,
    };
}

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

        const payload = normalizePortfolioPayload(body);

        if (!payload.title) {
            return NextResponse.json({ error: "Title is required" }, { status: 400 });
        }

        // Generate slug
        let slug = payload.title
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
                title: payload.title,
                slug: uniqueSlug,
                description: payload.description,
                content: payload.content,
                coverImage: payload.coverImage,
                images: payload.images,
                links: payload.links,
                techStack: payload.techStack,
                published: payload.published,
                visibility: payload.visibility,
                sortOrder: payload.sortOrder,
                authorId: session.user.id,
            },
        });

        await syncPortfolioToRag(portfolio);

        return NextResponse.json(portfolio, { status: 201 });
    } catch (error) {
        console.error("Error creating portfolio:", error);
        return NextResponse.json({ error: "Failed to create portfolio" }, { status: 500 });
    }
}
