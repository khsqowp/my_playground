import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { removeRagDocument, syncPortfolioToRag } from "@/lib/rag-sync";

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

// GET /api/portfolio/[id] - Get portfolio details
export async function GET(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    try {
        const session = await auth();
        if (!session?.user?.id) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const { id } = await params;

        const portfolio = await prisma.portfolio.findUnique({
            where: { id },
        });

        if (!portfolio) {
            return NextResponse.json({ error: "Portfolio not found" }, { status: 404 });
        }

        // Check ownership
        if (portfolio.authorId !== session.user.id) {
            return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        }

        return NextResponse.json(portfolio);
    } catch (error) {
        console.error("Error fetching portfolio:", error);
        return NextResponse.json({ error: "Failed to fetch portfolio" }, { status: 500 });
    }
}

// PUT /api/portfolio/[id] - Update portfolio
export async function PUT(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    try {
        const session = await auth();
        if (!session?.user?.id) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const { id } = await params;
        const body = await request.json();
        const payload = normalizePortfolioPayload(body);

        const portfolio = await prisma.portfolio.findUnique({
            where: { id },
        });

        if (!portfolio) {
            return NextResponse.json({ error: "Portfolio not found" }, { status: 404 });
        }

        if (portfolio.authorId !== session.user.id) {
            return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        }

        const updated = await prisma.portfolio.update({
            where: { id },
            data: {
                title: payload.title,
                description: payload.description,
                content: payload.content,
                coverImage: payload.coverImage,
                images: payload.images,
                links: payload.links,
                techStack: payload.techStack,
                published: payload.published,
                visibility: payload.visibility,
                sortOrder: payload.sortOrder,
            },
        });

        await syncPortfolioToRag(updated);

        return NextResponse.json(updated);
    } catch (error) {
        console.error("Error updating portfolio:", error);
        return NextResponse.json({ error: "Failed to update portfolio" }, { status: 500 });
    }
}

// DELETE /api/portfolio/[id] - Delete portfolio
export async function DELETE(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    try {
        const session = await auth();
        if (!session?.user?.id) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const { id } = await params;

        const portfolio = await prisma.portfolio.findUnique({
            where: { id },
        });

        if (!portfolio) {
            return NextResponse.json({ error: "Portfolio not found" }, { status: 404 });
        }

        if (portfolio.authorId !== session.user.id) {
            return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        }

        await prisma.portfolio.delete({
            where: { id },
        });

        await removeRagDocument("portfolio", portfolio.slug);

        return NextResponse.json({ success: true });
    } catch (error) {
        console.error("Error deleting portfolio:", error);
        return NextResponse.json({ error: "Failed to delete portfolio" }, { status: 500 });
    }
}
