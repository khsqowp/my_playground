import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

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
                title: body.title,
                description: body.description,
                content: body.content,
                coverImage: body.coverImage,
                images: body.images,
                links: body.links,
                techStack: body.techStack,
                published: body.published,
                visibility: body.visibility,
            },
        });

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

        return NextResponse.json({ success: true });
    } catch (error) {
        console.error("Error deleting portfolio:", error);
        return NextResponse.json({ error: "Failed to delete portfolio" }, { status: 500 });
    }
}
