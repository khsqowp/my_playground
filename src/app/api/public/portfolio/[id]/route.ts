import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = "force-dynamic";

// GET /api/public/portfolio/[id] - Get single public portfolio
export async function GET(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    try {
        const { id } = await params;

        const portfolio = await prisma.portfolio.findFirst({
            where: {
                id,
                published: true,
                visibility: "PUBLIC",
            },
            include: {
                author: {
                    select: {
                        name: true,
                    },
                },
            },
        });

        if (!portfolio) {
            return NextResponse.json({ error: "Portfolio not found" }, { status: 404 });
        }

        return NextResponse.json(portfolio);
    } catch (error) {
        console.error("Error fetching public portfolio:", error);
        return NextResponse.json({ error: "Failed to fetch portfolio" }, { status: 500 });
    }
}
