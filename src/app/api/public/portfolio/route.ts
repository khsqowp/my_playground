import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = "force-dynamic";

// GET /api/public/portfolio - List public portfolios
export async function GET(request: NextRequest) {
    try {
        const searchParams = request.nextUrl.searchParams;
        const page = parseInt(searchParams.get("page") || "1");
        const limit = parseInt(searchParams.get("limit") || "12");

        const skip = (page - 1) * limit;

        const [portfolios, total] = await Promise.all([
            prisma.portfolio.findMany({
                where: {
                    published: true,
                    visibility: "PUBLIC",
                },
                orderBy: [
                    { sortOrder: "asc" },
                    { createdAt: "desc" },
                ],
                skip,
                take: limit,
            }),
            prisma.portfolio.count({
                where: {
                    published: true,
                    visibility: "PUBLIC",
                },
            }),
        ]);

        const totalPages = Math.ceil(total / limit);

        return NextResponse.json({
            portfolios,
            pagination: {
                page,
                limit,
                total,
                totalPages,
            },
        });
    } catch (error) {
        console.error("Error fetching public portfolios:", error);
        return NextResponse.json({ error: "Failed to fetch portfolios" }, { status: 500 });
    }
}
