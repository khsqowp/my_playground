import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = "force-dynamic";

// GET /api/public/blog - List public posts
export async function GET(request: NextRequest) {
    try {
        const searchParams = request.nextUrl.searchParams;
        const page = parseInt(searchParams.get("page") || "1");
        const limit = parseInt(searchParams.get("limit") || "12");
        const category = searchParams.get("category");
        const search = searchParams.get("search");

        const skip = (page - 1) * limit;

        // Build where clause
        const where: any = {
            published: true,
            visibility: "PUBLIC",
        };

        if (category) {
            where.category = {
                slug: category,
            };
        }

        if (search) {
            where.OR = [
                { title: { contains: search } },
                { content: { contains: search } },
                { excerpt: { contains: search } },
            ];
        }

        const [posts, total] = await Promise.all([
            prisma.post.findMany({
                where,
                skip,
                take: limit,
                orderBy: { createdAt: "desc" },
                include: {
                    author: {
                        select: {
                            name: true,
                        },
                    },
                    category: {
                        select: {
                            name: true,
                            slug: true,
                            color: true,
                        },
                    },
                    tags: {
                        include: {
                            tag: {
                                select: {
                                    name: true,
                                },
                            },
                        },
                    },
                },
            }),
            prisma.post.count({ where }),
        ]);

        const totalPages = Math.ceil(total / limit);

        return NextResponse.json({
            posts,
            pagination: {
                page,
                limit,
                total,
                totalPages,
            },
        });
    } catch (error) {
        console.error("Error fetching public posts:", error);
        return NextResponse.json({ error: "Failed to fetch posts" }, { status: 500 });
    }
}
