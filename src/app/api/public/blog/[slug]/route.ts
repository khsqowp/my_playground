import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = "force-dynamic";

// GET /api/public/blog/[slug] - Get single public post
export async function GET(
    request: NextRequest,
    { params }: { params: Promise<{ slug: string }> }
) {
    try {
        const { slug } = await params;

        // Increment view count and get post
        const post = await prisma.post.update({
            where: {
                slug,
                published: true,
                visibility: "PUBLIC",
            },
            data: {
                viewCount: {
                    increment: 1,
                },
            },
            include: {
                author: {
                    select: {
                        id: true,
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
                                id: true,
                                name: true,
                            },
                        },
                    },
                },
                series: {
                    include: {
                        posts: {
                            where: {
                                published: true,
                                visibility: "PUBLIC",
                            },
                            select: {
                                id: true,
                                title: true,
                                slug: true,
                                seriesOrder: true,
                            },
                            orderBy: {
                                seriesOrder: "asc",
                            },
                        },
                    },
                },
            },
        });

        if (!post) {
            return NextResponse.json({ error: "Post not found" }, { status: 404 });
        }

        return NextResponse.json(post);
    } catch (error) {
        console.error("Error fetching public post:", error);
        return NextResponse.json({ error: "Failed to fetch post" }, { status: 500 });
    }
}
