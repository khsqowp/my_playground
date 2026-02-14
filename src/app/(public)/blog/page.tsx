export const dynamic = "force-dynamic";

import Link from "next/link";
import { PostList } from "@/components/blog/PostList";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import prisma from "@/lib/prisma";

export default async function PublicBlogPage({
    searchParams,
}: {
    searchParams: Promise<{ category?: string; page?: string }>;
}) {
    const params = await searchParams;
    const page = parseInt(params.page || "1");
    const limit = 12;

    const where: any = {
        published: true,
        visibility: "PUBLIC",
    };

    if (params.category) {
        where.category = { slug: params.category };
    }

    const [posts, total, categories] = await Promise.all([
        prisma.post.findMany({
            where,
            include: {
                author: { select: { name: true } },
                category: { select: { name: true, color: true } },
                tags: { include: { tag: { select: { name: true } } } },
            },
            orderBy: { createdAt: "desc" },
            skip: (page - 1) * limit,
            take: limit,
        }),
        prisma.post.count({ where }),
        prisma.category.findMany({
            where: {
                posts: {
                    some: {
                        published: true,
                        visibility: "PUBLIC",
                    },
                },
            },
            include: {
                _count: {
                    select: {
                        posts: {
                            where: {
                                published: true,
                                visibility: "PUBLIC",
                            }
                        }
                    }
                }
            },
        }),
    ]);

    const totalPages = Math.ceil(total / limit);

    return (
        <div className="space-y-8">
            <div className="flex flex-col gap-4">
                <h1 className="text-3xl font-bold tracking-tight">블로그</h1>
                <p className="text-muted-foreground">
                    개발, 보안, 그리고 일상에 대한 기록
                </p>
            </div>

            <div className="flex flex-wrap gap-2">
                <Link href="/blog">
                    <Badge
                        variant={!params.category ? "default" : "outline"}
                        className="text-sm py-1 px-3"
                    >
                        전체
                    </Badge>
                </Link>
                {categories.map((cat) => (
                    <Link key={cat.id} href={`/blog?category=${cat.slug}`}>
                        <Badge
                            variant={params.category === cat.slug ? "default" : "outline"}
                            className="text-sm py-1 px-3"
                        >
                            {cat.name} ({cat._count.posts})
                        </Badge>
                    </Link>
                ))}
            </div>

            <PostList
                posts={posts.map((p) => ({
                    ...p,
                    createdAt: p.createdAt.toISOString(),
                }))}
                basePath="/blog"
            />

            {totalPages > 1 && (
                <div className="flex justify-center gap-2 mt-8">
                    {Array.from({ length: totalPages }, (_, i) => (
                        <Link key={i} href={`/blog?page=${i + 1}${params.category ? `&category=${params.category}` : ""}`}>
                            <Button variant={page === i + 1 ? "default" : "outline"} size="sm">
                                {i + 1}
                            </Button>
                        </Link>
                    ))}
                </div>
            )}
        </div>
    );
}
