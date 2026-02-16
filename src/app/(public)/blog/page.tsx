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

    const [posts, totalPosts, allCategories] = await Promise.all([
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
        prisma.post.count({
            where: {
                published: true,
                visibility: "PUBLIC",
            }
        }),
        prisma.category.findMany({
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
            orderBy: { name: "asc" }
        }),
    ]);

    const totalPages = Math.ceil(totalPosts / limit);

    return (
        <div className="max-w-6xl mx-auto px-4 py-8 space-y-10">
            {/* Header Section */}
            <div className="text-center space-y-4">
                <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl">
                    블로그
                </h1>
                <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
                    지식의 공유와 기록, 더 나은 내일을 위한 기술 블로그
                </p>
            </div>

            {/* Categories Section */}
            <div className="bg-muted/30 p-6 rounded-xl border border-border/50">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-primary" />
                        카테고리 탐색
                    </h2>
                    <span className="text-xs text-muted-foreground">총 {totalPosts}개의 포스트</span>
                </div>
                <div className="flex flex-wrap gap-2">
                    <Link href="/blog">
                        <Badge
                            variant={!params.category ? "default" : "secondary"}
                            className={cn(
                                "text-sm py-1.5 px-4 cursor-pointer transition-all hover:scale-105",
                                !params.category && "shadow-md"
                            )}
                        >
                            전체 ({totalPosts})
                        </Badge>
                    </Link>
                    {allCategories.filter(cat => cat._count.posts > 0).map((cat) => (
                        <Link key={cat.id} href={`/blog?category=${cat.slug}`}>
                            <Badge
                                variant={params.category === cat.slug ? "default" : "secondary"}
                                className={cn(
                                    "text-sm py-1.5 px-4 cursor-pointer transition-all hover:scale-105",
                                    params.category === cat.slug && "shadow-md"
                                )}
                                style={params.category !== cat.slug && cat.color ? { 
                                    borderLeft: `3px solid ${cat.color}`,
                                    paddingLeft: '10px'
                                } : {}}
                            >
                                {cat.name} ({cat._count.posts})
                            </Badge>
                        </Link>
                    ))}
                </div>
            </div>

            {/* Posts List Section */}
            <div className="space-y-6">
                <div className="flex items-center gap-2 border-b pb-2">
                    <h3 className="text-lg font-bold">
                        {params.category ? `${allCategories.find(c => c.slug === params.category)?.name} 포스트` : "최신 포스트"}
                    </h3>
                </div>
                <PostList
                    posts={posts.map((p) => ({
                        ...p,
                        createdAt: p.createdAt.toISOString(),
                    }))}
                    basePath="/blog"
                />
            </div>

            {totalPages > 1 && (
                <div className="flex justify-center gap-2 mt-12 pt-8 border-t">
                    {Array.from({ length: totalPages }, (_, i) => (
                        <Link key={i} href={`/blog?page=${i + 1}${params.category ? `&category=${params.category}` : ""}`}>
                            <Button variant={page === i + 1 ? "default" : "outline"} size="sm" className="w-10">
                                {i + 1}
                            </Button>
                        </Link>
                    ))}
                </div>
            )}
        </div>
    );
}

// cn helper import was missing, adding it at the top
import { cn } from "@/lib/utils";
