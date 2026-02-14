export const dynamic = "force-dynamic";

import { notFound } from "next/navigation";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { MarkdownRenderer } from "@/components/shared/MarkdownRenderer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ArrowLeft, Edit, Calendar, Eye } from "lucide-react";
import { formatDate } from "@/lib/utils";
import { auth } from "@/lib/auth";

export default async function PublicBlogPostPage({
    params,
}: {
    params: Promise<{ slug: string }>;
}) {
    const { slug } = await params;
    const session = await auth();

    const post = await prisma.post.update({
        where: {
            slug,
            published: true,
            visibility: "PUBLIC",
        },
        data: { viewCount: { increment: 1 } },
        include: {
            author: { select: { id: true, name: true } },
            category: true,
            tags: { include: { tag: true } },
            series: { include: { posts: { select: { id: true, title: true, slug: true, seriesOrder: true }, orderBy: { seriesOrder: "asc" } } } },
        },
    }).catch(() => null);

    if (!post) notFound();

    return (
        <div className="mx-auto max-w-4xl space-y-6">
            <div className="flex items-center justify-between">
                <Button variant="ghost" size="sm" asChild>
                    <Link href="/blog">
                        <ArrowLeft className="mr-2 h-4 w-4" />
                        블로그로 돌아가기
                    </Link>
                </Button>
                {session?.user && (
                    <Button variant="outline" size="sm" asChild>
                        <Link href={`/blog/edit/${post.id}`}>
                            <Edit className="mr-1 h-3 w-3" />
                            수정
                        </Link>
                    </Button>
                )}
            </div>

            {post.coverImage && (
                <img
                    src={post.coverImage}
                    alt={post.title}
                    className="w-full rounded-lg object-cover max-h-80"
                />
            )}

            <div className="space-y-4">
                <div className="flex items-center gap-2">
                    {post.category && (
                        <Badge
                            style={{
                                backgroundColor: post.category.color ? `${post.category.color}20` : undefined,
                                color: post.category.color || undefined,
                            }}
                        >
                            {post.category.name}
                        </Badge>
                    )}
                </div>

                <h1 className="text-3xl font-bold">{post.title}</h1>

                <div className="flex items-center gap-4 text-sm text-muted-foreground">
                    <span>{post.author.name}</span>
                    <div className="flex items-center gap-1">
                        <Calendar className="h-3 w-3" />
                        {formatDate(post.createdAt)}
                    </div>
                    <div className="flex items-center gap-1">
                        <Eye className="h-3 w-3" />
                        {post.viewCount}
                    </div>
                </div>

                <div className="flex flex-wrap gap-1">
                    {post.tags.map(({ tag }) => (
                        <Badge key={tag.id} variant="outline">
                            {tag.name}
                        </Badge>
                    ))}
                </div>
            </div>

            <Separator />

            <article className="prose prose-neutral dark:prose-invert max-w-none">
                <MarkdownRenderer content={post.content} />
            </article>

            {post.series && (
                <>
                    <Separator />
                    <div className="space-y-3">
                        <h3 className="font-semibold">시리즈: {post.series.name}</h3>
                        <div className="space-y-1">
                            {post.series.posts.map((p) => (
                                <Link
                                    key={p.id}
                                    href={`/blog/${p.slug}`}
                                    className={`block rounded px-3 py-2 text-sm transition-colors ${p.id === post.id
                                        ? "bg-accent font-medium"
                                        : "hover:bg-accent/50"
                                        }`}
                                >
                                    {p.seriesOrder != null ? `${p.seriesOrder}. ` : ""}
                                    {p.title}
                                </Link>
                            ))}
                        </div>
                    </div>
                </>
            )}
        </div>
    );
}
