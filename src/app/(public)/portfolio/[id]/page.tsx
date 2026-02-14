export const dynamic = "force-dynamic";

import { notFound } from "next/navigation";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { MarkdownRenderer } from "@/components/shared/MarkdownRenderer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ArrowLeft, Calendar, Globe, Github, ExternalLink } from "lucide-react";
import { formatDate } from "@/lib/utils";
import { auth } from "@/lib/auth";

export default async function PublicPortfolioDetailPage({
    params,
}: {
    params: Promise<{ id: string }>;
}) {
    const { id } = await params;
    const session = await auth();

    const portfolio = await prisma.portfolio.findUnique({
        where: {
            id,
            published: true,
            visibility: "PUBLIC",
        },
        include: {
            author: { select: { name: true } },
        },
    });

    if (!portfolio) notFound();

    const links = Array.isArray(portfolio.links) ? portfolio.links : [];
    const images = Array.isArray(portfolio.images) ? portfolio.images : [];

    return (
        <div className="mx-auto max-w-4xl space-y-8">
            <div className="flex items-center justify-between">
                <Button variant="ghost" size="sm" asChild>
                    <Link href="/portfolio">
                        <ArrowLeft className="mr-2 h-4 w-4" />
                        목록으로
                    </Link>
                </Button>
                {session?.user && (
                    <Button variant="outline" size="sm" asChild>
                        <Link href={`/portfolio/edit/${portfolio.id}`}>
                            관리
                        </Link>
                    </Button>
                )}
            </div>

            <div className="space-y-4">
                <h1 className="text-4xl font-bold">{portfolio.title}</h1>

                <div className="flex items-center gap-4 text-sm text-muted-foreground">
                    <span>{portfolio.author.name}</span>
                    <div className="flex items-center gap-1">
                        <Calendar className="h-3 w-3" />
                        {formatDate(portfolio.createdAt)}
                    </div>
                </div>

                {portfolio.techStack && (
                    <div className="flex flex-wrap gap-2">
                        {portfolio.techStack.split(',').map((tech) => (
                            <Badge key={tech} variant="secondary">
                                {tech.trim()}
                            </Badge>
                        ))}
                    </div>
                )}

                {links.length > 0 && (
                    <div className="flex flex-wrap gap-3 pt-2">
                        {links.map((link: any, index: number) => (
                            <Button key={index} variant="outline" size="sm" asChild>
                                <a href={link.url} target="_blank" rel="noopener noreferrer">
                                    {link.type === 'github' ? <Github className="mr-2 h-4 w-4" /> :
                                        link.type === 'demo' ? <Globe className="mr-2 h-4 w-4" /> :
                                            <ExternalLink className="mr-2 h-4 w-4" />}
                                    {link.title || 'Link'}
                                </a>
                            </Button>
                        ))}
                    </div>
                )}
            </div>

            {portfolio.coverImage && (
                <div className="aspect-video w-full overflow-hidden rounded-lg border bg-muted">
                    <img
                        src={portfolio.coverImage}
                        alt={portfolio.title}
                        className="h-full w-full object-cover"
                    />
                </div>
            )}

            {portfolio.description && (
                <div className="prose prose-neutral dark:prose-invert max-w-none">
                    <p className="lead">{portfolio.description}</p>
                </div>
            )}

            {images.length > 0 && (
                <div className="space-y-4">
                    <h2 className="text-2xl font-bold">갤러리</h2>
                    <div className="grid gap-4 sm:grid-cols-2">
                        {images.map((img: any, index: number) => (
                            <div key={index} className="space-y-2">
                                <div className="aspect-video overflow-hidden rounded-lg border bg-muted">
                                    <img
                                        src={img.url}
                                        alt={img.caption || `Gallery image ${index + 1}`}
                                        className="h-full w-full object-cover"
                                    />
                                </div>
                                {img.caption && (
                                    <p className="text-sm text-muted-foreground text-center">{img.caption}</p>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {portfolio.content && (
                <>
                    <Separator />
                    <article className="prose prose-neutral dark:prose-invert max-w-none">
                        <MarkdownRenderer content={portfolio.content} />
                    </article>
                </>
            )}
        </div>
    );
}
