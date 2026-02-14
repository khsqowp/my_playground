export const dynamic = "force-dynamic";
import { notFound } from "next/navigation";
import prisma from "@/lib/prisma";
import { MarkdownRenderer } from "@/components/shared/MarkdownRenderer";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Calendar, Eye, Bike } from "lucide-react";
import { formatDate } from "@/lib/utils";

export default async function PublicBlogPostPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;

  const post = await prisma.post.findUnique({
    where: { slug, visibility: "PUBLIC", published: true },
    include: {
      author: { select: { name: true } },
      category: true,
      tags: { include: { tag: true } },
    },
  });

  if (!post) notFound();

  // Increment view count
  await prisma.post.update({
    where: { id: post.id },
    data: { viewCount: { increment: 1 } },
  });

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="mx-auto max-w-4xl flex items-center gap-2 px-4 py-4">
          <Bike className="h-6 w-6" />
          <span className="font-bold">88Motorcycle</span>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-4 py-8 space-y-6">
        {post.coverImage && (
          <img src={post.coverImage} alt={post.title} className="w-full rounded-lg object-cover max-h-80" />
        )}

        <div className="space-y-4">
          {post.category && (
            <Badge style={{ backgroundColor: post.category.color ? `${post.category.color}20` : undefined, color: post.category.color || undefined }}>
              {post.category.name}
            </Badge>
          )}
          <h1 className="text-3xl font-bold">{post.title}</h1>
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <span>{post.author.name}</span>
            <div className="flex items-center gap-1"><Calendar className="h-3 w-3" />{formatDate(post.createdAt)}</div>
            <div className="flex items-center gap-1"><Eye className="h-3 w-3" />{post.viewCount + 1}</div>
          </div>
          <div className="flex flex-wrap gap-1">
            {post.tags.map(({ tag }) => (<Badge key={tag.id} variant="outline">{tag.name}</Badge>))}
          </div>
        </div>

        <Separator />

        <article className="prose prose-neutral dark:prose-invert max-w-none">
          <MarkdownRenderer content={post.content} />
        </article>
      </main>
    </div>
  );
}
