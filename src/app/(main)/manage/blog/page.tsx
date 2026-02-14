export const dynamic = "force-dynamic";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { PostList } from "@/components/blog/PostList";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Plus } from "lucide-react";

export default async function BlogPage({
  searchParams,
}: {
  searchParams: Promise<{ category?: string; page?: string }>;
}) {
  const params = await searchParams;
  const page = parseInt(params.page || "1");
  const limit = 12;

  const where: Record<string, unknown> = {};
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
      include: { _count: { select: { posts: true } } },
    }),
  ]);

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">블로그</h1>
        <Button asChild>
          <Link href="/blog/write">
            <Plus className="mr-2 h-4 w-4" />
            새 글 작성
          </Link>
        </Button>
      </div>

      <div className="flex flex-wrap gap-2">
        <Link href="/blog">
          <Badge variant={!params.category ? "default" : "outline"}>전체</Badge>
        </Link>
        {categories.map((cat) => (
          <Link key={cat.id} href={`/blog?category=${cat.slug}`}>
            <Badge variant={params.category === cat.slug ? "default" : "outline"}>
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
        basePath="/blog/edit"
        linkField="id"
      />

      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
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
