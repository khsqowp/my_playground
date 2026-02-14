import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Eye, Calendar } from "lucide-react";
import { formatDate } from "@/lib/utils";

interface PostCardProps {
  post: {
    id: string;
    title: string;
    slug: string;
    excerpt: string | null;
    coverImage: string | null;
    published: boolean;
    visibility: string;
    category: { name: string; color: string | null } | null;
    tags: { tag: { name: string } }[];
    author: { name: string };
    viewCount: number;
    createdAt: string;
  };
  basePath?: string;
  linkField?: "id" | "slug";
}

export function PostCard({ post, basePath = "/blog", linkField = "slug" }: PostCardProps) {
  const linkValue = linkField === "id" ? post.id : post.slug;
  return (
    <Link href={`${basePath}/${linkValue}`}>
      <Card className="h-full transition-shadow hover:shadow-md">
        {post.coverImage && (
          <div className="aspect-video overflow-hidden rounded-t-lg">
            <img
              src={post.coverImage}
              alt={post.title}
              className="h-full w-full object-cover"
              loading="lazy"
            />
          </div>
        )}
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2 mb-1">
            {post.category && (
              <Badge
                variant="secondary"
                style={{
                  backgroundColor: post.category.color
                    ? `${post.category.color}20`
                    : undefined,
                  color: post.category.color || undefined,
                }}
              >
                {post.category.name}
              </Badge>
            )}
            {!post.published && (
              <Badge variant="outline">임시저장</Badge>
            )}
          </div>
          <h3 className="font-semibold line-clamp-2">{post.title}</h3>
        </CardHeader>
        <CardContent>
          {post.excerpt && (
            <p className="text-sm text-muted-foreground line-clamp-2 mb-3">
              {post.excerpt}
            </p>
          )}
          <div className="flex flex-wrap gap-1 mb-3">
            {post.tags.slice(0, 3).map(({ tag }) => (
              <Badge key={tag.name} variant="outline" className="text-xs">
                {tag.name}
              </Badge>
            ))}
          </div>
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <Calendar className="h-3 w-3" />
              {formatDate(post.createdAt)}
            </div>
            <div className="flex items-center gap-1">
              <Eye className="h-3 w-3" />
              {post.viewCount}
            </div>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
