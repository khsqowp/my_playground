import { PostCard } from "./PostCard";
import { FileText } from "lucide-react";

interface PostListProps {
  posts: {
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
  }[];
  basePath?: string;
  linkField?: "id" | "slug";
}

export function PostList({ posts, basePath = "/blog", linkField = "slug" }: PostListProps) {
  if (posts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <FileText className="h-12 w-12 mb-4" />
        <p className="text-lg font-medium">글이 없습니다</p>
        <p className="text-sm">첫 번째 블로그 글을 작성해보세요.</p>
      </div>
    );
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {posts.map((post) => (
        <PostCard key={post.id} post={post} basePath={basePath} linkField={linkField} />
      ))}
    </div>
  );
}
