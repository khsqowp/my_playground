export interface PostData {
  id: string;
  title: string;
  slug: string;
  content: string;
  excerpt: string | null;
  coverImage: string | null;
  published: boolean;
  visibility: "PUBLIC" | "PRIVATE" | "SHARED";
  categoryId: string | null;
  category: { id: string; name: string; slug: string; color: string | null } | null;
  tags: { tag: { id: string; name: string } }[];
  seriesId: string | null;
  series: { id: string; name: string } | null;
  seriesOrder: number | null;
  authorId: string;
  author: { id: string; name: string };
  viewCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface PostCreateInput {
  title: string;
  content: string;
  excerpt?: string;
  coverImage?: string;
  published?: boolean;
  visibility?: "PUBLIC" | "PRIVATE" | "SHARED";
  categoryId?: string;
  tags?: string[];
  seriesId?: string;
  seriesOrder?: number;
  createdAt?: string;
}

export interface PostUpdateInput extends Partial<PostCreateInput> { }

export interface CategoryData {
  id: string;
  name: string;
  slug: string;
  color: string | null;
  _count?: { posts: number; notes: number };
}

export interface TagData {
  id: string;
  name: string;
  _count?: { posts: number; notes: number };
}

export interface SeriesData {
  id: string;
  name: string;
  description: string | null;
  posts: { id: string; title: string; slug: string; seriesOrder: number | null }[];
  createdAt: string;
}
