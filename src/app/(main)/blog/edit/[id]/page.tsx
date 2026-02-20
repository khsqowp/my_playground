"use client";

import { useState, useEffect } from "react";
import { useRouter, useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { MarkdownEditor } from "@/components/blog/MarkdownEditor";
import { toast } from "sonner";
import { Loader2, Save, Trash2, Sparkles } from "lucide-react";

export default function BlogEditPage() {
  const router = useRouter();
  const params = useParams();
  const id = params.id as string;

  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [categoryId, setCategoryId] = useState("");
  const [tags, setTags] = useState("");
  const [visibility, setVisibility] = useState("PRIVATE");
  const [coverImage, setCoverImage] = useState("");
  const [published, setPublished] = useState(false);
  const [loading, setLoading] = useState(false);
  const [regenTagging, setRegenTagging] = useState(false);
  const [categories, setCategories] = useState<{ id: string; name: string }[]>([]);
  const [createdAt, setCreatedAt] = useState("");

  useEffect(() => {
    Promise.all([
      fetch(`/api/blog/${id}`).then((r) => r.json()),
      fetch("/api/categories").then((r) => r.json()),
    ]).then(([post, catData]) => {
      setTitle(post.title);
      setContent(post.content);
      setCategoryId(post.categoryId || "");
      setTags(post.tags?.map((t: { tag: { name: string } }) => t.tag.name).join(", ") || "");
      setVisibility(post.visibility);
      setCoverImage(post.coverImage || "");
      setPublished(post.published);
      if (post.createdAt) {
        // Format for datetime-local input: YYYY-MM-DDThh:mm
        const date = new Date(post.createdAt);
        date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
        setCreatedAt(date.toISOString().slice(0, 16));
      }
      if (catData.categories) setCategories(catData.categories);
    });
  }, [id]);

  async function handleSave() {
    setLoading(true);
    try {
      const res = await fetch(`/api/blog/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          content,
          categoryId: categoryId || undefined,
          tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
          visibility,
          coverImage: coverImage || undefined,
          published,
          createdAt: createdAt ? new Date(createdAt).toISOString() : undefined,
        }),
      });
      if (!res.ok) throw new Error();
      const data = await res.json();
      toast.success("글이 업데이트되었습니다");
      router.push(`/blog/${data.slug}`);
    } catch {
      toast.error("업데이트에 실패했습니다");
    } finally {
      setLoading(false);
    }
  }

  async function handleRegenTags() {
    setRegenTagging(true);
    try {
      const res = await fetch(`/api/blog/${id}/regen-tags`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "태그 생성 실패");
      setTags(data.tags.join(", "));
      toast.success(`태그가 재생성되었습니다: ${data.tags.join(", ")}`);
    } catch (e: any) {
      toast.error(e.message || "태그 재생성에 실패했습니다");
    } finally {
      setRegenTagging(false);
    }
  }

  async function handleDelete() {
    if (!confirm("이 글을 삭제하시겠습니까?")) return;
    await fetch(`/api/blog/${id}`, { method: "DELETE" });
    toast.success("글이 삭제되었습니다");
    router.push("/manage/blog");
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <h1 className="text-2xl font-bold">글 수정</h1>

      <div className="grid gap-4 md:grid-cols-4">
        <div className="md:col-span-3 space-y-4">
          <Input
            placeholder="글 제목"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="text-lg font-semibold"
          />
          <MarkdownEditor value={content} onChange={setContent} />
        </div>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label>카테고리</Label>
            <Select value={categoryId} onValueChange={setCategoryId}>
              <SelectTrigger><SelectValue placeholder="카테고리 선택" /></SelectTrigger>
              <SelectContent>
                {categories.map((cat) => (
                  <SelectItem key={cat.id} value={cat.id}>{cat.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>태그</Label>
            <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="react, nextjs" />
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="w-full"
              onClick={handleRegenTags}
              disabled={regenTagging}
            >
              {regenTagging ? (
                <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
              ) : (
                <Sparkles className="mr-2 h-3.5 w-3.5" />
              )}
              AI 태그 재생성
            </Button>
          </div>

          <div className="space-y-2">
            <Label>공개 범위</Label>
            <Select value={visibility} onValueChange={setVisibility}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="PRIVATE">비공개</SelectItem>
                <SelectItem value="PUBLIC">공개</SelectItem>
                <SelectItem value="SHARED">공유</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-2">
            <Switch checked={published} onCheckedChange={setPublished} />
            <Label>발행 상태</Label>
          </div>

          <div className="space-y-2">
            <Label>작성일</Label>
            <Input
              type="datetime-local"
              value={createdAt}
              onChange={(e) => setCreatedAt(e.target.value)}
            />
          </div>

          <Button onClick={handleSave} disabled={loading} className="w-full">
            {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
            변경사항 저장
          </Button>
          <Button variant="destructive" onClick={handleDelete} className="w-full">
            <Trash2 className="mr-2 h-4 w-4" /> 삭제
          </Button>
        </div>
      </div>
    </div>
  );
}
