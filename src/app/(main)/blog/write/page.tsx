"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
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
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { MarkdownEditor } from "@/components/blog/MarkdownEditor";
import { FileUpload } from "@/components/shared/FileUpload";
import { toast } from "sonner";
import { Loader2, Save, Send, Plus } from "lucide-react";

interface Category {
  id: string;
  name: string;
  slug: string;
  color: string | null;
}

export default function BlogWritePage() {
  const router = useRouter();
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [categoryId, setCategoryId] = useState("");
  const [tags, setTags] = useState("");
  const [visibility, setVisibility] = useState("PUBLIC");
  const [coverImage, setCoverImage] = useState("");
  const [published, setPublished] = useState(false);
  const [loading, setLoading] = useState(false);
  const [categories, setCategories] = useState<Category[]>([]);
  
  // 기본 작성일: 오늘 오전 09:00 설정
  const getDefaultDateTime = () => {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}T09:00`;
  };
  const [createdAt, setCreatedAt] = useState(getDefaultDateTime());

  // 카테고리 추가 관련
  const [showNewCategory, setShowNewCategory] = useState(false);
  const [newCategoryName, setNewCategoryName] = useState("");
  const [newCategoryColor, setNewCategoryColor] = useState("#3B82F6");
  const [addingCategory, setAddingCategory] = useState(false);

  function loadCategories() {
    fetch("/api/categories")
      .then((r) => r.json())
      .then((data) => {
        if (data.categories) setCategories(data.categories);
      })
      .catch(() => { });
  }

  // 최근 게시글의 카테고리 가져오기
  function loadLastCategory() {
    fetch("/api/blog?limit=1")
      .then((r) => r.json())
      .then((data) => {
        if (data.posts && data.posts.length > 0 && data.posts[0].categoryId) {
          setCategoryId(data.posts[0].categoryId);
        }
      })
      .catch(() => { });
  }

  useEffect(() => {
    loadCategories();
    loadLastCategory();
  }, []);

  async function handleAddCategory() {
    if (!newCategoryName.trim()) return;
    setAddingCategory(true);
    try {
      const res = await fetch("/api/categories", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newCategoryName, color: newCategoryColor }),
      });
      if (!res.ok) {
        const err = await res.json();
        toast.error(err.error || "카테고리 추가에 실패했습니다");
        return;
      }
      const created = await res.json();
      setCategories((prev) => [...prev, created].sort((a, b) => a.name.localeCompare(b.name)));
      setCategoryId(created.id);
      setNewCategoryName("");
      setShowNewCategory(false);
      toast.success(`'${created.name}' 카테고리가 추가되었습니다`);
    } catch {
      toast.error("카테고리 추가에 실패했습니다");
    } finally {
      setAddingCategory(false);
    }
  }

  async function handleSave(shouldPublish: boolean) {
    if (!title.trim()) {
      toast.error("제목을 입력해주세요");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/blog", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          content,
          categoryId: categoryId || undefined,
          tags: tags
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
          visibility,
          coverImage: coverImage || undefined,
          published: shouldPublish,
          createdAt: createdAt || undefined,
        }),
      });

      if (!res.ok) throw new Error("Failed to save");
      const data = await res.json();
      toast.success(shouldPublish ? "글이 발행되었습니다!" : "임시저장되었습니다!");
      router.push("/manage/blog");
    } catch {
      toast.error("글 저장에 실패했습니다");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <h1 className="text-2xl font-bold">새 글 작성</h1>

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
              <SelectTrigger>
                <SelectValue placeholder="카테고리 선택" />
              </SelectTrigger>
              <SelectContent>
                {categories.map((cat) => (
                  <SelectItem key={cat.id} value={cat.id}>
                    <span className="flex items-center gap-2">
                      {cat.color && (
                        <span
                          className="inline-block h-2.5 w-2.5 rounded-full"
                          style={{ backgroundColor: cat.color }}
                        />
                      )}
                      {cat.name}
                    </span>
                  </SelectItem>
                ))}
                <Separator className="my-1" />
                <button
                  type="button"
                  className="relative flex w-full cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  onMouseDown={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    setShowNewCategory(true);
                  }}
                >
                  <Plus className="h-3.5 w-3.5" />
                  새 카테고리 추가
                </button>
              </SelectContent>
            </Select>

            {showNewCategory && (
              <div className="space-y-2 rounded-md border p-3 bg-muted/30">
                <Input
                  placeholder="카테고리 이름"
                  value={newCategoryName}
                  onChange={(e) => setNewCategoryName(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleAddCategory()}
                  autoFocus
                />
                <div className="flex items-center gap-2">
                  <Label className="text-xs text-muted-foreground">색상</Label>
                  <input
                    type="color"
                    value={newCategoryColor}
                    onChange={(e) => setNewCategoryColor(e.target.value)}
                    className="h-7 w-7 cursor-pointer rounded border-0"
                  />
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    onClick={handleAddCategory}
                    disabled={addingCategory || !newCategoryName.trim()}
                    className="flex-1"
                  >
                    {addingCategory ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <Plus className="mr-1 h-3 w-3" />}
                    추가
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => { setShowNewCategory(false); setNewCategoryName(""); }}
                  >
                    취소
                  </Button>
                </div>
              </div>
            )}
          </div>

          <div className="space-y-2">
            <Label>태그 (쉼표로 구분)</Label>
            <Input
              placeholder="react, nextjs, ..."
              value={tags}
              onChange={(e) => setTags(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label>공개 범위</Label>
            <Select value={visibility} onValueChange={setVisibility}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="PRIVATE">비공개</SelectItem>
                <SelectItem value="PUBLIC">공개</SelectItem>
                <SelectItem value="SHARED">링크 공유만</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>커버 이미지</Label>
            <FileUpload onUpload={setCoverImage} />
            {coverImage && (
              <img src={coverImage} alt="Cover" className="rounded max-h-32 w-full object-cover" />
            )}
          </div>

          <div className="flex items-center gap-2">
            <Switch checked={published} onCheckedChange={setPublished} />
            <Label>즉시 발행</Label>
          </div>

          <div className="space-y-2">
            <Label>작성일 (선택사항)</Label>
            <Input
              type="datetime-local"
              value={createdAt}
              onChange={(e) => setCreatedAt(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">비워두면 현재 시간으로 저장됩니다.</p>
          </div>

          <div className="flex flex-col gap-2">
            <Button onClick={() => handleSave(true)} disabled={loading}>
              {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Send className="mr-2 h-4 w-4" />}
              발행하기
            </Button>
            <Button variant="outline" onClick={() => handleSave(false)} disabled={loading}>
              <Save className="mr-2 h-4 w-4" />
              임시저장
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
