"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { MarkdownEditor } from "@/components/blog/MarkdownEditor";
import { toast } from "sonner";
import { Loader2, Save } from "lucide-react";

export default function NoteWritePage() {
  const router = useRouter();
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [categoryId, setCategoryId] = useState("");
  const [tags, setTags] = useState("");
  const [visibility, setVisibility] = useState("PRIVATE");
  const [loading, setLoading] = useState(false);
  const [categories, setCategories] = useState<{ id: string; name: string }[]>([]);

  useEffect(() => {
    fetch("/api/categories")
      .then((r) => r.json())
      .then((data) => { if (data.categories) setCategories(data.categories); })
      .catch(() => { });
  }, []);

  async function handleSave() {
    if (!title.trim()) { toast.error("제목을 입력해주세요"); return; }
    setLoading(true);
    try {
      const res = await fetch("/api/archive/notes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title, content, visibility,
          categoryId: categoryId || undefined,
          tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        }),
      });
      if (!res.ok) throw new Error();
      const data = await res.json();
      toast.success("노트가 저장되었습니다!");
      router.push(`/archive/notes/${data.id}`);
    } catch {
      toast.error("저장에 실패했습니다");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <h1 className="text-2xl font-bold">새 노트</h1>
      <div className="grid gap-4 md:grid-cols-4">
        <div className="md:col-span-3 space-y-4">
          <Input placeholder="노트 제목" value={title} onChange={(e) => setTitle(e.target.value)} className="text-lg font-semibold" />
          <MarkdownEditor value={content} onChange={setContent} />
        </div>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label>카테고리</Label>
            <Select value={categoryId} onValueChange={setCategoryId}>
              <SelectTrigger><SelectValue placeholder="선택" /></SelectTrigger>
              <SelectContent>
                {categories.map((c) => (<SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>태그</Label>
            <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="쉼표로 구분" />
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
          <Button onClick={handleSave} disabled={loading} className="w-full">
            {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
            노트 저장
          </Button>
        </div>
      </div>
    </div>
  );
}
