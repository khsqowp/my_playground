"use client";

import { useState, useEffect, useCallback } from "react";
import { MemoInput } from "@/components/data/MemoInput";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Pin, PinOff, Trash2, Search, Pencil, X, Check, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { formatDate } from "@/lib/utils";

interface Memo {
  id: string;
  content: string;
  categoryTag: string | null;
  pinned: boolean;
  createdAt: string;
}

export default function MemoPage() {
  const [memos, setMemos] = useState<Memo[]>([]);
  const [search, setSearch] = useState("");
  
  // Editing state
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editContent, setEditContent] = useState("");
  const [editTag, setEditTag] = useState("");
  const [saving, setSaving] = useState(false);

  const loadMemos = useCallback(async () => {
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    const res = await fetch(`/api/data/memo?${params}`);
    const data = await res.json();
    setMemos(data.memos);
  }, [search]);

  useEffect(() => { loadMemos(); }, [loadMemos]);

  async function togglePin(id: string, pinned: boolean) {
    try {
      const res = await fetch("/api/data/memo", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, pinned: !pinned }),
      });
      if (!res.ok) throw new Error();
      loadMemos();
    } catch {
      toast.error("고정 상태 변경 실패");
    }
  }

  async function deleteMemo(id: string) {
    if (!confirm("이 메모를 삭제하시겠습니까?")) return;
    try {
      const res = await fetch("/api/data/memo", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      if (!res.ok) throw new Error();
      toast.success("삭제되었습니다");
      loadMemos();
    } catch {
      toast.error("삭제 실패");
    }
  }

  const startEditing = (memo: Memo) => {
    setEditingId(memo.id);
    setEditContent(memo.content);
    setEditTag(memo.categoryTag || "");
  };

  const cancelEditing = () => {
    setEditingId(null);
    setEditContent("");
    setEditTag("");
  };

  const saveEdit = async () => {
    if (!editContent.trim()) return;
    setSaving(true);
    try {
      const res = await fetch("/api/data/memo", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          id: editingId, 
          content: editContent, 
          categoryTag: editTag || null 
        }),
      });
      if (!res.ok) throw new Error();
      toast.success("메모가 수정되었습니다");
      setEditingId(null);
      loadMemos();
    } catch {
      toast.error("수정 실패");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <h1 className="text-2xl font-bold">메모</h1>
      <MemoInput onSaved={loadMemos} />

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input className="pl-10" placeholder="메모 검색..." value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>

      <div className="space-y-3">
        {memos.map((memo) => (
          <Card key={memo.id} className={memo.pinned ? "border-primary/50" : ""}>
            <CardContent className="p-4">
              {editingId === memo.id ? (
                <div className="space-y-3">
                  <Textarea 
                    value={editContent} 
                    onChange={(e) => setEditContent(e.target.value)}
                    className="min-h-[100px] text-sm"
                    autoFocus
                  />
                  <div className="flex items-center gap-2">
                    <Input 
                      placeholder="태그" 
                      value={editTag} 
                      onChange={(e) => setEditTag(e.target.value)}
                      className="text-sm h-8"
                    />
                    <div className="flex gap-1 ml-auto">
                      <Button size="sm" variant="ghost" onClick={cancelEditing} disabled={saving}>
                        <X className="h-4 w-4 mr-1" /> 취소
                      </Button>
                      <Button size="sm" onClick={saveEdit} disabled={saving || !editContent.trim()}>
                        {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4 mr-1" />}
                        저장
                      </Button>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <p className="whitespace-pre-wrap text-sm">{memo.content}</p>
                    <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
                      {memo.categoryTag && <Badge variant="outline" className="text-[10px]">{memo.categoryTag}</Badge>}
                      <span>{formatDate(memo.createdAt)}</span>
                    </div>
                  </div>
                  <div className="flex gap-1">
                    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => togglePin(memo.id, memo.pinned)}>
                      {memo.pinned ? <PinOff className="h-3 w-3" /> : <Pin className="h-3 w-3" />}
                    </Button>
                    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => startEditing(memo)}>
                      <Pencil className="h-3 w-3" />
                    </Button>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => deleteMemo(memo.id)}>
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
