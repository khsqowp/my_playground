"use client";

import { useState, useEffect, useCallback } from "react";
import { MemoInput } from "@/components/data/MemoInput";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Pin, PinOff, Trash2, Search } from "lucide-react";
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

  const loadMemos = useCallback(async () => {
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    const res = await fetch(`/api/data/memo?${params}`);
    const data = await res.json();
    setMemos(data.memos);
  }, [search]);

  useEffect(() => { loadMemos(); }, [loadMemos]);

  async function togglePin(id: string, pinned: boolean) {
    await fetch("/api/data/memo", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, pinned: !pinned }),
    });
    loadMemos();
  }

  async function deleteMemo(id: string) {
    await fetch("/api/data/memo", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    toast.success("삭제되었습니다");
    loadMemos();
  }

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
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <p className="whitespace-pre-wrap text-sm">{memo.content}</p>
                  <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
                    {memo.categoryTag && <Badge variant="outline" className="text-xs">{memo.categoryTag}</Badge>}
                    <span>{formatDate(memo.createdAt)}</span>
                  </div>
                </div>
                <div className="flex gap-1">
                  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => togglePin(memo.id, memo.pinned)}>
                    {memo.pinned ? <PinOff className="h-3 w-3" /> : <Pin className="h-3 w-3" />}
                  </Button>
                  <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => deleteMemo(memo.id)}>
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
