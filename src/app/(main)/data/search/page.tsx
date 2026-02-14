"use client";

import { useState } from "react";
import Link from "next/link";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Search, FileText, BookOpen, StickyNote } from "lucide-react";
import { truncate } from "@/lib/utils";

export default function DataSearchPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<{
    posts: { id: string; title: string; slug: string }[];
    notes: { id: string; title: string }[];
    memos: { id: string; content: string }[];
  }>({ posts: [], notes: [], memos: [] });
  const [searched, setSearched] = useState(false);

  async function handleSearch() {
    if (!query.trim()) return;
    setSearched(true);
    const res = await fetch(`/api/data/search?q=${encodeURIComponent(query)}`);
    setResults(await res.json());
  }

  const total = results.posts.length + results.notes.length + results.memos.length;

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <h1 className="text-2xl font-bold">통합 검색</h1>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          className="pl-10"
          placeholder="모든 데이터에서 검색..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSearch()}
        />
      </div>

      {searched && (
        <div className="space-y-6">
          <p className="text-sm text-muted-foreground">{total}개 결과</p>

          {results.posts.length > 0 && (
            <Card>
              <CardHeader><CardTitle className="text-base flex items-center gap-2"><FileText className="h-4 w-4" />글</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {results.posts.map((p) => (
                  <Link key={p.id} href={`/blog/${p.slug}`} className="block rounded px-3 py-2 hover:bg-accent text-sm">{p.title}</Link>
                ))}
              </CardContent>
            </Card>
          )}

          {results.notes.length > 0 && (
            <Card>
              <CardHeader><CardTitle className="text-base flex items-center gap-2"><BookOpen className="h-4 w-4" />노트</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {results.notes.map((n) => (
                  <Link key={n.id} href={`/archive/notes/${n.id}`} className="block rounded px-3 py-2 hover:bg-accent text-sm">{n.title}</Link>
                ))}
              </CardContent>
            </Card>
          )}

          {results.memos.length > 0 && (
            <Card>
              <CardHeader><CardTitle className="text-base flex items-center gap-2"><StickyNote className="h-4 w-4" />메모</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {results.memos.map((m) => (
                  <div key={m.id} className="rounded px-3 py-2 hover:bg-accent text-sm">{truncate(m.content, 100)}</div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
