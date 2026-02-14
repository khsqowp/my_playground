"use client";

import { useState } from "react";
import Link from "next/link";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent } from "@/components/ui/card";
import { Search, BookOpen, HelpCircle } from "lucide-react";

interface Result {
  id: string;
  title: string;
  type: string;
}

export default function ArchiveSearchPage() {
  const [query, setQuery] = useState("");
  const [notes, setNotes] = useState<Result[]>([]);
  const [quizzes, setQuizzes] = useState<Result[]>([]);
  const [searched, setSearched] = useState(false);

  async function handleSearch() {
    if (!query.trim()) return;
    setSearched(true);

    const [notesRes, quizRes] = await Promise.all([
      fetch(`/api/archive/notes?search=${encodeURIComponent(query)}`).then((r) => r.json()),
      fetch(`/api/archive/quiz?search=${encodeURIComponent(query)}`).then((r) => r.json()),
    ]);

    setNotes((notesRes.notes || []).map((n: { id: string; title: string }) => ({ ...n, type: "note" })));
    setQuizzes((quizRes || []).map((q: { id: string; title: string }) => ({ ...q, type: "quiz" })));
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <h1 className="text-2xl font-bold">아카이브 검색</h1>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            className="pl-10"
            placeholder="노트와 퀴즈 검색..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
          />
        </div>
      </div>

      {searched && (
        <Tabs defaultValue="all">
          <TabsList>
            <TabsTrigger value="all">전체 ({notes.length + quizzes.length})</TabsTrigger>
            <TabsTrigger value="notes">노트 ({notes.length})</TabsTrigger>
            <TabsTrigger value="quiz">퀴즈 ({quizzes.length})</TabsTrigger>
          </TabsList>
          <TabsContent value="all" className="space-y-2">
            {[...notes, ...quizzes].map((r) => (
              <ResultItem key={r.id} result={r} />
            ))}
            {notes.length + quizzes.length === 0 && <p className="text-muted-foreground py-4">검색 결과가 없습니다</p>}
          </TabsContent>
          <TabsContent value="notes" className="space-y-2">
            {notes.map((r) => (<ResultItem key={r.id} result={r} />))}
          </TabsContent>
          <TabsContent value="quiz" className="space-y-2">
            {quizzes.map((r) => (<ResultItem key={r.id} result={r} />))}
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}

function ResultItem({ result }: { result: Result }) {
  const href = result.type === "note" ? `/archive/notes/${result.id}` : `/archive/quiz/${result.id}`;
  const Icon = result.type === "note" ? BookOpen : HelpCircle;
  return (
    <Link href={href}>
      <Card className="hover:shadow-sm transition-shadow">
        <CardContent className="flex items-center gap-3 p-4">
          <Icon className="h-4 w-4 text-muted-foreground" />
          <span>{result.title}</span>
        </CardContent>
      </Card>
    </Link>
  );
}
