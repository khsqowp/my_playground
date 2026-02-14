"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Plus, BookOpen } from "lucide-react";
import { toast } from "sonner";

interface Series {
  id: string;
  name: string;
  description: string | null;
  _count: { posts: number };
}

export default function SeriesPage() {
  const [seriesList, setSeriesList] = useState<Series[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [open, setOpen] = useState(false);

  useEffect(() => {
    fetch("/api/blog?_series=true")
      .then((r) => r.json())
      .then((data) => {
        if (data.series) setSeriesList(data.series);
      });
  }, []);

  async function handleCreate() {
    if (!name.trim()) return;
    try {
      const res = await fetch("/api/blog", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ _createSeries: true, name, description }),
      });
      if (!res.ok) throw new Error();
      const created = await res.json();
      setSeriesList((prev) => [...prev, { ...created, _count: { posts: 0 } }]);
      setName("");
      setDescription("");
      setOpen(false);
      toast.success("시리즈가 생성되었습니다");
    } catch {
      toast.error("시리즈 생성에 실패했습니다");
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">시리즈</h1>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button><Plus className="mr-2 h-4 w-4" />새 시리즈</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>시리즈 생성</DialogTitle></DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>이름</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="시리즈 이름" />
              </div>
              <div className="space-y-2">
                <Label>설명</Label>
                <Textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="선택적 설명" />
              </div>
              <Button onClick={handleCreate} className="w-full">생성</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {seriesList.map((s) => (
          <Card key={s.id}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BookOpen className="h-4 w-4" />
                {s.name}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {s.description && <p className="text-sm text-muted-foreground mb-2">{s.description}</p>}
              <p className="text-sm">{s._count.posts}개 글</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
