"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, Trash2, ExternalLink as LinkIcon, GripVertical } from "lucide-react";
import { toast } from "sonner";

interface Link {
  id: string;
  title: string;
  url: string;
  icon: string | null;
  order: number;
}

export default function LinksPage() {
  const [links, setLinks] = useState<Link[]>([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [url, setUrl] = useState("");
  const [icon, setIcon] = useState("");

  useEffect(() => { loadLinks(); }, []);

  async function loadLinks() {
    const res = await fetch("/api/links");
    if (res.ok) setLinks(await res.json());
  }

  async function create() {
    if (!title || !url) return;
    await fetch("/api/links", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, url, icon: icon || null }),
    });
    toast.success("링크가 추가되었습니다");
    setDialogOpen(false);
    setTitle("");
    setUrl("");
    setIcon("");
    loadLinks();
  }

  async function remove(id: string) {
    await fetch(`/api/links/${id}`, { method: "DELETE" });
    toast.success("삭제되었습니다");
    loadLinks();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">외부 링크</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild><Button><Plus className="mr-2 h-4 w-4" />링크 추가</Button></DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>외부 링크 추가</DialogTitle></DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2"><Label>제목</Label><Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="GitHub" /></div>
              <div className="space-y-2"><Label>URL</Label><Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com" /></div>
              <div className="space-y-2"><Label>아이콘 이름 (선택사항)</Label><Input value={icon} onChange={(e) => setIcon(e.target.value)} placeholder="github" /></div>
              <Button onClick={create} className="w-full">추가</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {links.map((link) => (
          <Card key={link.id} className="group">
            <CardContent className="flex items-center justify-between p-4">
              <a href={link.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-3 flex-1 min-w-0">
                <LinkIcon className="h-5 w-5 shrink-0 text-muted-foreground" />
                <div className="min-w-0">
                  <p className="font-medium truncate">{link.title}</p>
                  <p className="text-xs text-muted-foreground truncate">{link.url}</p>
                </div>
              </a>
              <Button variant="ghost" size="icon" className="opacity-0 group-hover:opacity-100 shrink-0 text-destructive" onClick={() => remove(link.id)}>
                <Trash2 className="h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        ))}
        {links.length === 0 && <p className="text-muted-foreground col-span-full text-center py-8">외부 링크가 없습니다</p>}
      </div>
    </div>
  );
}
