"use client";

import { useState, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Plus, Trash2, Brain, Star, MessageSquare, Search, Pencil, Wand2, Loader2 } from "lucide-react";
import { toast } from "sonner";

interface AiConfig {
  id: string;
  provider: string;
  apiKey: string;
  model: string;
  isDefault: boolean;
}

interface AiPrompt {
  id: string;
  title: string;
  content: string;
  tags: string | null;
  createdAt: string;
}

export default function AiSettingsPage() {
  const [configs, setConfigs] = useState<AiConfig[]>([]);
  const [prompts, setPrompts] = useState<AiPrompt[]>([]);

  // Config State
  const [confDialogOpen, setConfDialogOpen] = useState(false);
  const [provider, setProvider] = useState("openai");
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("");
  const [isDefault, setIsDefault] = useState(false);

  // Prompt State
  const [promptDialogOpen, setPromptDialogOpen] = useState(false);
  const [pTitle, setPTitle] = useState("");
  const [pContent, setPContent] = useState("");
  const [pTags, setPTags] = useState("");
  const [editingPromptId, setEditingPromptId] = useState<string | null>(null);
  const [promptQuery, setPromptQuery] = useState("");
  const [appliedPromptQuery, setAppliedPromptQuery] = useState("");
  const [isTagging, setIsTagging] = useState(false);
  const [isSavingPrompt, setIsSavingPrompt] = useState(false);
  const [isSearching, setIsSearching] = useState(false);

  const loadConfigs = useCallback(async () => {
    const res = await fetch("/api/automation/ai");
    if (res.ok) setConfigs(await res.json());
  }, []);

  const loadPrompts = useCallback(async () => {
    setIsSearching(true);
    try {
      const query = appliedPromptQuery.trim();
      const url = query
        ? `/api/automation/ai/prompts?q=${encodeURIComponent(query)}`
        : "/api/automation/ai/prompts";
      const res = await fetch(url);
      if (res.ok) setPrompts(await res.json());
    } finally {
      setIsSearching(false);
    }
  }, [appliedPromptQuery]);

  useEffect(() => {
    loadConfigs();
    loadPrompts();
  }, [loadConfigs, loadPrompts]);

  async function createConfig() {
    if (!apiKey || !model) return;
    await fetch("/api/automation/ai", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, apiKey, model, isDefault }),
    });
    toast.success("AI 설정이 저장되었습니다");
    setConfDialogOpen(false);
    setApiKey("");
    setModel("");
    loadConfigs();
  }

  async function removeConfig(id: string) {
    if (!confirm("삭제하시겠습니까?")) return;
    await fetch("/api/automation/ai", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    loadConfigs();
  }

  function normalizeTags(input: string): string[] {
    return Array.from(
      new Set(
        input
          .split(/[,#\n]/g)
          .map((s) => s.trim())
          .filter(Boolean)
      )
    );
  }

  async function autoGenerateTags() {
    setIsTagging(true);
    try {
      const text = `${pTitle}\n${pContent}`.trim() || "새로운 AI 프롬프트 템플릿";
      const res = await fetch("/api/automation/ai/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, type: "tagging" }),
      });
      if (!res.ok) throw new Error("태그 생성 실패");
      const data = await res.json();
      const tagsFromAi = Array.isArray(data.tags) ? data.tags.map((t: string) => t.trim()).filter(Boolean) : [];
      const merged = normalizeTags([pTags, ...tagsFromAi].join(", "));
      const fallback = ["AI", "프롬프트", "자동화", "업무", "템플릿"];
      for (const t of fallback) {
        if (!merged.includes(t)) merged.push(t);
        if (merged.length >= 5) break;
      }
      setPTags(merged.slice(0, 5).join(", "));
      toast.success("태그 5개를 자동 생성했습니다");
    } catch {
      toast.error("AI 태그 생성에 실패했습니다");
    } finally {
      setIsTagging(false);
    }
  }

  async function savePrompt() {
    if (!pTitle || !pContent) {
      toast.error("제목과 내용을 입력해주세요.");
      return;
    }
    setIsSavingPrompt(true);
    try {
      const method = editingPromptId ? "PUT" : "POST";
      const payload: any = { title: pTitle, content: pContent, tags: pTags };
      if (editingPromptId) payload.id = editingPromptId;

      const res = await fetch("/api/automation/ai/prompts", {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "저장 실패");
      }

      toast.success(editingPromptId ? "프롬프트가 수정되었습니다" : "프롬프트가 저장되었습니다");
      setPromptDialogOpen(false);
      setEditingPromptId(null);
      setPTitle("");
      setPContent("");
      setPTags("");
      loadPrompts();
    } catch (error: any) {
      toast.error(error.message || "오류가 발생했습니다.");
    } finally {
      setIsSavingPrompt(false);
    }
  }

  function openCreatePrompt() {
    setEditingPromptId(null);
    setPTitle("");
    setPContent("");
    setPTags("");
    setPromptDialogOpen(true);
  }

  function openEditPrompt(prompt: AiPrompt) {
    setEditingPromptId(prompt.id);
    setPTitle(prompt.title);
    setPContent(prompt.content);
    setPTags(prompt.tags || "");
    setPromptDialogOpen(true);
  }

  async function handlePromptSearch() {
    setAppliedPromptQuery(promptQuery.trim());
  }

  useEffect(() => {
    if (promptDialogOpen && !editingPromptId && !pTags.trim()) {
      autoGenerateTags();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [promptDialogOpen, editingPromptId]);

  async function removePrompt(id: string) {
    if (!confirm("삭제하시겠습니까?")) return;
    await fetch("/api/automation/ai/prompts", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    loadPrompts();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">AI 스튜디오</h1>
      </div>

      <Tabs defaultValue="prompts" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="prompts">프롬프트 라이브러리</TabsTrigger>
          <TabsTrigger value="settings">연동 설정</TabsTrigger>
        </TabsList>

        {/* Prompts Tab */}
        <TabsContent value="prompts" className="space-y-4 mt-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex w-full sm:max-w-md gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  className="pl-9"
                  value={promptQuery}
                  onChange={(e) => setPromptQuery(e.target.value)}
                  placeholder="제목/내용/태그 검색"
                  onKeyDown={(e) => e.key === "Enter" && handlePromptSearch()}
                />
              </div>
              <Button variant="outline" onClick={handlePromptSearch} disabled={isSearching}>
                {isSearching ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Search className="h-4 w-4 mr-1" />}
                검색
              </Button>
            </div>
            <Dialog open={promptDialogOpen} onOpenChange={setPromptDialogOpen}>
              <Button onClick={openCreatePrompt}>
                <Plus className="mr-2 h-4 w-4" />새 프롬프트
              </Button>
              <DialogContent className="max-w-2xl">
                <DialogHeader><DialogTitle>{editingPromptId ? "프롬프트 수정" : "프롬프트 생성"}</DialogTitle></DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2"><Label>제목</Label><Input value={pTitle} onChange={(e) => setPTitle(e.target.value)} placeholder="예: 블로그 글 요약용" /></div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label>태그</Label>
                      <Button type="button" variant="outline" size="sm" onClick={autoGenerateTags} disabled={isTagging}>
                        {isTagging ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Wand2 className="h-3.5 w-3.5 mr-1" />}
                        AI 태그 5개
                      </Button>
                    </div>
                    <Input value={pTags} onChange={(e) => setPTags(e.target.value)} placeholder="블로그, 요약, SEO (쉼표로 구분)" />
                  </div>
                  <div className="space-y-2">
                    <Label>프롬프트 내용</Label>
                    <Textarea value={pContent} onChange={(e) => setPContent(e.target.value)} className="min-h-[200px]" placeholder="여기에 프롬프트를 입력하세요..." />
                  </div>
                  <Button onClick={savePrompt} className="w-full" disabled={isSavingPrompt}>
                    {isSavingPrompt ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                    {editingPromptId ? "수정 저장" : "저장"}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {prompts.map((p) => (
              <Card key={p.id} className="flex flex-col">
                <CardHeader>
                  <div className="flex justify-between items-start">
                    <CardTitle className="text-lg">{p.title}</CardTitle>
                    <div className="flex items-center gap-1">
                      <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => openEditPrompt(p)}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="icon" className="text-destructive h-8 w-8" onClick={() => removePrompt(p.id)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {p.tags?.split(',').map(tag => (
                      <Badge key={tag} variant="secondary" className="text-xs">{tag.trim()}</Badge>
                    ))}
                  </div>
                </CardHeader>
                <CardContent className="flex-1">
                  <div className="bg-muted p-3 rounded-md text-sm font-mono whitespace-pre-wrap max-h-[150px] overflow-y-auto">
                    {p.content}
                  </div>
                </CardContent>
              </Card>
            ))}
            {prompts.length === 0 && (
              <div className="col-span-full text-center py-12 text-muted-foreground">
                <MessageSquare className="mx-auto h-12 w-12 opacity-20 mb-3" />
                <p>저장된 프롬프트가 없습니다</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* Settings Tab */}
        <TabsContent value="settings" className="space-y-4 mt-4">
          <div className="flex justify-end">
            <Dialog open={confDialogOpen} onOpenChange={setConfDialogOpen}>
              <DialogTrigger asChild><Button variant="outline"><Plus className="mr-2 h-4 w-4" />제공자 추가</Button></DialogTrigger>
              <DialogContent>
                <DialogHeader><DialogTitle>AI 제공자 추가</DialogTitle></DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>제공자</Label>
                    <Select value={provider} onValueChange={setProvider}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="openai">OpenAI</SelectItem>
                        <SelectItem value="anthropic">Anthropic</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2"><Label>API 키</Label><Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} /></div>
                  <div className="space-y-2"><Label>모델</Label><Input value={model} onChange={(e) => setModel(e.target.value)} placeholder="gpt-4" /></div>
                  <div className="flex items-center gap-2"><Switch checked={isDefault} onCheckedChange={setIsDefault} /><Label>기본값으로 설정</Label></div>
                  <Button onClick={createConfig} className="w-full">저장</Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <div className="space-y-3">
            {configs.map((c) => (
              <Card key={c.id}>
                <CardContent className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3">
                    <Brain className="h-5 w-5" />
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium capitalize">{c.provider}</p>
                        {c.isDefault && <Star className="h-3 w-3 text-yellow-500 fill-yellow-500" />}
                      </div>
                      <p className="text-sm text-muted-foreground">{c.model}</p>
                    </div>
                    <Badge variant="outline" className="font-mono">••••••••</Badge>
                  </div>
                  <Button variant="ghost" size="icon" className="text-destructive" onClick={() => removeConfig(c.id)}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </CardContent>
              </Card>
            ))}
            {configs.length === 0 && <p className="text-muted-foreground text-center py-8">설정된 AI 제공자가 없습니다</p>}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
