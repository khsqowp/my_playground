"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Plus, Trash2, Brain, Star, Tag, MessageSquare, Key } from "lucide-react";
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

  useEffect(() => {
    loadConfigs();
    loadPrompts();
  }, []);

  async function loadConfigs() {
    const res = await fetch("/api/automation/ai");
    if (res.ok) setConfigs(await res.json());
  }

  async function loadPrompts() {
    const res = await fetch("/api/automation/ai/prompts");
    if (res.ok) setPrompts(await res.json());
  }

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

  async function createPrompt() {
    if (!pTitle || !pContent) return;
    await fetch("/api/automation/ai/prompts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: pTitle, content: pContent, tags: pTags }),
    });
    toast.success("프롬프트가 저장되었습니다");
    setPromptDialogOpen(false);
    setPTitle("");
    setPContent("");
    setPTags("");
    loadPrompts();
  }

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
          <div className="flex justify-end">
            <Dialog open={promptDialogOpen} onOpenChange={setPromptDialogOpen}>
              <DialogTrigger asChild><Button><Plus className="mr-2 h-4 w-4" />새 프롬프트</Button></DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader><DialogTitle>프롬프트 생성</DialogTitle></DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2"><Label>제목</Label><Input value={pTitle} onChange={(e) => setPTitle(e.target.value)} placeholder="예: 블로그 글 요약용" /></div>
                  <div className="space-y-2"><Label>태그</Label><Input value={pTags} onChange={(e) => setPTags(e.target.value)} placeholder="블로그, 요약, SEO (쉼표로 구분)" /></div>
                  <div className="space-y-2">
                    <Label>프롬프트 내용</Label>
                    <Textarea value={pContent} onChange={(e) => setPContent(e.target.value)} className="min-h-[200px]" placeholder="여기에 프롬프트를 입력하세요..." />
                  </div>
                  <Button onClick={createPrompt} className="w-full">저장</Button>
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
                    <Button variant="ghost" size="icon" className="text-destructive h-8 w-8" onClick={() => removePrompt(p.id)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
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
