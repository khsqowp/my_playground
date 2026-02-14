"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Plus, Trash2, Webhook, Copy, ArrowRight, ArrowLeft } from "lucide-react";
import { toast } from "sonner";

interface WebhookConfig {
  id: string;
  name: string;
  platform: string;
  url: string;
  enabled: boolean;
  _count?: { logs: number };
}

interface IncomingWebhook {
  id: string;
  name: string;
  slug: string;
  enabled: boolean;
  _count?: { logs: number };
}

export default function WebhooksPage() {
  const [outgoingWebhooks, setOutgoingWebhooks] = useState<WebhookConfig[]>([]);
  const [incomingWebhooks, setIncomingWebhooks] = useState<IncomingWebhook[]>([]);

  // Outgoing State
  const [outDialogOpen, setOutDialogOpen] = useState(false);
  const [outName, setOutName] = useState("");
  const [outPlatform, setOutPlatform] = useState("DISCORD");
  const [outUrl, setOutUrl] = useState("");

  // Incoming State
  const [inDialogOpen, setInDialogOpen] = useState(false);
  const [inName, setInName] = useState("");

  useEffect(() => {
    loadOutgoing();
    loadIncoming();
  }, []);

  async function loadOutgoing() {
    const res = await fetch("/api/automation/webhooks");
    if (res.ok) setOutgoingWebhooks(await res.json());
  }

  async function loadIncoming() {
    const res = await fetch("/api/automation/incoming");
    if (res.ok) setIncomingWebhooks(await res.json());
  }

  async function createOutgoing() {
    if (!outName || !outUrl) return;
    await fetch("/api/automation/webhooks", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: outName, platform: outPlatform, url: outUrl }),
    });
    toast.success("웹훅이 생성되었습니다");
    setOutDialogOpen(false);
    setOutName("");
    setOutUrl("");
    loadOutgoing();
  }

  async function createIncoming() {
    if (!inName) return;
    await fetch("/api/automation/incoming", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: inName }),
    });
    toast.success("수신 웹훅이 생성되었습니다");
    setInDialogOpen(false);
    setInName("");
    loadIncoming();
  }

  async function toggleOutgoing(id: string, enabled: boolean) {
    await fetch("/api/automation/webhooks", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, enabled: !enabled }),
    });
    loadOutgoing();
  }

  async function deleteOutgoing(id: string) {
    if (!confirm("삭제하시겠습니까?")) return;
    await fetch("/api/automation/webhooks", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    loadOutgoing();
  }

  function getIncomingUrl(slug: string) {
    if (typeof window === 'undefined') return '';
    return `${window.location.origin}/api/hooks/${slug}`;
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    toast.success("URL이 복사되었습니다");
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">웹훅 관리</h1>
      </div>

      <Tabs defaultValue="outgoing" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="outgoing">보내기 (Outgoing)</TabsTrigger>
          <TabsTrigger value="incoming">받기 (Incoming)</TabsTrigger>
        </TabsList>

        {/* Outgoing Tab */}
        <TabsContent value="outgoing" className="space-y-4 mt-4">
          <div className="flex justify-end">
            <Dialog open={outDialogOpen} onOpenChange={setOutDialogOpen}>
              <DialogTrigger asChild><Button><Plus className="mr-2 h-4 w-4" />웹훅 추가</Button></DialogTrigger>
              <DialogContent>
                <DialogHeader><DialogTitle>새 발신 웹훅</DialogTitle></DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2"><Label>이름</Label><Input value={outName} onChange={(e) => setOutName(e.target.value)} /></div>
                  <div className="space-y-2">
                    <Label>플랫폼</Label>
                    <Select value={outPlatform} onValueChange={setOutPlatform}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="DISCORD">Discord</SelectItem>
                        <SelectItem value="SLACK">Slack</SelectItem>
                        <SelectItem value="CUSTOM">Custom</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2"><Label>URL</Label><Input value={outUrl} onChange={(e) => setOutUrl(e.target.value)} /></div>
                  <Button onClick={createOutgoing} className="w-full">생성</Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <div className="space-y-3">
            {outgoingWebhooks.map((wh) => (
              <Card key={wh.id}>
                <CardContent className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3">
                    <ArrowRight className="h-5 w-5 text-blue-500" />
                    <div>
                      <p className="font-medium">{wh.name}</p>
                      <p className="text-xs text-muted-foreground truncate max-w-[300px]">{wh.url}</p>
                    </div>
                    <Badge variant="outline">{wh.platform}</Badge>
                  </div>
                  <div className="flex items-center gap-3">
                    <Switch checked={wh.enabled} onCheckedChange={() => toggleOutgoing(wh.id, wh.enabled)} />
                    <Button variant="ghost" size="icon" className="text-destructive" onClick={() => deleteOutgoing(wh.id)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
            {outgoingWebhooks.length === 0 && <p className="text-muted-foreground text-center py-8">설정된 발신 웹훅이 없습니다</p>}
          </div>
        </TabsContent>

        {/* Incoming Tab */}
        <TabsContent value="incoming" className="space-y-4 mt-4">
          <div className="flex justify-between items-center bg-muted/50 p-4 rounded-lg">
            <div className="text-sm text-muted-foreground">
              외부 서비스에서 내 서버로 이벤트를 보낼 때 사용합니다.
            </div>
            <Dialog open={inDialogOpen} onOpenChange={setInDialogOpen}>
              <DialogTrigger asChild><Button><Plus className="mr-2 h-4 w-4" />수신 웹훅 생성</Button></DialogTrigger>
              <DialogContent>
                <DialogHeader><DialogTitle>새 수신 웹훅</DialogTitle></DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>이름</Label>
                    <Input value={inName} onChange={(e) => setInName(e.target.value)} placeholder="예: Github Push 알림" />
                  </div>
                  <Button onClick={createIncoming} className="w-full">생성 및 URL 발급</Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <div className="space-y-3">
            {incomingWebhooks.map((wh) => (
              <Card key={wh.id}>
                <CardHeader className="pb-2">
                  <div className="flex justify-between items-start">
                    <div className="flex items-center gap-2">
                      <ArrowLeft className="h-5 w-5 text-green-500" />
                      <div>
                        <CardTitle className="text-base">{wh.name}</CardTitle>
                        <CardDescription className="text-xs">로그 {wh._count?.logs || 0}건</CardDescription>
                      </div>
                    </div>
                    {/* Incoming Delete/Toggle not implemented fully for brevity, can add later */}
                  </div>
                </CardHeader>
                <CardContent className="pb-4">
                  <div className="flex items-center gap-2 mt-2">
                    <Input readOnly value={getIncomingUrl(wh.slug)} className="font-mono text-xs bg-muted" />
                    <Button variant="outline" size="icon" onClick={() => copyToClipboard(getIncomingUrl(wh.slug))}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
            {incomingWebhooks.length === 0 && <p className="text-muted-foreground text-center py-8">설정된 수신 웹훅이 없습니다</p>}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
