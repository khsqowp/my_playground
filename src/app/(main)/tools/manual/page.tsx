"use client";

import { useEffect, useMemo, useState } from "react";
import { Activity, ClipboardCopy, Plus, Radar, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";

type StoredRecord<T> = {
  id: string;
  createdAt: string;
  updatedAt: string;
  data: T;
};

type ManualSession = {
  kind: "manual-session";
  ownerId: string;
  title: string;
  target: string;
  scope: string;
  status: "ACTIVE" | "PAUSED" | "CLOSED";
  callbackToken: string;
  createdAt: string;
  updatedAt: string;
};

type OobCallback = {
  kind: "oob-callback";
  token: string;
  sessionRecordId: string | null;
  method: string;
  path: string;
  params: Record<string, string>;
  body: unknown;
  ip: string;
  userAgent: string | null;
  createdAt: string;
};

export default function ManualSecurityPage() {
  const [sessions, setSessions] = useState<StoredRecord<ManualSession>[]>([]);
  const [callbacks, setCallbacks] = useState<StoredRecord<OobCallback>[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [origin, setOrigin] = useState("");
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({ title: "", target: "", scope: "" });

  const selectedSession = useMemo(
    () => sessions.find((item) => item.id === selectedSessionId) || sessions[0],
    [selectedSessionId, sessions]
  );

  const callbackUrl = selectedSession
    ? `${origin}/api/hooks/manual/${selectedSession.data.callbackToken}`
    : "";

  async function loadSessions() {
    const res = await fetch("/api/tools/manual/sessions");
    if (!res.ok) throw new Error("세션 목록을 불러오지 못했습니다.");
    const data = await res.json();
    setSessions(data.sessions || []);
    if (!selectedSessionId && data.sessions?.[0]?.id) setSelectedSessionId(data.sessions[0].id);
  }

  async function loadCallbacks(sessionId = selectedSession?.id) {
    const query = sessionId ? `?sessionId=${encodeURIComponent(sessionId)}` : "";
    const res = await fetch(`/api/tools/manual/oob${query}`);
    if (!res.ok) throw new Error("OOB 로그를 불러오지 못했습니다.");
    const data = await res.json();
    setCallbacks(data.callbacks || []);
  }

  useEffect(() => {
    setOrigin(window.location.origin);
    loadSessions().catch((error) => toast.error(error.message));
  }, []);

  useEffect(() => {
    if (!selectedSession?.id) return;
    loadCallbacks(selectedSession.id).catch((error) => toast.error(error.message));
    const interval = setInterval(() => {
      loadCallbacks(selectedSession.id).catch(() => undefined);
    }, 5000);
    return () => clearInterval(interval);
  }, [selectedSession?.id]);

  async function createSession() {
    if (!form.title.trim() || !form.target.trim()) {
      toast.error("진단명과 대상을 입력해주세요.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/tools/manual/sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "세션 생성 실패");
      setForm({ title: "", target: "", scope: "" });
      await loadSessions();
      setSelectedSessionId(data.session.id);
      toast.success("수동 진단 세션을 만들었습니다.");
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function copy(text: string) {
    await navigator.clipboard.writeText(text);
    toast.success("복사되었습니다.");
  }

  return (
    <div className="space-y-6 pb-10">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Manual Security Workspace</h1>
          <p className="mt-1 text-muted-foreground">
            수동 진단 세션, OOB 증거, 페이로드와 정찰 기록을 한 곳에서 관리합니다.
          </p>
        </div>
        <Badge variant="outline" className="w-fit gap-2">
          <ShieldCheck className="h-4 w-4" />
          Manual-first
        </Badge>
      </div>

      <Tabs defaultValue="oob" className="space-y-4">
        <TabsList>
          <TabsTrigger value="oob">OOB Center</TabsTrigger>
          <TabsTrigger value="payloads">Payload Lab</TabsTrigger>
          <TabsTrigger value="archive">Security Archive</TabsTrigger>
          <TabsTrigger value="recon">Recon Notes</TabsTrigger>
        </TabsList>

        <TabsContent value="oob" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-[360px_1fr]">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Plus className="h-5 w-5" />
                  진단 세션
                </CardTitle>
                <CardDescription>허가된 대상과 범위를 세션 단위로 기록합니다.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>진단명</Label>
                  <Input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
                </div>
                <div className="space-y-2">
                  <Label>대상</Label>
                  <Input
                    placeholder="https://example.com 또는 내부 자산명"
                    value={form.target}
                    onChange={(e) => setForm({ ...form, target: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>허가 범위/메모</Label>
                  <Textarea
                    className="min-h-28"
                    value={form.scope}
                    onChange={(e) => setForm({ ...form, scope: e.target.value })}
                  />
                </div>
                <Button className="w-full" onClick={createSession} disabled={loading}>
                  세션 만들기
                </Button>
                <Separator />
                <ScrollArea className="h-60">
                  <div className="space-y-2 pr-3">
                    {sessions.map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => setSelectedSessionId(item.id)}
                        className={`w-full rounded-md border p-3 text-left transition-colors ${
                          selectedSession?.id === item.id ? "border-primary bg-primary/5" : "hover:bg-muted"
                        }`}
                      >
                        <div className="font-medium">{item.data.title}</div>
                        <div className="mt-1 truncate text-xs text-muted-foreground">{item.data.target}</div>
                      </button>
                    ))}
                    {sessions.length === 0 && (
                      <p className="py-8 text-center text-sm text-muted-foreground">아직 세션이 없습니다.</p>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            <div className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Radar className="h-5 w-5" />
                    Callback Endpoint
                  </CardTitle>
                  <CardDescription>Blind SSRF, XXE, SSTI 등에서 수신 증거를 세션에 연결합니다.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {selectedSession ? (
                    <>
                      <div className="rounded-md border bg-muted/40 p-3 font-mono text-xs break-all">{callbackUrl}</div>
                      <Button variant="outline" onClick={() => copy(callbackUrl)}>
                        <ClipboardCopy className="mr-2 h-4 w-4" />
                        URL 복사
                      </Button>
                    </>
                  ) : (
                    <p className="text-sm text-muted-foreground">먼저 진단 세션을 생성하세요.</p>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="h-5 w-5" />
                    OOB Evidence
                  </CardTitle>
                  <CardDescription>5초마다 갱신됩니다.</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[420px]">
                    <div className="space-y-3 pr-3">
                      {callbacks.map((item) => (
                        <div key={item.id} className="rounded-md border p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge variant="secondary">{item.data.method}</Badge>
                            <span className="font-mono text-xs text-muted-foreground">
                              {new Date(item.data.createdAt).toLocaleString()}
                            </span>
                            <span className="font-mono text-xs">{item.data.ip}</span>
                          </div>
                          <div className="mt-2 break-all font-mono text-xs">{item.data.path}</div>
                          <pre className="mt-2 max-h-32 overflow-auto rounded bg-muted p-2 text-xs">
                            {JSON.stringify(
                              { params: item.data.params, body: item.data.body, userAgent: item.data.userAgent },
                              null,
                              2
                            )}
                          </pre>
                        </div>
                      ))}
                      {callbacks.length === 0 && (
                        <p className="py-16 text-center text-sm text-muted-foreground">수신된 OOB 로그가 없습니다.</p>
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="payloads">
          <Card>
            <CardHeader>
              <CardTitle>Payload Lab</CardTitle>
              <CardDescription>다음 단계에서 구현됩니다.</CardDescription>
            </CardHeader>
          </Card>
        </TabsContent>

        <TabsContent value="archive">
          <Card>
            <CardHeader>
              <CardTitle>Security Archive</CardTitle>
              <CardDescription>다음 단계에서 구현됩니다.</CardDescription>
            </CardHeader>
          </Card>
        </TabsContent>

        <TabsContent value="recon">
          <Card>
            <CardHeader>
              <CardTitle>Recon Notes</CardTitle>
              <CardDescription>다음 단계에서 구현됩니다.</CardDescription>
            </CardHeader>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
