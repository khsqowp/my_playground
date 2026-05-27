"use client";

import { useEffect, useMemo, useState } from "react";
import { Activity, Archive, ClipboardCopy, FlaskConical, Plus, Radar, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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

type PayloadRecord = {
  kind: "payload";
  ownerId: string;
  title: string;
  category: string;
  payload: string;
  context: string;
  expectedSignal: string;
  tags: string[];
  risk: "LOW" | "MEDIUM" | "HIGH";
  createdAt: string;
  updatedAt: string;
};

type ArchiveRule = {
  kind: "archive-rule";
  ownerId: string;
  name: string;
  folder: string;
  keywords: string[];
  extensions: string[];
  createdAt: string;
  updatedAt: string;
};

type ArchiveFileSuggestion = {
  id: string;
  fileName: string;
  extension: string;
  folder: string;
  aiSummary: string | null;
  aiTags: string | null;
  fileSize: number;
  updatedAt: string;
  suggestedRules: { id: string; name: string; folder: string }[];
};

const payloadCategories = ["sqli", "xss", "ssrf", "ssti", "lfi", "xxe", "cmdi", "auth", "recon", "other"];

export default function ManualSecurityPage() {
  const [sessions, setSessions] = useState<StoredRecord<ManualSession>[]>([]);
  const [callbacks, setCallbacks] = useState<StoredRecord<OobCallback>[]>([]);
  const [payloads, setPayloads] = useState<StoredRecord<PayloadRecord>[]>([]);
  const [archiveRules, setArchiveRules] = useState<StoredRecord<ArchiveRule>[]>([]);
  const [archiveFiles, setArchiveFiles] = useState<ArchiveFileSuggestion[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [origin, setOrigin] = useState("");
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({ title: "", target: "", scope: "" });
  const [payloadFilter, setPayloadFilter] = useState("all");
  const [payloadSearch, setPayloadSearch] = useState("");
  const [payloadForm, setPayloadForm] = useState({
    title: "",
    category: "sqli",
    risk: "MEDIUM",
    payload: "",
    context: "",
    expectedSignal: "",
    tags: "",
  });
  const [archiveRuleForm, setArchiveRuleForm] = useState({
    name: "",
    folder: "Security/Unsorted",
    keywords: "",
    extensions: "",
  });

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

  async function loadPayloads(category = payloadFilter, query = payloadSearch) {
    const params = new URLSearchParams();
    if (category) params.set("category", category);
    if (query.trim()) params.set("q", query.trim());
    const res = await fetch(`/api/tools/manual/payloads?${params.toString()}`);
    if (!res.ok) throw new Error("페이로드 목록을 불러오지 못했습니다.");
    const data = await res.json();
    setPayloads(data.payloads || []);
  }

  async function loadArchiveClassifier() {
    const res = await fetch("/api/tools/manual/archive");
    if (!res.ok) throw new Error("보안 아카이브 정보를 불러오지 못했습니다.");
    const data = await res.json();
    setArchiveRules(data.rules || []);
    setArchiveFiles(data.files || []);
  }

  useEffect(() => {
    setOrigin(window.location.origin);
    loadSessions().catch((error) => toast.error(error.message));
    loadPayloads().catch((error) => toast.error(error.message));
    loadArchiveClassifier().catch((error) => toast.error(error.message));
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

  async function createPayload() {
    if (!payloadForm.title.trim() || !payloadForm.payload.trim()) {
      toast.error("제목과 페이로드를 입력해주세요.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/tools/manual/payloads", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payloadForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "페이로드 저장 실패");
      setPayloadForm({
        title: "",
        category: payloadForm.category,
        risk: "MEDIUM",
        payload: "",
        context: "",
        expectedSignal: "",
        tags: "",
      });
      await loadPayloads();
      toast.success("페이로드를 저장했습니다.");
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function createArchiveRule() {
    if (!archiveRuleForm.name.trim() || !archiveRuleForm.folder.trim()) {
      toast.error("규칙명과 분류 폴더를 입력해주세요.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/tools/manual/archive", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(archiveRuleForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "분류 규칙 저장 실패");
      setArchiveRuleForm({ name: "", folder: archiveRuleForm.folder, keywords: "", extensions: "" });
      await loadArchiveClassifier();
      toast.success("분류 규칙을 저장했습니다.");
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function applyArchiveRule(fileId: string, ruleId: string) {
    setLoading(true);
    try {
      const res = await fetch("/api/tools/manual/archive", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fileId, ruleId }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "분류 적용 실패");
      await loadArchiveClassifier();
      toast.success("아카이브 파일을 분류했습니다.");
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
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
          <div className="grid gap-4 lg:grid-cols-[420px_1fr]">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FlaskConical className="h-5 w-5" />
                  Payload Lab
                </CardTitle>
                <CardDescription>수동 진단에 사용할 페이로드와 기대 신호를 기록합니다.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <Label>분류</Label>
                    <Select
                      value={payloadForm.category}
                      onValueChange={(value) => setPayloadForm({ ...payloadForm, category: value })}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {payloadCategories.map((category) => (
                          <SelectItem key={category} value={category}>{category.toUpperCase()}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>위험도</Label>
                    <Select
                      value={payloadForm.risk}
                      onValueChange={(value) => setPayloadForm({ ...payloadForm, risk: value })}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="LOW">LOW</SelectItem>
                        <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                        <SelectItem value="HIGH">HIGH</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>제목</Label>
                  <Input value={payloadForm.title} onChange={(e) => setPayloadForm({ ...payloadForm, title: e.target.value })} />
                </div>
                <div className="space-y-2">
                  <Label>Payload</Label>
                  <Textarea
                    className="min-h-32 font-mono text-xs"
                    value={payloadForm.payload}
                    onChange={(e) => setPayloadForm({ ...payloadForm, payload: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>사용 맥락</Label>
                  <Textarea
                    className="min-h-24"
                    placeholder="예: 검색 파라미터, JSON body, XML entity, template expression"
                    value={payloadForm.context}
                    onChange={(e) => setPayloadForm({ ...payloadForm, context: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>기대 신호</Label>
                  <Input
                    placeholder="응답 지연, DNS callback, 에러 문자열, DOM 반영 등"
                    value={payloadForm.expectedSignal}
                    onChange={(e) => setPayloadForm({ ...payloadForm, expectedSignal: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>태그</Label>
                  <Input
                    placeholder="blind,time-based,json"
                    value={payloadForm.tags}
                    onChange={(e) => setPayloadForm({ ...payloadForm, tags: e.target.value })}
                  />
                </div>
                <Button className="w-full" onClick={createPayload} disabled={loading}>
                  페이로드 저장
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Saved Payloads</CardTitle>
                <CardDescription>복사해서 수동 요청 도구나 프록시에 붙여 넣어 사용합니다.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 md:grid-cols-[180px_1fr_auto]">
                  <Select
                    value={payloadFilter}
                    onValueChange={(value) => {
                      setPayloadFilter(value);
                      loadPayloads(value, payloadSearch).catch((error) => toast.error(error.message));
                    }}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">ALL</SelectItem>
                      {payloadCategories.map((category) => (
                        <SelectItem key={category} value={category}>{category.toUpperCase()}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Input
                    placeholder="검색"
                    value={payloadSearch}
                    onChange={(e) => setPayloadSearch(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") loadPayloads().catch((error) => toast.error(error.message));
                    }}
                  />
                  <Button variant="outline" onClick={() => loadPayloads().catch((error) => toast.error(error.message))}>
                    검색
                  </Button>
                </div>
                <ScrollArea className="h-[620px]">
                  <div className="space-y-3 pr-3">
                    {payloads.map((item) => (
                      <div key={item.id} className="rounded-md border p-4">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div>
                            <div className="font-medium">{item.data.title}</div>
                            <div className="mt-1 flex flex-wrap gap-2">
                              <Badge variant="secondary">{item.data.category.toUpperCase()}</Badge>
                              <Badge variant={item.data.risk === "HIGH" ? "destructive" : "outline"}>{item.data.risk}</Badge>
                              {item.data.tags.map((tag) => (
                                <Badge key={tag} variant="outline">{tag}</Badge>
                              ))}
                            </div>
                          </div>
                          <Button variant="outline" size="sm" onClick={() => copy(item.data.payload)}>
                            <ClipboardCopy className="mr-2 h-4 w-4" />
                            복사
                          </Button>
                        </div>
                        <pre className="mt-3 max-h-36 overflow-auto rounded bg-muted p-3 text-xs">{item.data.payload}</pre>
                        {(item.data.context || item.data.expectedSignal) && (
                          <div className="mt-3 grid gap-2 text-sm md:grid-cols-2">
                            <div>
                              <div className="text-xs font-medium text-muted-foreground">Context</div>
                              <p className="whitespace-pre-wrap">{item.data.context || "-"}</p>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-muted-foreground">Expected Signal</div>
                              <p className="whitespace-pre-wrap">{item.data.expectedSignal || "-"}</p>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                    {payloads.length === 0 && (
                      <p className="py-16 text-center text-sm text-muted-foreground">저장된 페이로드가 없습니다.</p>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="archive">
          <div className="grid gap-4 lg:grid-cols-[380px_1fr]">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Archive className="h-5 w-5" />
                  분류 규칙
                </CardTitle>
                <CardDescription>업로드된 자료를 보안 주제별 폴더로 수동 분류합니다.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>규칙명</Label>
                  <Input
                    placeholder="SSRF 자료"
                    value={archiveRuleForm.name}
                    onChange={(e) => setArchiveRuleForm({ ...archiveRuleForm, name: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>분류 폴더</Label>
                  <Input
                    placeholder="Security/SSRF"
                    value={archiveRuleForm.folder}
                    onChange={(e) => setArchiveRuleForm({ ...archiveRuleForm, folder: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>키워드</Label>
                  <Input
                    placeholder="ssrf, metadata, 169.254.169.254"
                    value={archiveRuleForm.keywords}
                    onChange={(e) => setArchiveRuleForm({ ...archiveRuleForm, keywords: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>확장자</Label>
                  <Input
                    placeholder="pdf, md, txt"
                    value={archiveRuleForm.extensions}
                    onChange={(e) => setArchiveRuleForm({ ...archiveRuleForm, extensions: e.target.value })}
                  />
                </div>
                <Button className="w-full" onClick={createArchiveRule} disabled={loading}>
                  규칙 저장
                </Button>
                <Separator />
                <ScrollArea className="h-72">
                  <div className="space-y-2 pr-3">
                    {archiveRules.map((rule) => (
                      <div key={rule.id} className="rounded-md border p-3">
                        <div className="font-medium">{rule.data.name}</div>
                        <div className="mt-1 text-xs text-muted-foreground">{rule.data.folder}</div>
                        <div className="mt-2 flex flex-wrap gap-1">
                          {rule.data.keywords.map((keyword) => <Badge key={keyword} variant="outline">{keyword}</Badge>)}
                          {rule.data.extensions.map((ext) => <Badge key={ext} variant="secondary">.{ext}</Badge>)}
                        </div>
                      </div>
                    ))}
                    {archiveRules.length === 0 && (
                      <p className="py-10 text-center text-sm text-muted-foreground">분류 규칙이 없습니다.</p>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Archive Matches</CardTitle>
                <CardDescription>규칙과 매칭된 파일만 적용 버튼이 표시됩니다.</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[700px]">
                  <div className="space-y-3 pr-3">
                    {archiveFiles.map((file) => (
                      <div key={file.id} className="rounded-md border p-4">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div>
                            <div className="font-medium">{file.fileName}</div>
                            <div className="mt-1 flex flex-wrap gap-2">
                              <Badge variant="outline">.{file.extension}</Badge>
                              <Badge variant="secondary">{file.folder}</Badge>
                              {file.aiTags && <Badge variant="outline">{file.aiTags}</Badge>}
                            </div>
                          </div>
                          <Button variant="outline" size="sm" onClick={loadArchiveClassifier}>
                            새로고침
                          </Button>
                        </div>
                        {file.aiSummary && (
                          <p className="mt-3 line-clamp-2 text-sm text-muted-foreground">{file.aiSummary}</p>
                        )}
                        <div className="mt-3 flex flex-wrap gap-2">
                          {file.suggestedRules.map((rule) => (
                            <Button
                              key={rule.id}
                              size="sm"
                              variant="secondary"
                              disabled={loading}
                              onClick={() => applyArchiveRule(file.id, rule.id)}
                            >
                              {rule.name} → {rule.folder}
                            </Button>
                          ))}
                          {file.suggestedRules.length === 0 && (
                            <span className="text-sm text-muted-foreground">매칭된 규칙 없음</span>
                          )}
                        </div>
                      </div>
                    ))}
                    {archiveFiles.length === 0 && (
                      <p className="py-16 text-center text-sm text-muted-foreground">아카이브 파일이 없습니다.</p>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
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
