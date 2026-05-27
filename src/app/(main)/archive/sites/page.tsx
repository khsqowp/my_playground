"use client";

import { useEffect, useMemo, useState } from "react";
import { Archive, Clock3, Download, ExternalLink, Globe2, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";

type StoredRecord<T> = {
  id: string;
  createdAt: string;
  updatedAt: string;
  data: T;
};

type SiteArchiveWatch = {
  kind: "site-archive-watch";
  ownerId: string;
  url: string;
  title: string;
  folder: string;
  tags: string[];
  enabled: boolean;
  schedule: "manual" | "daily";
  captureHour: number;
  lastCapturedAt: string | null;
  lastContentHash: string | null;
  createdAt: string;
  updatedAt: string;
};

type SiteArchiveCapture = {
  kind: "site-archive-capture";
  ownerId: string;
  watchId: string | null;
  sourceUrl: string;
  title: string;
  folder: string;
  tags: string[];
  statusCode: number;
  contentHash: string;
  changed: boolean;
  capturedAt: string;
  storageDir: string;
  htmlPath: string;
  textPath: string;
  metadataPath: string;
  textPreview: string;
};

const hours = Array.from({ length: 24 }, (_, hour) => hour);

export default function SiteArchivePage() {
  const [watches, setWatches] = useState<StoredRecord<SiteArchiveWatch>[]>([]);
  const [captures, setCaptures] = useState<StoredRecord<SiteArchiveCapture>[]>([]);
  const [selectedWatchId, setSelectedWatchId] = useState("all");
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    url: "",
    title: "",
    folder: "web/unsorted",
    tags: "",
    enabled: true,
    schedule: "daily",
    captureHour: "3",
  });

  const filteredCaptures = useMemo(() => {
    if (selectedWatchId === "all") return captures;
    return captures.filter((capture) => capture.data.watchId === selectedWatchId);
  }, [captures, selectedWatchId]);

  async function loadAll(watchId = selectedWatchId) {
    const [watchRes, captureRes] = await Promise.all([
      fetch("/api/site-archive/watchlist"),
      fetch(`/api/site-archive/captures${watchId !== "all" ? `?watchId=${encodeURIComponent(watchId)}` : ""}`),
    ]);
    if (!watchRes.ok) throw new Error("아카이브 대상 목록을 불러오지 못했습니다.");
    if (!captureRes.ok) throw new Error("저장본 목록을 불러오지 못했습니다.");
    const watchData = await watchRes.json();
    const captureData = await captureRes.json();
    setWatches(watchData.watches || []);
    setCaptures(captureData.captures || []);
  }

  useEffect(() => {
    loadAll().catch((error) => toast.error(error.message));
  }, []);

  async function createWatch() {
    if (!form.url.trim()) {
      toast.error("저장할 URL을 입력해주세요.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/site-archive/watchlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...form,
          captureHour: Number(form.captureHour),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "대상 등록 실패");
      setForm({ ...form, url: "", title: "", tags: "" });
      await loadAll();
      toast.success("아카이브 대상을 등록했습니다.");
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function captureNow(watchId: string) {
    setLoading(true);
    try {
      const res = await fetch("/api/site-archive/capture", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ watchId }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "페이지 저장 실패");
      await loadAll();
      toast.success(data.capture?.data?.changed ? "새 페이지 저장본을 만들었습니다." : "동일한 내용도 확인 기록으로 저장했습니다.");
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function manualCapture() {
    if (!form.url.trim()) {
      toast.error("즉시 저장할 URL을 입력해주세요.");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/site-archive/capture", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: form.url }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "즉시 저장 실패");
      await loadAll();
      toast.success("로컬 저장본을 만들었습니다.");
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
          <h1 className="text-3xl font-bold tracking-tight">사이트 아카이브</h1>
          <p className="mt-1 text-muted-foreground">
            등록한 웹페이지를 새벽 시간대에 불러와 HTML, 텍스트, 메타데이터로 로컬 저장합니다.
          </p>
        </div>
        <Button variant="outline" onClick={() => loadAll().catch((error) => toast.error(error.message))}>
          <RefreshCw className="mr-2 h-4 w-4" />
          새로고침
        </Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-[420px_1fr]">
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe2 className="h-5 w-5" />
                아카이브 대상
              </CardTitle>
              <CardDescription>URL은 수집 대상일 뿐이고, 실제 보관 대상은 로컬 페이지 저장본입니다.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>URL</Label>
                <Input
                  placeholder="https://example.com/page"
                  value={form.url}
                  onChange={(e) => setForm({ ...form, url: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>표시 제목</Label>
                <Input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
              </div>
              <div className="space-y-2">
                <Label>저장 폴더</Label>
                <Input
                  placeholder="web/unsorted"
                  value={form.folder}
                  onChange={(e) => setForm({ ...form, folder: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>태그</Label>
                <Input
                  placeholder="docs, reference, security"
                  value={form.tags}
                  onChange={(e) => setForm({ ...form, tags: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label>수집 방식</Label>
                  <Select value={form.schedule} onValueChange={(value) => setForm({ ...form, schedule: value })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="daily">매일</SelectItem>
                      <SelectItem value="manual">수동</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>수집 시간</Label>
                  <Select value={form.captureHour} onValueChange={(value) => setForm({ ...form, captureHour: value })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {hours.map((hour) => (
                        <SelectItem key={hour} value={String(hour)}>
                          {String(hour).padStart(2, "0")}:00
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex items-center justify-between rounded-md border p-3">
                <div>
                  <div className="text-sm font-medium">자동 수집 활성화</div>
                  <div className="text-xs text-muted-foreground">cron 실행 시 대상에 포함됩니다.</div>
                </div>
                <Switch checked={form.enabled} onCheckedChange={(enabled) => setForm({ ...form, enabled })} />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Button onClick={createWatch} disabled={loading}>
                  대상 등록
                </Button>
                <Button variant="outline" onClick={manualCapture} disabled={loading}>
                  즉시 저장
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock3 className="h-5 w-5" />
                Watchlist
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[420px]">
                <div className="space-y-2 pr-3">
                  {watches.map((watch) => (
                    <div key={watch.id} className="rounded-md border p-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="truncate font-medium">{watch.data.title || watch.data.url}</div>
                          <div className="mt-1 truncate text-xs text-muted-foreground">{watch.data.url}</div>
                        </div>
                        <Button variant="outline" size="sm" disabled={loading} onClick={() => captureNow(watch.id)}>
                          저장
                        </Button>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <Badge variant={watch.data.enabled ? "secondary" : "outline"}>{watch.data.enabled ? "ON" : "OFF"}</Badge>
                        <Badge variant="outline">{watch.data.schedule}</Badge>
                        <Badge variant="outline">{String(watch.data.captureHour).padStart(2, "0")}:00</Badge>
                        <Badge variant="outline">{watch.data.folder}</Badge>
                      </div>
                      {watch.data.lastCapturedAt && (
                        <div className="mt-2 text-xs text-muted-foreground">
                          마지막 저장: {new Date(watch.data.lastCapturedAt).toLocaleString()}
                        </div>
                      )}
                    </div>
                  ))}
                  {watches.length === 0 && (
                    <p className="py-12 text-center text-sm text-muted-foreground">등록된 아카이브 대상이 없습니다.</p>
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Archive className="h-5 w-5" />
                  로컬 저장본
                </CardTitle>
                <CardDescription>HTML, Markdown 텍스트, 메타데이터가 로컬 파일로 저장됩니다.</CardDescription>
              </div>
              <Select
                value={selectedWatchId}
                onValueChange={(value) => {
                  setSelectedWatchId(value);
                  loadAll(value).catch((error) => toast.error(error.message));
                }}
              >
                <SelectTrigger className="w-full md:w-64"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">전체 저장본</SelectItem>
                  {watches.map((watch) => (
                    <SelectItem key={watch.id} value={watch.id}>
                      {watch.data.title || watch.data.url}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[840px]">
              <div className="space-y-3 pr-3">
                {filteredCaptures.map((capture) => (
                  <div key={capture.id} className="rounded-md border p-4">
                    <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                      <div className="min-w-0">
                        <div className="truncate font-medium">{capture.data.title}</div>
                        <div className="mt-1 break-all text-xs text-muted-foreground">{capture.data.sourceUrl}</div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Badge variant={capture.data.changed ? "secondary" : "outline"}>
                          {capture.data.changed ? "changed" : "same"}
                        </Badge>
                        <Badge variant="outline">{capture.data.statusCode}</Badge>
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Badge variant="outline">{capture.data.folder}</Badge>
                      {capture.data.tags.map((tag) => (
                        <Badge key={tag} variant="secondary">{tag}</Badge>
                      ))}
                    </div>
                    <Textarea className="mt-3 h-32 resize-none text-xs" readOnly value={capture.data.textPreview} />
                    <Separator className="my-3" />
                    <div className="grid gap-2 text-xs text-muted-foreground md:grid-cols-2">
                      <div>저장 시각: {new Date(capture.data.capturedAt).toLocaleString()}</div>
                      <div>해시: {capture.data.contentHash.slice(0, 16)}</div>
                      <div className="break-all">HTML: {capture.data.htmlPath}</div>
                      <div className="break-all">Text: {capture.data.textPath}</div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Button variant="outline" size="sm" asChild>
                        <a href={capture.data.sourceUrl} target="_blank" rel="noreferrer">
                          <ExternalLink className="mr-2 h-4 w-4" />
                          원본
                        </a>
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(capture.data.storageDir)}>
                        <Download className="mr-2 h-4 w-4" />
                        경로 복사
                      </Button>
                    </div>
                  </div>
                ))}
                {filteredCaptures.length === 0 && (
                  <p className="py-20 text-center text-sm text-muted-foreground">아직 로컬 저장본이 없습니다.</p>
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
