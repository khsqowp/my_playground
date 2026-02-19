"use client";

import { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  GitPullRequest,
  Plus,
  Trash2,
  Play,
  Loader2,
  ToggleLeft,
  ToggleRight,
  ChevronDown,
  ChevronRight,
  CheckSquare,
  Square,
  GitCommit,
  FileText,
  CheckCircle2,
  Clock,
} from "lucide-react";
import { toast } from "sonner";
import { format } from "date-fns";
import { ko } from "date-fns/locale";
import { cn } from "@/lib/utils";

interface CommitLog {
  id: string;
  createdAt: string;
  ref: string;
  repo: string;
  commitSha: string | null;
  commitMessage: string;
  author: string;
  added: string[];
  modified: string[];
  removed: string[];
  reviewed: boolean;
  reviewText: string | null;
  reviewedAt: string | null;
}

interface CommitLogsState {
  logs: CommitLog[];
  loading: boolean;
  expanded: boolean;
  selectedIds: Set<string>;
  reviewing: boolean;
  reviewingOne: string | null;
}

function CommitRow({
  log,
  selected,
  onSelect,
  onReviewOne,
  reviewing,
}: {
  log: CommitLog;
  selected: boolean;
  onSelect: () => void;
  onReviewOne: (id: string) => void;
  reviewing: boolean;
}) {
  const [showReview, setShowReview] = useState(false);
  const branch = log.ref?.split("/").pop() || log.ref;
  const totalChanged = log.added.length + log.modified.length + log.removed.length;

  return (
    <div
      className={cn(
        "rounded-lg border p-3 space-y-2 transition-colors",
        selected ? "border-primary bg-primary/5" : "border-border bg-muted/20"
      )}
    >
      <div className="flex items-start gap-2">
        {/* 체크박스 */}
        <button onClick={onSelect} className="mt-0.5 shrink-0">
          {selected ? (
            <CheckSquare className="h-4 w-4 text-primary" />
          ) : (
            <Square className="h-4 w-4 text-muted-foreground" />
          )}
        </button>

        <div className="flex-1 min-w-0 space-y-1">
          {/* 커밋 메시지 */}
          <p className="text-sm font-medium leading-snug line-clamp-2">
            {log.commitMessage || "(메시지 없음)"}
          </p>
          {/* 메타 */}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
            {log.commitSha && (
              <span className="font-mono">{log.commitSha.substring(0, 7)}</span>
            )}
            <span>{log.author}</span>
            <span className="font-mono text-primary/70">{branch}</span>
            <span>{format(new Date(log.createdAt), "MM-dd HH:mm", { locale: ko })}</span>
          </div>
          {/* 변경 파일 수 */}
          {totalChanged > 0 && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              {log.added.length > 0 && (
                <span className="text-green-600">+{log.added.length}</span>
              )}
              {log.modified.length > 0 && (
                <span className="text-yellow-600">~{log.modified.length}</span>
              )}
              {log.removed.length > 0 && (
                <span className="text-red-500">-{log.removed.length}</span>
              )}
              <span>파일 변경</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {log.reviewed ? (
            <>
              <Badge variant="default" className="text-xs gap-1">
                <CheckCircle2 className="h-3 w-3" />
                리뷰 완료
              </Badge>
              {log.reviewText && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 text-xs px-2"
                  onClick={() => setShowReview((v) => !v)}
                >
                  {showReview ? "접기" : "보기"}
                </Button>
              )}
            </>
          ) : (
            <>
              <Badge variant="secondary" className="text-xs gap-1">
                <Clock className="h-3 w-3" />
                미검토
              </Badge>
              <Button
                size="sm"
                variant="outline"
                className="h-6 text-xs px-2"
                onClick={() => onReviewOne(log.id)}
                disabled={reviewing}
              >
                {reviewing ? <Loader2 className="h-3 w-3 animate-spin" /> : "리뷰"}
              </Button>
            </>
          )}
        </div>
      </div>

      {/* 리뷰 내용 */}
      {showReview && log.reviewText && (
        <div className="mt-2 rounded-md bg-muted p-3 text-xs text-muted-foreground whitespace-pre-wrap leading-relaxed border-l-2 border-primary/30">
          {log.reviewText}
        </div>
      )}
    </div>
  );
}

export default function CodeReviewPage() {
  const [configs, setConfigs] = useState<any[]>([]);
  const [webhooks, setWebhooks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);

  // 커밋 로그 상태 — configId → state
  const [logsMap, setLogsMap] = useState<Record<string, CommitLogsState>>({});

  const [form, setForm] = useState({
    name: "",
    incomingWebhookId: "",
    discordWebhookUrl: "",
    enabled: true,
  });
  const [saving, setSaving] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [configsRes, webhooksRes] = await Promise.all([
        fetch("/api/automation/code-review"),
        fetch("/api/automation/incoming"),
      ]);
      const configsData = await configsRes.json();
      const webhooksData = await webhooksRes.json();
      if (Array.isArray(configsData)) setConfigs(configsData);
      if (Array.isArray(webhooksData)) setWebhooks(webhooksData);
      if (Array.isArray(webhooksData) && webhooksData.length > 0) {
        setForm((prev) => ({ ...prev, incomingWebhookId: webhooksData[0].id }));
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // ── 커밋 로그 토글 ───────────────────────────────────────
  const toggleLogs = async (configId: string) => {
    const current = logsMap[configId];

    if (current?.expanded) {
      setLogsMap((prev) => ({
        ...prev,
        [configId]: { ...prev[configId], expanded: false },
      }));
      return;
    }

    // 첫 열기 또는 새로고침
    setLogsMap((prev) => ({
      ...prev,
      [configId]: {
        logs: current?.logs || [],
        loading: true,
        expanded: true,
        selectedIds: current?.selectedIds || new Set(),
        reviewing: false,
        reviewingOne: null,
      },
    }));

    try {
      const res = await fetch(`/api/automation/code-review/logs?configId=${configId}`);
      const data = await res.json();
      setLogsMap((prev) => ({
        ...prev,
        [configId]: {
          ...prev[configId],
          logs: data.logs || [],
          loading: false,
        },
      }));
    } catch {
      setLogsMap((prev) => ({
        ...prev,
        [configId]: { ...prev[configId], loading: false },
      }));
      toast.error("로그 조회 중 오류가 발생했습니다.");
    }
  };

  // ── 개별 로그 선택 토글 ──────────────────────────────────
  const toggleLogSelect = (configId: string, logId: string) => {
    setLogsMap((prev) => {
      const state = prev[configId];
      if (!state) return prev;
      const next = new Set(state.selectedIds);
      if (next.has(logId)) next.delete(logId);
      else next.add(logId);
      return { ...prev, [configId]: { ...state, selectedIds: next } };
    });
  };

  const selectAllLogs = (configId: string) => {
    setLogsMap((prev) => {
      const state = prev[configId];
      if (!state) return prev;
      const allIds = new Set(state.logs.map((l) => l.id));
      return { ...prev, [configId]: { ...state, selectedIds: allIds } };
    });
  };

  const clearLogSelect = (configId: string) => {
    setLogsMap((prev) => {
      const state = prev[configId];
      if (!state) return prev;
      return { ...prev, [configId]: { ...state, selectedIds: new Set() } };
    });
  };

  // ── 선택 커밋 일괄 리뷰 ─────────────────────────────────
  const handleReviewSelected = async (configId: string) => {
    const state = logsMap[configId];
    if (!state || state.selectedIds.size === 0) return;

    setLogsMap((prev) => ({ ...prev, [configId]: { ...prev[configId], reviewing: true } }));
    try {
      const res = await fetch("/api/automation/code-review/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          configId,
          webhookLogIds: Array.from(state.selectedIds),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "실패");

      if (data.queued === 0) {
        toast.info("처리할 커밋이 없습니다.");
      } else {
        toast.success(
          `${data.queued}개 커밋 리뷰 시작! Discord로 순차 전송됩니다.`,
          { duration: 5000 }
        );
      }
      clearLogSelect(configId);
      // 로그 새로고침
      setTimeout(() => {
        setLogsMap((prev) => ({ ...prev, [configId]: { ...prev[configId], expanded: false } }));
        setTimeout(() => toggleLogs(configId), 100);
      }, 3000);
    } catch (err: any) {
      toast.error(err.message || "오류가 발생했습니다.");
    } finally {
      setLogsMap((prev) => ({ ...prev, [configId]: { ...prev[configId], reviewing: false } }));
    }
  };

  // ── 단일 커밋 즉시 리뷰 ─────────────────────────────────
  const handleReviewOne = async (configId: string, logId: string) => {
    setLogsMap((prev) => ({
      ...prev,
      [configId]: { ...prev[configId], reviewingOne: logId },
    }));
    try {
      const res = await fetch("/api/automation/code-review/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ configId, webhookLogIds: [logId] }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "실패");
      toast.success("리뷰 완료! Discord로 전송됩니다.", { duration: 4000 });
      // 3초 뒤 로그 새로고침
      setTimeout(() => {
        setLogsMap((prev) => ({ ...prev, [configId]: { ...prev[configId], expanded: false } }));
        setTimeout(() => toggleLogs(configId), 100);
      }, 3000);
    } catch (err: any) {
      toast.error(err.message || "오류가 발생했습니다.");
    } finally {
      setLogsMap((prev) => ({
        ...prev,
        [configId]: { ...prev[configId], reviewingOne: null },
      }));
    }
  };

  const handleCreate = async () => {
    if (!form.name.trim() || !form.incomingWebhookId || !form.discordWebhookUrl.trim()) {
      toast.error("모든 필드를 입력해주세요.");
      return;
    }
    setSaving(true);
    try {
      const res = await fetch("/api/automation/code-review", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "생성 실패");
      }
      toast.success("코드 리뷰 설정이 생성되었습니다.");
      setOpen(false);
      setForm({ name: "", incomingWebhookId: webhooks[0]?.id || "", discordWebhookUrl: "", enabled: true });
      fetchData();
    } catch (err: any) {
      toast.error(err.message || "오류가 발생했습니다.");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (config: any) => {
    try {
      const res = await fetch("/api/automation/code-review", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: config.id, enabled: !config.enabled }),
      });
      if (!res.ok) throw new Error("변경 실패");
      const updated = await res.json();
      setConfigs((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
      toast.success(`${updated.enabled ? "활성화" : "비활성화"}되었습니다.`);
    } catch {
      toast.error("상태 변경 중 오류가 발생했습니다.");
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("이 설정을 삭제하시겠습니까?")) return;
    setDeleting(id);
    try {
      const res = await fetch("/api/automation/code-review", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      if (!res.ok) throw new Error("삭제 실패");
      toast.success("삭제되었습니다.");
      setConfigs((prev) => prev.filter((c) => c.id !== id));
      setLogsMap((prev) => { const n = { ...prev }; delete n[id]; return n; });
    } catch {
      toast.error("삭제 중 오류가 발생했습니다.");
    } finally {
      setDeleting(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <GitPullRequest className="h-6 w-6 text-primary" />
          GitHub 코드 리뷰 자동화
        </h1>
        <Button onClick={() => setOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          설정 추가
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        GitHub 웹훅 수신 시 AI가 자동으로 코드 리뷰를 생성하여 Discord로 전송합니다.
        커밋 기록을 펼쳐 개별 선택 후 분석·저장할 수 있습니다.
      </p>

      {loading ? (
        <div className="space-y-3">
          {[1, 2].map((i) => (
            <div key={i} className="h-24 bg-muted animate-pulse rounded-lg" />
          ))}
        </div>
      ) : configs.length === 0 ? (
        <Card className="p-12 text-center text-muted-foreground border-dashed">
          <GitPullRequest className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>코드 리뷰 설정이 없습니다.</p>
          <p className="text-sm mt-1">GitHub 인입 웹훅과 Discord 웹훅을 연결해보세요.</p>
        </Card>
      ) : (
        <div className="space-y-4">
          {configs.map((config) => {
            const logState = logsMap[config.id];
            const isExpanded = logState?.expanded ?? false;
            const logs = logState?.logs ?? [];
            const selectedIds = logState?.selectedIds ?? new Set<string>();
            const reviewing = logState?.reviewing ?? false;
            const reviewingOne = logState?.reviewingOne ?? null;
            const unreviewed = logs.filter((l) => !l.reviewed).length;

            return (
              <Card key={config.id} className="overflow-hidden">
                <CardContent className="p-0">
                  {/* Config 헤더 */}
                  <div className="flex items-center justify-between gap-4 p-4">
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold">{config.name}</span>
                        <Badge variant={config.enabled ? "default" : "secondary"}>
                          {config.enabled ? "활성" : "비활성"}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        웹훅: {config.incomingWebhook?.name} (
                        <code>/api/hooks/{config.incomingWebhook?.slug}</code>)
                      </p>
                      {config.lastReviewAt && (
                        <p className="text-xs text-muted-foreground">
                          마지막 리뷰:{" "}
                          {format(new Date(config.lastReviewAt), "yyyy-MM-dd HH:mm", { locale: ko })}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleToggle(config)}
                        title={config.enabled ? "비활성화" : "활성화"}
                      >
                        {config.enabled ? (
                          <ToggleRight className="h-5 w-5 text-primary" />
                        ) : (
                          <ToggleLeft className="h-5 w-5 text-muted-foreground" />
                        )}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => toggleLogs(config.id)}
                      >
                        {isExpanded ? (
                          <ChevronDown className="mr-1.5 h-3.5 w-3.5" />
                        ) : (
                          <ChevronRight className="mr-1.5 h-3.5 w-3.5" />
                        )}
                        커밋 기록
                        {unreviewed > 0 && !isExpanded && (
                          <Badge variant="destructive" className="ml-1.5 text-[10px] px-1.5 py-0">
                            {unreviewed}
                          </Badge>
                        )}
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="text-muted-foreground hover:text-destructive"
                        onClick={() => handleDelete(config.id)}
                        disabled={deleting === config.id}
                      >
                        {deleting === config.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Trash2 className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>

                  {/* 커밋 로그 확장 패널 */}
                  {isExpanded && (
                    <div className="border-t">
                      {logState?.loading ? (
                        <div className="flex items-center justify-center py-8">
                          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                          <span className="ml-2 text-sm text-muted-foreground">로그 조회 중...</span>
                        </div>
                      ) : logs.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                          <GitCommit className="h-8 w-8 opacity-30 mb-2" />
                          <p className="text-sm">수신된 push 이벤트가 없습니다.</p>
                        </div>
                      ) : (
                        <div className="p-4 space-y-3">
                          {/* 툴바 */}
                          <div className="flex items-center justify-between gap-2 flex-wrap">
                            <div className="flex items-center gap-3 text-sm text-muted-foreground">
                              <span>총 {logs.length}개 커밋</span>
                              <span className="text-green-600">완료 {logs.filter(l => l.reviewed).length}</span>
                              <span className="text-yellow-600">미검토 {unreviewed}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 text-xs"
                                onClick={() =>
                                  selectedIds.size === logs.length
                                    ? clearLogSelect(config.id)
                                    : selectAllLogs(config.id)
                                }
                              >
                                {selectedIds.size === logs.length ? (
                                  <CheckSquare className="mr-1 h-3.5 w-3.5 text-primary" />
                                ) : (
                                  <Square className="mr-1 h-3.5 w-3.5" />
                                )}
                                {selectedIds.size === logs.length ? "전체 해제" : "전체 선택"}
                              </Button>
                              {selectedIds.size > 0 && (
                                <Button
                                  size="sm"
                                  className="h-7 text-xs"
                                  onClick={() => handleReviewSelected(config.id)}
                                  disabled={reviewing}
                                >
                                  {reviewing ? (
                                    <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                                  ) : (
                                    <Play className="mr-1 h-3 w-3" />
                                  )}
                                  {selectedIds.size}개 리뷰 분석
                                </Button>
                              )}
                            </div>
                          </div>

                          {/* 커밋 목록 */}
                          <ScrollArea className="max-h-[480px] pr-1">
                            <div className="space-y-2">
                              {logs.map((log) => (
                                <CommitRow
                                  key={log.id}
                                  log={log}
                                  selected={selectedIds.has(log.id)}
                                  onSelect={() => toggleLogSelect(config.id, log.id)}
                                  onReviewOne={(id) => handleReviewOne(config.id, id)}
                                  reviewing={reviewingOne === log.id}
                                />
                              ))}
                            </div>
                          </ScrollArea>
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>코드 리뷰 설정 추가</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <label className="text-sm font-medium">설정 이름</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="예: 메인 프로젝트 리뷰"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">GitHub 인입 웹훅</label>
              <select
                value={form.incomingWebhookId}
                onChange={(e) => setForm({ ...form, incomingWebhookId: e.target.value })}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              >
                {webhooks.length === 0 ? (
                  <option value="">인입 웹훅 없음</option>
                ) : (
                  webhooks.map((w) => (
                    <option key={w.id} value={w.id}>
                      {w.name}
                    </option>
                  ))
                )}
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">Discord 웹훅 URL</label>
              <input
                type="url"
                value={form.discordWebhookUrl}
                onChange={(e) => setForm({ ...form, discordWebhookUrl: e.target.value })}
                placeholder="https://discord.com/api/webhooks/..."
                className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={saving}>
              취소
            </Button>
            <Button onClick={handleCreate} disabled={saving}>
              {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              생성
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
