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
import {
  GitPullRequest,
  Plus,
  Trash2,
  Loader2,
  ToggleLeft,
  ToggleRight,
  CheckSquare,
  Square,
  GitCommit,
  CheckCircle2,
  Clock,
  RefreshCw,
  Play,
  ChevronDown,
  ChevronRight,
  GitBranch,
} from "lucide-react";
import { toast } from "sonner";
import { format } from "date-fns";
import { ko } from "date-fns/locale";
import { cn } from "@/lib/utils";

interface Commit {
  sha: string;
  message: string;
  author: string;
  date: string;
  branches?: string[];
  reviewed: boolean;
  reviewText: string | null;
  reviewedAt: string | null;
}

interface SyncState {
  commits: Commit[];
  loading: boolean;
  expanded: boolean;
  selectedShas: Set<string>;
  reviewing: boolean;
  reviewingOne: string | null;
  lastSynced: Date | null;
}

function CommitRow({
  commit,
  selected,
  onSelect,
  onReviewOne,
  reviewingThis,
}: {
  commit: Commit;
  selected: boolean;
  onSelect: () => void;
  onReviewOne: (sha: string) => void;
  reviewingThis: boolean;
}) {
  const [showReview, setShowReview] = useState(false);
  const firstLine = commit.message.split("\n")[0];

  return (
    <div
      className={cn(
        "rounded-lg border p-3 space-y-2 transition-colors",
        selected ? "border-primary bg-primary/5" : "border-border bg-muted/20"
      )}
    >
      <div className="flex items-start gap-2">
        <button onClick={onSelect} className="mt-0.5 shrink-0">
          {selected ? (
            <CheckSquare className="h-4 w-4 text-primary" />
          ) : (
            <Square className="h-4 w-4 text-muted-foreground" />
          )}
        </button>

        <div className="flex-1 min-w-0 space-y-1">
          <p className="text-sm font-medium leading-snug line-clamp-2">{firstLine || "(메시지 없음)"}</p>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
            <span className="font-mono text-primary/80">{commit.sha.substring(0, 7)}</span>
            <span>{commit.author}</span>
            <span>{format(new Date(commit.date), "yyyy-MM-dd HH:mm", { locale: ko })}</span>
          </div>
          {commit.branches && commit.branches.length > 0 && (
            <div className="flex flex-wrap items-center gap-1 mt-0.5">
              <GitBranch className="h-3 w-3 text-muted-foreground shrink-0" />
              {commit.branches.slice(0, 4).map((b) => (
                <span
                  key={b}
                  className="inline-flex items-center rounded px-1.5 py-0 text-[10px] font-mono bg-muted text-muted-foreground border"
                >
                  {b}
                </span>
              ))}
              {commit.branches.length > 4 && (
                <span className="text-[10px] text-muted-foreground">+{commit.branches.length - 4}</span>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {commit.reviewed ? (
            <>
              <Badge variant="default" className="text-xs gap-1 shrink-0">
                <CheckCircle2 className="h-3 w-3" />
                완료
              </Badge>
              {commit.reviewText && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 text-xs px-2 shrink-0"
                  onClick={() => setShowReview((v) => !v)}
                >
                  {showReview ? "접기" : "보기"}
                </Button>
              )}
            </>
          ) : (
            <>
              <Badge variant="secondary" className="text-xs gap-1 shrink-0">
                <Clock className="h-3 w-3" />
                미검토
              </Badge>
              <Button
                size="sm"
                variant="outline"
                className="h-6 text-xs px-2 shrink-0"
                onClick={() => onReviewOne(commit.sha)}
                disabled={reviewingThis}
              >
                {reviewingThis ? <Loader2 className="h-3 w-3 animate-spin" /> : "리뷰"}
              </Button>
            </>
          )}
        </div>
      </div>

      {showReview && commit.reviewText && (
        <div className="mt-2 rounded-md bg-muted p-3 text-xs text-muted-foreground whitespace-pre-wrap leading-relaxed border-l-2 border-primary/30">
          {commit.reviewText}
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
  const [editTarget, setEditTarget] = useState<any | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const [syncMap, setSyncMap] = useState<Record<string, SyncState>>({});

  const [form, setForm] = useState({
    name: "",
    incomingWebhookId: "",
    discordWebhookUrl: "",
    githubRepo: "",
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
      if (Array.isArray(webhooksData)) {
        setWebhooks(webhooksData);
        if (webhooksData.length > 0) {
          setForm((prev) => ({ ...prev, incomingWebhookId: webhooksData[0].id }));
        }
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // ── GitHub 동기화 ────────────────────────────────────────────
  const syncGitHub = async (configId: string) => {
    const current = syncMap[configId];

    if (current?.expanded && current?.commits.length > 0) {
      // 토글 닫기
      setSyncMap((prev) => ({ ...prev, [configId]: { ...prev[configId], expanded: false } }));
      return;
    }

    setSyncMap((prev) => ({
      ...prev,
      [configId]: {
        commits: current?.commits || [],
        loading: true,
        expanded: true,
        selectedShas: current?.selectedShas || new Set(),
        reviewing: false,
        reviewingOne: null,
        lastSynced: current?.lastSynced || null,
      },
    }));

    try {
      const res = await fetch("/api/automation/code-review/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ configId }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "동기화 실패");

      setSyncMap((prev) => ({
        ...prev,
        [configId]: {
          ...prev[configId],
          commits: data.commits || [],
          loading: false,
          lastSynced: new Date(),
        },
      }));
      toast.success(
        `${data.total}개 커밋 로드 완료 — 브랜치 ${data.branches?.length ?? 1}개 (완료 ${data.reviewed} / 미검토 ${data.unreviewed})`,
        { duration: 4000 }
      );
    } catch (err: any) {
      setSyncMap((prev) => ({ ...prev, [configId]: { ...prev[configId], loading: false } }));
      toast.error(err.message || "동기화 중 오류가 발생했습니다.");
    }
  };

  const refreshSync = async (configId: string) => {
    setSyncMap((prev) => ({
      ...prev,
      [configId]: { ...prev[configId], loading: true },
    }));
    try {
      const res = await fetch("/api/automation/code-review/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ configId }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "새로고침 실패");
      setSyncMap((prev) => ({
        ...prev,
        [configId]: { ...prev[configId], commits: data.commits || [], loading: false, lastSynced: new Date() },
      }));
    } catch (err: any) {
      setSyncMap((prev) => ({ ...prev, [configId]: { ...prev[configId], loading: false } }));
      toast.error(err.message);
    }
  };

  // ── 선택 ─────────────────────────────────────────────────────
  const toggleSelect = (configId: string, sha: string) => {
    setSyncMap((prev) => {
      const s = prev[configId];
      if (!s) return prev;
      const next = new Set(s.selectedShas);
      if (next.has(sha)) next.delete(sha);
      else next.add(sha);
      return { ...prev, [configId]: { ...s, selectedShas: next } };
    });
  };

  const selectAll = (configId: string) => {
    setSyncMap((prev) => {
      const s = prev[configId];
      if (!s) return prev;
      return { ...prev, [configId]: { ...s, selectedShas: new Set(s.commits.map((c) => c.sha)) } };
    });
  };

  const selectUnreviewed = (configId: string) => {
    setSyncMap((prev) => {
      const s = prev[configId];
      if (!s) return prev;
      return {
        ...prev,
        [configId]: { ...s, selectedShas: new Set(s.commits.filter((c) => !c.reviewed).map((c) => c.sha)) },
      };
    });
  };

  const clearSelect = (configId: string) => {
    setSyncMap((prev) => {
      const s = prev[configId];
      if (!s) return prev;
      return { ...prev, [configId]: { ...s, selectedShas: new Set() } };
    });
  };

  // ── 일괄 리뷰 ────────────────────────────────────────────────
  const handleReviewSelected = async (configId: string) => {
    const s = syncMap[configId];
    if (!s || s.selectedShas.size === 0) return;

    setSyncMap((prev) => ({ ...prev, [configId]: { ...prev[configId], reviewing: true } }));
    try {
      const res = await fetch("/api/automation/code-review/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ configId, commitShas: Array.from(s.selectedShas) }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "실패");
      toast.success(
        `${data.queued}개 커밋 분석 시작! Discord로 순차 전송됩니다.`,
        { duration: 5000 }
      );
      clearSelect(configId);
      // 4초 후 자동 새로고침
      setTimeout(() => refreshSync(configId), 4000);
    } catch (err: any) {
      toast.error(err.message || "오류가 발생했습니다.");
    } finally {
      setSyncMap((prev) => ({ ...prev, [configId]: { ...prev[configId], reviewing: false } }));
    }
  };

  // ── 단일 리뷰 ────────────────────────────────────────────────
  const handleReviewOne = async (configId: string, sha: string) => {
    setSyncMap((prev) => ({ ...prev, [configId]: { ...prev[configId], reviewingOne: sha } }));
    try {
      const res = await fetch("/api/automation/code-review/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ configId, commitShas: [sha] }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "실패");
      toast.success("리뷰 분석 시작! Discord로 전송됩니다.", { duration: 3000 });
      setTimeout(() => refreshSync(configId), 3000);
    } catch (err: any) {
      toast.error(err.message || "오류가 발생했습니다.");
    } finally {
      setSyncMap((prev) => ({ ...prev, [configId]: { ...prev[configId], reviewingOne: null } }));
    }
  };

  // ── CRUD ─────────────────────────────────────────────────────
  const openCreate = () => {
    setEditTarget(null);
    setForm({ name: "", incomingWebhookId: webhooks[0]?.id || "", discordWebhookUrl: "", githubRepo: "", enabled: true });
    setOpen(true);
  };

  const openEdit = (config: any) => {
    setEditTarget(config);
    setForm({
      name: config.name,
      incomingWebhookId: config.incomingWebhookId,
      discordWebhookUrl: config.discordWebhookUrl,
      githubRepo: config.githubRepo || "",
      enabled: config.enabled,
    });
    setOpen(true);
  };

  const handleSave = async () => {
    if (!form.name.trim() || !form.incomingWebhookId || !form.discordWebhookUrl.trim()) {
      toast.error("이름, 웹훅, Discord URL은 필수입니다.");
      return;
    }
    setSaving(true);
    try {
      const res = editTarget
        ? await fetch("/api/automation/code-review", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: editTarget.id, ...form }),
          })
        : await fetch("/api/automation/code-review", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(form),
          });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "저장 실패");
      }
      toast.success(editTarget ? "수정되었습니다." : "설정이 생성되었습니다.");
      setOpen(false);
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
      setSyncMap((prev) => { const n = { ...prev }; delete n[id]; return n; });
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
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          설정 추가
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        GitHub 레포지토리를 연결하면 전체 커밋 이력을 불러와 누락된 커밋을 AI로 분석·저장합니다.
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
          <p className="text-sm mt-1">설정을 추가하고 GitHub 레포지토리를 연결해보세요.</p>
        </Card>
      ) : (
        <div className="space-y-4">
          {configs.map((config) => {
            const s = syncMap[config.id];
            const isExpanded = s?.expanded ?? false;
            const commits = s?.commits ?? [];
            const selectedShas = s?.selectedShas ?? new Set<string>();
            const reviewing = s?.reviewing ?? false;
            const reviewingOne = s?.reviewingOne ?? null;
            const unreviewed = commits.filter((c) => !c.reviewed).length;
            const hasGithub = !!config.githubRepo;

            return (
              <Card key={config.id} className="overflow-hidden">
                <CardContent className="p-0">
                  {/* 헤더 */}
                  <div className="flex items-center justify-between gap-4 p-4">
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold">{config.name}</span>
                        <Badge variant={config.enabled ? "default" : "secondary"}>
                          {config.enabled ? "활성" : "비활성"}
                        </Badge>
                        {config.githubRepo && (
                          <Badge variant="outline" className="font-mono text-xs">
                            {config.githubRepo}
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        웹훅: {config.incomingWebhook?.name}
                      </p>
                      {config.lastReviewAt && (
                        <p className="text-xs text-muted-foreground">
                          마지막 리뷰: {format(new Date(config.lastReviewAt), "yyyy-MM-dd HH:mm", { locale: ko })}
                        </p>
                      )}
                      {s?.lastSynced && (
                        <p className="text-xs text-muted-foreground">
                          동기화: {format(s.lastSynced, "HH:mm:ss")} — {commits.length}개 커밋
                          {unreviewed > 0 && (
                            <span className="text-yellow-600 ml-1">(미검토 {unreviewed})</span>
                          )}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
                      <Button variant="ghost" size="icon" onClick={() => handleToggle(config)}>
                        {config.enabled ? (
                          <ToggleRight className="h-5 w-5 text-primary" />
                        ) : (
                          <ToggleLeft className="h-5 w-5 text-muted-foreground" />
                        )}
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => openEdit(config)}>
                        수정
                      </Button>
                      {hasGithub && (
                        <Button
                          variant="default"
                          size="sm"
                          onClick={() => syncGitHub(config.id)}
                          disabled={s?.loading}
                        >
                          {s?.loading ? (
                            <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                          ) : isExpanded ? (
                            <ChevronDown className="mr-1.5 h-3.5 w-3.5" />
                          ) : (
                            <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
                          )}
                          {isExpanded ? "접기" : "커밋 불러오기"}
                          {!isExpanded && unreviewed > 0 && (
                            <Badge variant="secondary" className="ml-1.5 text-[10px] px-1.5 py-0">
                              {unreviewed}
                            </Badge>
                          )}
                        </Button>
                      )}
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

                  {/* githubRepo 미설정 안내 */}
                  {!hasGithub && (
                    <div className="border-t px-4 py-3 bg-muted/30">
                      <p className="text-xs text-muted-foreground">
                        GitHub 레포지토리를 설정하면 전체 커밋 이력을 불러올 수 있습니다. (수정 버튼 →{" "}
                        <span className="font-mono">owner/repo</span> 형식으로 입력)
                      </p>
                    </div>
                  )}

                  {/* 커밋 목록 패널 */}
                  {isExpanded && hasGithub && (
                    <div className="border-t">
                      {s?.loading ? (
                        <div className="flex items-center justify-center py-10">
                          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                          <span className="ml-2 text-sm text-muted-foreground">
                            GitHub에서 커밋 이력을 불러오는 중...
                          </span>
                        </div>
                      ) : commits.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
                          <GitCommit className="h-8 w-8 opacity-30 mb-2" />
                          <p className="text-sm">커밋이 없거나 레포지토리에 접근할 수 없습니다.</p>
                        </div>
                      ) : (
                        <div className="p-4 space-y-3">
                          {/* 툴바 */}
                          <div className="flex items-center justify-between gap-2 flex-wrap">
                            <div className="flex items-center gap-3 text-sm">
                              <span className="text-muted-foreground">총 {commits.length}개</span>
                              <span className="text-green-600">완료 {commits.filter((c) => c.reviewed).length}</span>
                              <span className="text-yellow-600">미검토 {unreviewed}</span>
                            </div>
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 text-xs"
                                onClick={() => refreshSync(config.id)}
                                disabled={s?.loading}
                              >
                                <RefreshCw className="mr-1 h-3 w-3" />
                                새로고침
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 text-xs"
                                onClick={() => selectUnreviewed(config.id)}
                              >
                                미검토 선택
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 text-xs"
                                onClick={() =>
                                  selectedShas.size === commits.length
                                    ? clearSelect(config.id)
                                    : selectAll(config.id)
                                }
                              >
                                {selectedShas.size === commits.length ? (
                                  <CheckSquare className="mr-1 h-3.5 w-3.5 text-primary" />
                                ) : (
                                  <Square className="mr-1 h-3.5 w-3.5" />
                                )}
                                {selectedShas.size === commits.length ? "전체 해제" : "전체 선택"}
                              </Button>
                              {selectedShas.size > 0 && (
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
                                  {selectedShas.size}개 AI 분석
                                </Button>
                              )}
                            </div>
                          </div>

                          {/* 커밋 목록 */}
                          <div className="overflow-y-auto max-h-[520px] space-y-2 pr-1">
                            {commits.map((commit) => (
                              <CommitRow
                                key={commit.sha}
                                commit={commit}
                                selected={selectedShas.has(commit.sha)}
                                onSelect={() => toggleSelect(config.id, commit.sha)}
                                onReviewOne={(sha) => handleReviewOne(config.id, sha)}
                                reviewingThis={reviewingOne === commit.sha}
                              />
                            ))}
                          </div>
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

      {/* 설정 추가/수정 다이얼로그 */}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editTarget ? "코드 리뷰 설정 수정" : "코드 리뷰 설정 추가"}</DialogTitle>
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
            <div className="space-y-1">
              <label className="text-sm font-medium">
                GitHub 레포지토리{" "}
                <span className="font-normal text-muted-foreground">(전체 이력 동기화용, 선택)</span>
              </label>
              <input
                type="text"
                value={form.githubRepo}
                onChange={(e) => setForm({ ...form, githubRepo: e.target.value })}
                placeholder="owner/repo (예: khsqowp/my_playground)"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary font-mono"
              />
              <p className="text-xs text-muted-foreground">
                비공개 레포는 서버에 GITHUB_TOKEN 환경변수가 필요합니다.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={saving}>
              취소
            </Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              {editTarget ? "수정" : "생성"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
