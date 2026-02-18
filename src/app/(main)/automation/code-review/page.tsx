"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { GitPullRequest, Plus, Trash2, Play, Loader2, ToggleLeft, ToggleRight } from "lucide-react";
import { toast } from "sonner";
import { format } from "date-fns";
import { ko } from "date-fns/locale";

export default function CodeReviewPage() {
  const [configs, setConfigs] = useState<any[]>([]);
  const [webhooks, setWebhooks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [triggering, setTriggering] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

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
    } catch {
      toast.error("삭제 중 오류가 발생했습니다.");
    } finally {
      setDeleting(null);
    }
  };

  const handleTrigger = async (configId: string) => {
    setTriggering(configId);
    try {
      const res = await fetch("/api/automation/code-review/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ configId }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "실행 실패");
      }
      toast.success("코드 리뷰가 Discord로 전송되었습니다!");
      fetchData();
    } catch (err: any) {
      toast.error(err.message || "실행 중 오류가 발생했습니다.");
    } finally {
      setTriggering(null);
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
        <div className="space-y-3">
          {configs.map((config) => (
            <Card key={config.id} className="overflow-hidden">
              <CardContent className="p-4">
                <div className="flex items-center justify-between gap-4">
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
                        {format(new Date(config.lastReviewAt), "yyyy-MM-dd HH:mm", {
                          locale: ko,
                        })}
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
                      onClick={() => handleTrigger(config.id)}
                      disabled={triggering === config.id}
                    >
                      {triggering === config.id ? (
                        <Loader2 className="mr-2 h-3 w-3 animate-spin" />
                      ) : (
                        <Play className="mr-2 h-3 w-3" />
                      )}
                      수동 실행
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
              </CardContent>
            </Card>
          ))}
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
