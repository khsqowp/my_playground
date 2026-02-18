"use client";

import { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { format } from "date-fns";
import { ko } from "date-fns/locale";
import {
  Activity,
  ChevronDown,
  Database,
  Github,
  Globe,
  Send,
  Loader2,
} from "lucide-react";
import { toast } from "sonner";

function todayStr() {
  return new Date().toISOString().split("T")[0];
}

export default function LogsPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Report toolbar state
  const [dateFrom, setDateFrom] = useState(todayStr());
  const [dateTo, setDateTo] = useState(todayStr());
  const [webhooks, setWebhooks] = useState<any[]>([]);
  const [selectedWebhookId, setSelectedWebhookId] = useState("");
  const [sendingRaw, setSendingRaw] = useState(false);
  const [sendingAi, setSendingAi] = useState(false);

  useEffect(() => {
    fetch("/api/automation/logs")
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data)) setLogs(data);
      })
      .finally(() => setIsLoading(false));

    fetch("/api/automation/webhooks")
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data)) {
          const discord = data.filter((w: any) => w.platform === "DISCORD");
          setWebhooks(discord);
          if (discord.length > 0) setSelectedWebhookId(discord[0].id);
        }
      });
  }, []);

  const handleSend = async (type: "raw" | "ai") => {
    if (!selectedWebhookId) {
      toast.error("Discord 웹훅을 선택해주세요.");
      return;
    }
    const setter = type === "raw" ? setSendingRaw : setSendingAi;
    setter(true);
    try {
      const res = await fetch("/api/automation/report/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, webhookId: selectedWebhookId, dateFrom, dateTo }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "전송 실패");
      }
      const data = await res.json();
      toast.success(`Discord 전송 완료! (${data.sentMessages}개 메시지)`);
    } catch (err: any) {
      toast.error(err.message || "전송 중 오류가 발생했습니다.");
    } finally {
      setter(false);
    }
  };

  const getIcon = (platform: string) => {
    switch (platform) {
      case "GITHUB":
        return <Github className="h-4 w-4" />;
      case "NOTION":
        return <Database className="h-4 w-4" />;
      default:
        return <Globe className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Activity className="h-6 w-6 text-primary" />
          통합 활동 로그
        </h1>
        <Badge variant="outline">최근 100건</Badge>
      </div>

      {/* Report Toolbar */}
      <Card className="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">시작일</label>
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              className="rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">종료일</label>
            <input
              type="date"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              className="rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
          <div className="space-y-1 flex-1 min-w-[160px]">
            <label className="text-xs font-medium text-muted-foreground">Discord 웹훅</label>
            <select
              value={selectedWebhookId}
              onChange={(e) => setSelectedWebhookId(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            >
              {webhooks.length === 0 ? (
                <option value="">Discord 웹훅 없음</option>
              ) : (
                webhooks.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name}
                  </option>
                ))
              )}
            </select>
          </div>
          <Button
            variant="outline"
            onClick={() => handleSend("raw")}
            disabled={sendingRaw || sendingAi}
          >
            {sendingRaw ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Send className="mr-2 h-4 w-4" />
            )}
            원본 전송
          </Button>
          <Button
            onClick={() => handleSend("ai")}
            disabled={sendingRaw || sendingAi}
          >
            {sendingAi ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Send className="mr-2 h-4 w-4" />
            )}
            AI 리포트 전송
          </Button>
        </div>
      </Card>

      <div className="space-y-3">
        {isLoading ? (
          [1, 2, 3].map((i) => (
            <div key={i} className="h-16 bg-muted animate-pulse rounded-lg" />
          ))
        ) : logs.length === 0 ? (
          <Card className="p-12 text-center text-muted-foreground border-dashed">
            <p>기록된 로그가 없습니다.</p>
          </Card>
        ) : (
          logs.map((log) => (
            <Card
              key={log.id}
              className={`overflow-hidden transition-all ${
                expandedId === log.id
                  ? "ring-1 ring-primary"
                  : "hover:bg-muted/30 cursor-pointer"
              }`}
              onClick={() =>
                setExpandedId(expandedId === log.id ? null : log.id)
              }
            >
              <CardContent className="p-0">
                <div className="flex items-center p-4 gap-4">
                  <div
                    className={`p-2 rounded-full ${
                      log.type === "ACTIVITY"
                        ? "bg-blue-50 text-blue-600"
                        : "bg-slate-50 text-slate-600"
                    }`}
                  >
                    {getIcon(log.platform)}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-bold text-sm">{log.source}</span>
                      <Badge variant="outline" className="text-[9px] uppercase">
                        {log.type}
                      </Badge>
                    </div>
                    <p className="text-xs text-slate-600 truncate">{log.content}</p>
                    <p className="text-[10px] text-muted-foreground mt-1">
                      {format(new Date(log.createdAt), "yyyy-MM-dd HH:mm:ss", {
                        locale: ko,
                      })}
                    </p>
                  </div>

                  <ChevronDown
                    className={`h-4 w-4 text-muted-foreground transition-transform ${
                      expandedId === log.id ? "rotate-180" : ""
                    }`}
                  />
                </div>

                {expandedId === log.id && (
                  <div className="p-4 bg-muted/50 border-t">
                    <pre className="text-[11px] font-mono bg-background p-3 rounded-md border overflow-x-auto max-h-[400px]">
                      {JSON.stringify(log.raw, null, 2)}
                    </pre>
                  </div>
                )}
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
