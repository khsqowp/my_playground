"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatDate } from "@/lib/utils";

interface Log {
  id: string;
  direction: string;
  payload: unknown;
  status: string;
  response: string | null;
  webhook: { name: string };
  createdAt: string;
}

export default function LogsPage() {
  const [logs, setLogs] = useState<Log[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/automation/webhooks")
      .then((r) => r.json())
      .then(async (webhooks) => {
        // Fetch logs - we'll create a simple aggregated view
        // For now, load from each webhook's logs
        const allLogs: Log[] = [];
        for (const wh of webhooks) {
          try {
            const res = await fetch(`/api/automation/webhooks?_logs=${wh.id}`);
            const data = await res.json();
            if (Array.isArray(data)) {
              allLogs.push(...data.map((l: Log) => ({ ...l, webhook: { name: wh.name } })));
            }
          } catch { /* skip */ }
        }
        setLogs(allLogs.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()));
      });
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">웹훅 로그</h1>
      <div className="space-y-2">
        {logs.map((log) => (
          <Card key={log.id} className="cursor-pointer" onClick={() => setExpanded(expanded === log.id ? null : log.id)}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Badge variant={log.direction === "INBOUND" ? "secondary" : "default"}>
                    {log.direction}
                  </Badge>
                  <span className="text-sm font-medium">{log.webhook?.name}</span>
                  <Badge variant={log.status === "SUCCESS" ? "secondary" : "destructive"}>
                    {log.status}
                  </Badge>
                </div>
                <span className="text-xs text-muted-foreground">{formatDate(log.createdAt)}</span>
              </div>
              {expanded === log.id && (
                <div className="mt-3 space-y-2">
                  <div className="rounded bg-muted p-3">
                    <p className="text-xs font-medium mb-1">페이로드:</p>
                    <pre className="text-xs overflow-x-auto">{JSON.stringify(log.payload, null, 2)}</pre>
                  </div>
                  {log.response && (
                    <div className="rounded bg-muted p-3">
                      <p className="text-xs font-medium mb-1">응답:</p>
                      <pre className="text-xs overflow-x-auto">{log.response}</pre>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        ))}
        {logs.length === 0 && <p className="text-muted-foreground text-center py-8">로그가 없습니다</p>}
      </div>
    </div>
  );
}
