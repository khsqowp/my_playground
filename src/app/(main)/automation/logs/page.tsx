"use client";

import { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { ko } from "date-fns/locale";
import { Activity, ArrowDownLeft, ArrowUpRight, ChevronDown } from "lucide-react";

interface Log {
  id: string;
  direction: string;
  payload: any;
  status: string;
  response: string | null;
  createdAt: string;
  webhook?: { name: string; platform: string };
  incomingWebhook?: { name: string };
}

export default function LogsPage() {
  const [logs, setLogs] = useState<Log[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetch("/api/automation/logs")
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data)) setLogs(data);
      })
      .finally(() => setIsLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Activity className="h-6 w-6 text-primary" />
          자동화 활동 로그
        </h1>
        <Badge variant="outline" className="text-xs">최근 100건</Badge>
      </div>

      <div className="space-y-3">
        {isLoading ? (
          [1, 2, 3].map(i => <div key={i} className="h-16 bg-muted animate-pulse rounded-lg" />)
        ) : logs.length === 0 ? (
          <Card className="p-12 text-center text-muted-foreground border-dashed">
            <p>기록된 로그가 없습니다.</p>
          </Card>
        ) : (
          logs.map((log) => (
            <Card 
              key={log.id} 
              className={`overflow-hidden transition-all ${expandedId === log.id ? 'ring-1 ring-primary' : 'hover:bg-muted/30 cursor-pointer'}`}
              onClick={() => setExpandedId(expandedId === log.id ? null : log.id)}
            >
              <CardContent className="p-0">
                <div className="flex items-center p-4 gap-4">
                  <div className={`p-2 rounded-full ${log.direction === 'INCOMING' ? 'bg-blue-50 text-blue-600' : 'bg-green-50 text-green-600'}`}>
                    {log.direction === 'INCOMING' ? <ArrowDownLeft className="h-4 w-4" /> : <ArrowUpRight className="h-4 w-4" />}
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-bold text-sm truncate">
                        {log.webhook?.name || log.incomingWebhook?.name || "알 수 없는 소스"}
                      </span>
                      <Badge variant={log.status === 'SUCCEEDED' ? 'secondary' : 'destructive'} className="text-[10px] h-4">
                        {log.status}
                      </Badge>
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      {format(new Date(log.createdAt), "yyyy-MM-dd HH:mm:ss", { locale: ko })}
                    </p>
                  </div>

                  <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${expandedId === log.id ? 'rotate-180' : ''}`} />
                </div>

                {expandedId === log.id && (
                  <div className="p-4 bg-muted/50 border-t space-y-4">
                    <div className="space-y-1.5">
                      <p className="text-[10px] font-bold text-muted-foreground uppercase">Payload (데이터)</p>
                      <pre className="text-xs font-mono bg-background p-3 rounded-md border overflow-x-auto max-h-[300px]">
                        {JSON.stringify(log.payload, null, 2)}
                      </pre>
                    </div>
                    {log.response && (
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-bold text-muted-foreground uppercase">Response (응답)</p>
                        <pre className="text-xs font-mono bg-background p-3 rounded-md border overflow-x-auto">
                          {log.response}
                        </pre>
                      </div>
                    )}
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
