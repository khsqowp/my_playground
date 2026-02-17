"use client";

import { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { ko } from "date-fns/locale";
import { Activity, ArrowDownLeft, ArrowUpRight, ChevronDown, Database, Github, Globe } from "lucide-react";

export default function LogsPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetch("/api/automation/logs")
      .then((r) => r.json())
      .then((data) => { if (Array.isArray(data)) setLogs(data); })
      .finally(() => setIsLoading(false));
  }, []);

  const getIcon = (platform: string) => {
    switch(platform) {
      case 'GITHUB': return <Github className="h-4 w-4" />;
      case 'NOTION': return <Database className="h-4 w-4" />;
      default: return <Globe className="h-4 w-4" />;
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
                  <div className={`p-2 rounded-full ${log.type === 'ACTIVITY' ? 'bg-blue-50 text-blue-600' : 'bg-slate-50 text-slate-600'}`}>
                    {getIcon(log.platform)}
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-bold text-sm">{log.source}</span>
                      <Badge variant="outline" className="text-[9px] uppercase">{log.type}</Badge>
                    </div>
                    <p className="text-xs text-slate-600 truncate">{log.content}</p>
                    <p className="text-[10px] text-muted-foreground mt-1">
                      {format(new Date(log.createdAt), "yyyy-MM-dd HH:mm:ss", { locale: ko })}
                    </p>
                  </div>

                  <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${expandedId === log.id ? 'rotate-180' : ''}`} />
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
