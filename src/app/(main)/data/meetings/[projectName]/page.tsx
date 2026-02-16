"use client";

import { useState, useEffect, use } from "react";
import Link from "next/link";
import { 
  Plus, 
  RefreshCw, 
  Settings2, 
  ChevronDown, 
  ChevronUp, 
  Calendar,
  ChevronLeft,
  ArrowRight,
  FileText,
  Github,
  Database
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";

export default function ProjectMainPage({ params }: { params: Promise<{ projectName: string }> }) {
  const resolvedParams = use(params);
  const projectName = resolvedParams.projectName;

  const [showSettings, setShowSettings] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [syncStatus, setSyncStatus] = useState("");
  
  const [dates, setDates] = useState<any[]>([]);
  const [secrets, setSecrets] = useState([
    { name: `${projectName}_NOTION_API_KEY`, value: "" },
    { name: `${projectName}_NOTION_PAGE_ID`, value: "" },
    { name: `${projectName}_GITHUB_REPO`, value: "khsqowp/my_playground" },
    { name: `${projectName}_DISCORD_WEBHOOK_URL`, value: "" },
    { name: `${projectName}_GITHUB_WEBHOOK_SECRET`, value: "" },
    { name: `${projectName}_MIDNIGHT_REPORT_TYPE`, value: "RAW" },
  ]);

  useEffect(() => {
    fetchDateGroups();
  }, [projectName]);

  const fetchDateGroups = async () => {
    try {
      const res = await fetch(`/api/automation/meetings/dates?project=${projectName}`);
      if (res.ok) {
        const data = await res.json();
        setDates(data.dateGroups || []);
        if (data.settings && data.settings.length > 0) {
          const mappedSettings = data.settings.map((s: any) => ({
            name: s.key,
            value: "********"
          }));
          setSecrets(mappedSettings);
        }
      }
    } catch (error) {
      console.error("Failed to fetch data:", error);
    }
  };

  const handleSaveSettings = async () => {
    try {
      const res = await fetch(`/api/automation/meetings?project=${projectName}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "SETTINGS",
          data: { secrets }
        })
      });

      if (res.ok) {
        toast.success("설정이 저장되었습니다.");
        setShowSettings(false);
      }
    } catch (error) {
      toast.error("오류가 발생했습니다.");
    }
  };

  const handleSync = async () => {
    setIsSyncing(true);
    setProgress(0);
    setSyncStatus("동기화 시작...");
    
    try {
      const response = await fetch(`/api/automation/meetings/sync?project=${projectName}`, {
        method: "POST",
      });

      if (!response.body) throw new Error("No response body");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value);
        const lines = chunk.split("\n");
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const data = JSON.parse(line.slice(6));
            if (data.error) { toast.error(data.error); setIsSyncing(false); return; }
            setProgress(data.progress);
            setSyncStatus(data.status);
          }
        }
      }

      toast.success("동기화 완료!");
      fetchDateGroups(); 
    } catch (error) {
      toast.error("동기화 중 오류 발생");
    } finally {
      setIsSyncing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Link href="/data/meetings">
          <Button variant="ghost" size="sm" className="gap-1 p-0 h-auto text-muted-foreground hover:text-primary">
            <ChevronLeft className="h-4 w-4" />
            전체 프로젝트
          </Button>
        </Link>
      </div>

      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">{projectName} - 회의 기록</h1>
          <p className="text-sm text-muted-foreground">날짜별로 정리된 활동 로그와 회의록을 확인하세요.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowSettings(!showSettings)}>
            <Settings2 className="h-4 w-4 mr-2" />
            설정
          </Button>
          <Button size="sm" onClick={handleSync} disabled={isSyncing}>
            <RefreshCw className={`h-4 w-4 mr-2 ${isSyncing ? 'animate-spin' : ''}`} />
            즉시 불러오기
          </Button>
        </div>
      </div>

      {isSyncing && (
        <Card className="border-blue-200 bg-blue-50/50">
          <CardContent className="pt-6">
            <div className="flex justify-between mb-2">
              <span className="text-sm font-medium text-blue-700">{syncStatus}</span>
              <span className="text-sm font-medium text-blue-700">{progress}%</span>
            </div>
            <div className="w-full bg-blue-200 rounded-full h-1.5">
              <div className="bg-blue-600 h-1.5 rounded-full transition-all duration-500" style={{ width: `${progress}%` }}></div>
            </div>
          </CardContent>
        </Card>
      )}

      {showSettings && (
        <Card className="border-2 border-primary/20">
          <CardContent className="pt-6 space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              {secrets.map((secret, index) => (
                <div key={index} className="space-y-1.5">
                  <Label className="text-xs uppercase text-muted-foreground font-bold">{secret.name}</Label>
                  <Input 
                    type="password" 
                    value={secret.value}
                    onChange={(e) => {
                      const newSecrets = [...secrets];
                      newSecrets[index].value = e.target.value;
                      setSecrets(newSecrets);
                    }}
                  />
                </div>
              ))}
            </div>
            <div className="flex justify-end">
              <Button onClick={handleSaveSettings} size="sm">설정 저장하기</Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Date List (Grid) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {dates.map((group) => (
          <Link key={group.date} href={`/data/meetings/${projectName}/${group.date}`}>
            <Card className="hover:shadow-md transition-all cursor-pointer group border-l-4 border-l-primary">
              <CardContent className="p-5">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-muted rounded-md group-hover:bg-primary/10">
                      <Calendar className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-bold text-lg">{group.date}</h3>
                      <p className="text-xs text-muted-foreground">{group.dayOfWeek}</p>
                    </div>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:translate-x-1 transition-transform" />
                </div>
                
                <div className="flex gap-4">
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Github className="h-3 w-3" />
                    <span>Git {group.gitCount}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Database className="h-3 w-3" />
                    <span>Notion {group.notionCount}</span>
                  </div>
                  {group.hasStt && (
                    <div className="flex items-center gap-1.5 text-xs text-blue-600 font-medium">
                      <FileText className="h-3 w-3" />
                      <span>STT 포함</span>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}

        {dates.length === 0 && !isSyncing && (
          <div className="col-span-full py-20 text-center border-2 border-dashed rounded-xl">
            <p className="text-muted-foreground">아직 수집된 회의 기록이 없습니다.</p>
            <Button variant="link" onClick={handleSync}>데이터 즉시 불러오기</Button>
          </div>
        )}
      </div>
    </div>
  );
}
