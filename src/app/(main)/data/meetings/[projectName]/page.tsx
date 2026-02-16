"use client";

import { useState, useEffect, use } from "react";
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
import Link from "next/link";
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
  // 기본 설정 목록 (웹훅 슬러그 포함)
  const [secrets, setSecrets] = useState([
    { name: `${projectName}_NOTION_API_KEY`, value: "" },
    { name: `${projectName}_NOTION_PAGE_ID`, value: "" },
    { name: `${projectName}_GITHUB_REPO`, value: "khsqowp/my_playground" },
    { name: `${projectName}_PROJECT_WEBHOOK_URL`, value: "" },
    { name: `${projectName}_DISCORD_WEBHOOK_URL`, value: "" },
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
            value: s.isSecret ? "********" : s.value
          }));
          // 기존 설정에 있는 값들로 덮어쓰기
          setSecrets(prev => prev.map(p => {
            const found = mappedSettings.find((m: any) => m.name === p.name);
            return found ? found : p;
          }));
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
        toast.success("설정이 저장되고 웹훅 연결이 업데이트되었습니다.");
        setShowSettings(false);
        fetchDateGroups();
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
      if (!response.body) throw new Error("No body");
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
    } catch (error) { toast.error("동기화 오류"); } finally { setIsSyncing(false); }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Link href="/data/meetings">
          <Button variant="ghost" size="sm" className="gap-1 p-0 h-auto text-muted-foreground hover:text-primary">
            <ChevronLeft className="h-4 w-4" />
            목록으로
          </Button>
        </Link>
      </div>

      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">{projectName}</h1>
          <p className="text-sm text-muted-foreground">날짜별 활동 기록 관리</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowSettings(!showSettings)}>
            <Settings2 className="h-4 w-4 mr-2" />
            수집 설정
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
            <div className="flex justify-between mb-2 text-xs font-bold text-blue-600">
              <span>{syncStatus}</span>
              <span>{progress}%</span>
            </div>
            <div className="w-full bg-blue-200 rounded-full h-1.5">
              <div className="bg-blue-600 h-1.5 rounded-full transition-all duration-500" style={{ width: `${progress}%` }}></div>
            </div>
          </CardContent>
        </Card>
      )}

      {showSettings && (
        <Card className="border-2 border-primary/20 shadow-sm">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">프로젝트 수집 설정</CardTitle>
            <CardDescription className="text-[11px]">
              수신 웹훅 URL 전체를 입력하면 자동으로 이 프로젝트에 연결됩니다.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              {secrets.map((secret, index) => (
                <div key={index} className="space-y-1.5">
                  <Label className="text-[10px] uppercase text-muted-foreground font-bold">{secret.name.split('_').slice(1).join(' ')}</Label>
                  <Input 
                    type={secret.name.includes('KEY') || secret.name.includes('URL') ? "password" : "text"}
                    value={secret.value}
                    placeholder={secret.name}
                    onChange={(e) => {
                      const newSecrets = [...secrets];
                      newSecrets[index].value = e.target.value;
                      setSecrets(newSecrets);
                    }}
                    className="h-8 text-sm"
                  />
                </div>
              ))}
            </div>
            <div className="flex justify-end">
              <Button onClick={handleSaveSettings} size="sm">설정 저장 및 웹훅 연결</Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {dates.map((group) => (
          <Link key={group.date} href={`/data/meetings/${projectName}/${group.date}`}>
            <Card className="hover:shadow-md transition-all cursor-pointer group border-l-4 border-l-blue-500">
              <CardContent className="p-5">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-muted rounded-md group-hover:bg-blue-50">
                      <Calendar className="h-5 w-5 text-blue-500" />
                    </div>
                    <div>
                      <h3 className="font-bold text-lg">{group.date}</h3>
                      <p className="text-xs text-muted-foreground">{group.dayOfWeek}</p>
                    </div>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:translate-x-1 transition-transform" />
                </div>
                <div className="flex gap-4">
                  <div className="flex items-center gap-1 text-xs text-muted-foreground">
                    <Github className="h-3 w-3" /> <span>{group.gitCount}</span>
                  </div>
                  <div className="flex items-center gap-1 text-xs text-muted-foreground">
                    <Database className="h-3 w-3" /> <span>{group.notionCount}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
        {dates.length === 0 && !isSyncing && (
          <div className="col-span-full py-20 text-center border-2 border-dashed rounded-xl opacity-50">
            <p className="text-sm">기록이 없습니다. 설정을 완료하고 데이터를 불러오세요.</p>
          </div>
        )}
      </div>
    </div>
  );
}
