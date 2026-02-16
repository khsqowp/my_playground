"use client";

import { useState, useEffect, use } from "react";
import { 
  Plus, 
  RefreshCw, 
  Settings2, 
  ChevronDown, 
  ChevronUp, 
  Github, 
  Database, 
  MessageSquare,
  Send,
  FileText,
  Clock,
  ChevronLeft
} from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { formatDistanceToNow } from "date-fns";
import { ko } from "date-fns/locale";

export default function ProjectDetailPage({ params }: { params: Promise<{ projectName: string }> }) {
  const resolvedParams = use(params);
  const projectName = resolvedParams.projectName;

  const [showSettings, setShowSettings] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [syncStatus, setSyncStatus] = useState("");
  
  const [logs, setLogs] = useState<any[]>([]);
  const [secrets, setSecrets] = useState([
    { name: `${projectName}_NOTION_API_KEY`, value: "" },
    { name: `${projectName}_NOTION_PAGE_ID`, value: "" },
    { name: `${projectName}_DISCORD_WEBHOOK_URL`, value: "" },
    { name: `${projectName}_GITHUB_WEBHOOK_SECRET`, value: "" },
    { name: `${projectName}_MIDNIGHT_REPORT_TYPE`, value: "RAW" },
  ]);

  useEffect(() => {
    fetchData();
  }, [projectName]);

  const fetchData = async () => {
    try {
      const res = await fetch(`/api/automation/meetings?project=${projectName}`);
      if (res.ok) {
        const data = await res.json();
        if (data) {
          setLogs(data.activityLogs || []);
          if (data.settings && data.settings.length > 0) {
            const mappedSettings = data.settings.map((s: any) => ({
              name: s.key,
              value: "********"
            }));
            setSecrets(mappedSettings);
          }
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
      } else {
        toast.error("저장에 실패했습니다.");
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
        const lines = chunk.split("
");

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const data = JSON.parse(line.slice(6));
            if (data.error) {
              toast.error(data.error);
              setIsSyncing(false);
              return;
            }
            setProgress(data.progress);
            setSyncStatus(data.status);
          }
        }
      }

      toast.success("데이터를 성공적으로 불러왔습니다.");
      fetchData(); 
    } catch (error) {
      console.error("Sync failed:", error);
      toast.error("동기화 중 오류가 발생했습니다.");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleSendReport = async (type: "SUMMARY" | "RAW") => {
    try {
      const res = await fetch(`/api/automation/meetings/report?project=${projectName}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type })
      });

      if (res.ok) {
        toast.success(`${type === "SUMMARY" ? "요약본" : "원본"}이 발송되었습니다.`);
      } else {
        const data = await res.json();
        toast.error(data.error || "발송에 실패했습니다.");
      }
    } catch (error) {
      toast.error("오류가 발생했습니다.");
    }
  };

  const handleAddSecret = () => {
    setSecrets([...secrets, { name: "", value: "" }]);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-2">
        <Link href="/data/meetings">
          <Button variant="ghost" size="sm" className="gap-1 p-0 h-auto hover:bg-transparent text-muted-foreground hover:text-primary">
            <ChevronLeft className="h-4 w-4" />
            목록으로
          </Button>
        </Link>
      </div>

      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold">{projectName}</h1>
            <Badge className="bg-blue-100 text-blue-700 hover:bg-blue-100 border-none">Active</Badge>
          </div>
          <p className="text-sm text-muted-foreground">이 프로젝트의 노션 및 깃허브 활동 로그를 관리합니다.</p>
        </div>
        <div className="flex gap-2 w-full sm:w-auto">
          <Button variant="outline" onClick={handleSync} disabled={isSyncing}>
            <RefreshCw className={`h-4 w-4 mr-2 ${isSyncing ? 'animate-spin' : ''}`} />
            즉시 불러오기
          </Button>
        </div>
      </div>

      {/* Sync Status / Progress Bar */}
      {isSyncing && (
        <Card className="border-blue-200 bg-blue-50/50">
          <CardContent className="pt-6">
            <div className="flex justify-between mb-2">
              <span className="text-sm font-medium text-blue-700">{syncStatus}</span>
              <span className="text-sm font-medium text-blue-700">{progress}%</span>
            </div>
            <div className="w-full bg-blue-200 rounded-full h-2.5">
              <div 
                className="bg-blue-600 h-2.5 rounded-full transition-all duration-500" 
                style={{ width: `${progress}%` }}
              ></div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Settings Toggle */}
      <Card>
        <CardHeader 
          className="cursor-pointer flex flex-row items-center justify-between pb-2"
          onClick={() => setShowSettings(!showSettings)}
        >
          <div className="flex items-center gap-2">
            <Settings2 className="h-5 w-5 text-gray-500" />
            <CardTitle className="text-lg">수집 설정 (Secrets)</CardTitle>
          </div>
          {showSettings ? <ChevronUp className="h-5 w-5" /> : <ChevronDown className="h-5 w-5" />}
        </CardHeader>
        {showSettings && (
          <CardContent className="space-y-4 pt-0">
            <p className="text-xs text-muted-foreground mb-4">
              이 프로젝트 전용 Secrets를 설정하세요. 값은 마스킹 처리됩니다.
            </p>
            <div className="grid gap-4">
              {secrets.map((secret, index) => (
                <div key={index} className="flex gap-4 items-end">
                  <div className="flex-1 space-y-1.5">
                    <Label>Secret 이름</Label>
                    <Input 
                      placeholder="NAME" 
                      value={secret.name} 
                      onChange={(e) => {
                        const newSecrets = [...secrets];
                        newSecrets[index].name = e.target.value;
                        setSecrets(newSecrets);
                      }}
                    />
                  </div>
                  <div className="flex-1 space-y-1.5">
                    <Label>값</Label>
                    <Input 
                      type="password" 
                      placeholder="Value" 
                      value={secret.value}
                      onChange={(e) => {
                        const newSecrets = [...secrets];
                        newSecrets[index].value = e.target.value;
                        setSecrets(newSecrets);
                      }}
                    />
                  </div>
                </div>
              ))}
              <Button variant="ghost" size="sm" className="w-fit" onClick={handleAddSecret}>
                <Plus className="h-4 w-4 mr-2" />
                추가 항목
              </Button>
            </div>
            <div className="pt-2 flex justify-end">
              <Button onClick={handleSaveSettings}>저장하기</Button>
            </div>
          </CardContent>
        )}
      </Card>

      {/* Main Content Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Table */}
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-lg flex items-center gap-2">
              <Clock className="h-5 w-5" />
              최근 활동 기록
            </CardTitle>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => handleSendReport("SUMMARY")}>
                중간상황 보내기
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>플랫폼</TableHead>
                  <TableHead>활동</TableHead>
                  <TableHead>내용</TableHead>
                  <TableHead className="text-right">시간</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                      수집된 활동 기록이 없습니다.
                    </TableCell>
                  </TableRow>
                ) : (
                  logs.map((log) => (
                    <TableRow key={log.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {log.platform === "GITHUB" ? <Github className="h-4 w-4" /> : <Database className="h-4 w-4" />}
                          <span className="font-medium text-xs">{log.platform}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px]">{log.action}</Badge>
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-sm">{log.content}</TableCell>
                      <TableCell className="text-right text-muted-foreground text-[10px] whitespace-nowrap">
                        {formatDistanceToNow(new Date(log.eventTime), { addSuffix: true, locale: ko })}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Action Sidebar */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Send className="h-5 w-5" />
                Discord 보고
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">현재까지 수집된 데이터를 즉시 전송합니다.</p>
                <div className="grid grid-cols-1 gap-2">
                  <Button variant="secondary" className="justify-start" onClick={() => handleSendReport("SUMMARY")}>
                    <MessageSquare className="h-4 w-4 mr-2 text-blue-500" />
                    요약본 보내기
                  </Button>
                  <Button variant="secondary" className="justify-start" onClick={() => handleSendReport("RAW")}>
                    <FileText className="h-4 w-4 mr-2 text-gray-500" />
                    원본 보내기
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">회의 세션 관리</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button className="w-full">
                <Plus className="h-4 w-4 mr-2" />
                새 회의 생성
              </Button>
              <div className="border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center text-center cursor-pointer hover:bg-muted/50 transition-colors">
                <Plus className="h-8 w-8 text-muted-foreground mb-2" />
                <p className="text-sm font-medium">STT 기록 추가</p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
