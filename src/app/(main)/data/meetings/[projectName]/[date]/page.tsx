"use client";

import { useState, useEffect, use } from "react";
import Link from "next/link";
import { 
  ChevronLeft, 
  Github, 
  Database, 
  MessageSquare,
  Send,
  FileText,
  Clock,
  Plus,
  Download,
  ChevronDown
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { format } from "date-fns";
import { ko } from "date-fns/locale";

export default function DailyLogPage({ params }: { params: Promise<{ projectName: string, date: string }> }) {
  const resolvedParams = use(params);
  const { projectName, date } = resolvedParams;

  const [logs, setLogs] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    fetchLogs();
  }, [projectName, date]);

  const fetchLogs = async () => {
    try {
      const res = await fetch(`/api/automation/meetings/daily?project=${projectName}&date=${date}`);
      if (res.ok) {
        const data = await res.json();
        setLogs(data || []);
      }
    } catch (error) {
      toast.error("로그를 불러오지 못했습니다.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleSendReport = async (type: "SUMMARY" | "RAW") => {
    try {
      const res = await fetch(`/api/automation/meetings/report?project=${projectName}&date=${date}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type })
      });

      if (res.ok) {
        toast.success(`${type === "SUMMARY" ? "요약본" : "원본"}이 디코드로 발송되었습니다.`);
      } else {
        toast.error("발송에 실패했습니다.");
      }
    } catch (error) {
      toast.error("오류가 발생했습니다.");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-2">
        <Link href={`/data/meetings/${projectName}`}>
          <Button variant="ghost" size="sm" className="gap-1 p-0 h-auto text-muted-foreground hover:text-primary">
            <ChevronLeft className="h-4 w-4" />
            {projectName} 목록
          </Button>
        </Link>
      </div>

      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">{date} 활동 기록</h1>
            <Badge variant="outline" className="bg-primary/5">{projectName}</Badge>
          </div>
          <p className="text-sm text-muted-foreground">이 날의 Git 커밋 및 Notion 변경 이력입니다.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" onClick={() => handleSendReport("SUMMARY")}>
            <MessageSquare className="h-4 w-4 mr-2" />
            이 날의 요약본 발송
          </Button>
          <Button variant="outline" size="sm" onClick={() => handleSendReport("RAW")}>
            <FileText className="h-4 w-4 mr-2" />
            원본 데이터 발송
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Table */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Clock className="h-5 w-5" />
              활동 로그 리스트
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-4">
                {[1, 2, 3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[100px]">시간</TableHead>
                    <TableHead className="w-[100px]">플랫폼</TableHead>
                    <TableHead>활동</TableHead>
                    <TableHead>내용</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center py-10 text-muted-foreground">
                        활동 내역이 없습니다.
                      </TableCell>
                    </TableRow>
                  ) : (
                    logs.map((log) => (
                      <>
                        <TableRow 
                          key={log.id} 
                          className="cursor-pointer hover:bg-muted/50 transition-colors"
                          onClick={() => setExpandedId(expandedId === log.id ? null : log.id)}
                        >
                          <TableCell className="text-xs text-muted-foreground">
                            {format(new Date(log.eventTime), "HH:mm:ss")}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {log.platform === "GITHUB" ? <Github className="h-3.5 w-3.5" /> : <Database className="h-3.5 w-3.5" />}
                              <span className="text-xs font-bold">{log.platform}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="secondary" className="text-[10px]">{log.action}</Badge>
                          </TableCell>
                          <TableCell className="text-sm">
                            <div className="flex justify-between items-center">
                              <span>{log.content}</span>
                              <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${expandedId === log.id ? 'rotate-180' : ''}`} />
                            </div>
                          </TableCell>
                        </TableRow>
                        {expandedId === log.id && (
                          <TableRow className="bg-muted/30">
                            <TableCell colSpan={4} className="p-0">
                              <div className="p-4 overflow-x-auto max-h-[400px]">
                                <pre className="text-[11px] font-mono bg-black/5 p-3 rounded-md text-slate-700">
                                  {JSON.stringify(log.rawPayload, null, 2)}
                                </pre>
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </>
                    ))
                  )}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Sidebar: Files & Attachments */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">STT 및 첨부파일</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-col gap-2">
                <Button className="w-full justify-start" variant="outline">
                  <Plus className="h-4 w-4 mr-2" />
                  파일 업로드
                </Button>
              </div>
              
              <div className="border rounded-md p-4 space-y-3">
                <p className="text-xs font-bold text-muted-foreground uppercase">등록된 파일</p>
                <div className="flex items-center justify-between group">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-blue-500" />
                    <span className="text-sm truncate max-w-[150px]">meeting_stt.txt</span>
                  </div>
                  <Button variant="ghost" size="icon" className="h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Download className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-muted/50 border-none shadow-none">
            <CardContent className="pt-6">
              <p className="text-xs text-muted-foreground leading-relaxed">
                이 날의 활동 로그는 자정 보고서에 포함되어 디코드로 자동 발송됩니다.
                수동 발송 시에도 이 화면의 데이터가 기준이 됩니다.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
