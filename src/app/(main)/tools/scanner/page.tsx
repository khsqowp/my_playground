"use client";

import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { 
  Play, 
  Terminal, 
  Settings2, 
  ShieldAlert, 
  Bug, 
  Globe, 
  Lock, 
  Zap,
  Database,
  Loader2,
  Trash2,
  Plus,
  BookOpen,
  FileCode,
  Languages,
  Search,
  ChevronRight,
  ClipboardCheck,
  Info
} from "lucide-react";
import { toast } from "sonner";

// --- Types ---
interface ScanResult {
  type: string;
  payload: string;
  evidence: string;
  confidence: string;
}

interface CheatsheetCategory {
  title: string;
  description: string;
  payloads: { payload: string; description: string }[];
}

interface Cheatsheet {
  title: string;
  categories: Record<string, CheatsheetCategory>;
}

export default function ScannerHubPage() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [results, setResults] = useState<ScanResult[]>([]);
  
  // 공통 설정 (Global State)
  const [target, setTarget] = useState({ url: "", method: "GET", param: "", data: "" });
  const [options, setOptions] = useState({
    cookie: "",
    proxy: "",
    timeout: 10,
    rateLimit: 10,
    threads: 5,
    verbose: true
  });
  const [headers, setHeaders] = useState([{ name: "User-Agent", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ctf-toolkit/0.1.0" }]);

  // 치트시트 데이터
  const [cheatsheets, setCheatsheets] = useState<Record<string, Cheatsheet>>({});
  const [selectedCheat, setSelectedCheat] = useState<string>("sqli");

  // 인코더/디코더
  const [encodeInput, setEncodeInput] = useState("");
  const [encodeMode, setEncodeMode] = useState<"encode" | "decode">("encode");
  const [encodeOutput, setEncodeOutput] = useState<Record<string, string>>({});

  // 가이드 데이터
  const [guides, setGuides] = useState<Record<string, any>>({});
  const [selectedGuide, setSelectedGuide] = useState<string>("sqli");

  // 콜백 로그 상태
  const [callbackLogs, setCallbackLogs] = useState<any[]>([]);

  // 스크롤 리셋용 ref
  const pageRef = useRef<HTMLDivElement>(null);
  const cheatScrollRef = useRef<HTMLDivElement>(null);
  const guideScrollRef = useRef<HTMLDivElement>(null);
  const logTerminalRef = useRef<HTMLDivElement>(null);
  const logResultsRef = useRef<HTMLDivElement>(null);

  // 탭 전환 시 외부 메인 스크롤 컨테이너 리셋
  useEffect(() => {
    let el = pageRef.current?.parentElement;
    while (el) {
      const { overflowY } = window.getComputedStyle(el);
      if (overflowY === "auto" || overflowY === "scroll") {
        el.scrollTop = 0;
        break;
      }
      el = el.parentElement;
    }
  }, [activeTab]);

  // 치트시트 항목 전환 시 내부 스크롤 리셋
  useEffect(() => {
    const viewport = cheatScrollRef.current?.querySelector("[data-radix-scroll-area-viewport]");
    if (viewport) (viewport as HTMLElement).scrollTop = 0;
  }, [selectedCheat]);

  // 가이드 항목 전환 시 내부 스크롤 리셋
  useEffect(() => {
    const viewport = guideScrollRef.current?.querySelector("[data-radix-scroll-area-viewport]");
    if (viewport) (viewport as HTMLElement).scrollTop = 0;
  }, [selectedGuide]);

  useEffect(() => {
    fetchData();
    // 콜백 로그 주기적 업데이트
    const interval = setInterval(fetchCallbackLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const res = await fetch("/api/tools/scanner/data");
      if (res.ok) {
        const data = await res.json();
        setCheatsheets(data.cheatsheets || {});
        setGuides(data.guides || {});
      }
    } catch (e) {
      console.error("Data fetch failed", e);
    }
  };

  const runEncoder = async () => {
    if (!encodeInput) return;
    try {
      const res = await fetch("/api/tools/scanner/encode", {
        method: "POST",
        body: JSON.stringify({ input: encodeInput, mode: encodeMode })
      });
      const data = await res.json();
      setEncodeOutput(data);
    } catch (e) {
      toast.error("처리 실패");
    }
  };

  const fetchCallbackLogs = async () => {
    try {
      const res = await fetch("/api/activity?action=OOB_CALLBACK");
      if (res.ok) {
        const data = await res.json();
        setCallbackLogs(data.logs || []);
      }
    } catch (e) {
      console.error("Callback logs fetch failed");
    }
  };

  const startScan = async (mode: string) => {
    if (!target.url) {
      toast.error("타겟 URL을 입력해주세요.");
      setActiveTab("scanner");
      return;
    }

    setLoading(true);
    setActiveTab("logs");
    setLogs(["스캔을 시작합니다...", `Target: ${target.url}`, `Mode: ${mode.toUpperCase()}`]);
    setResults([]);
    if (logTerminalRef.current) logTerminalRef.current.scrollTop = 0;
    if (logResultsRef.current) logResultsRef.current.scrollTop = 0;

    try {
      const res = await fetch("/api/tools/scanner", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          options,
          headers: headers.filter(h => h.name && h.value),
          modes: { [mode]: true, smart: mode === 'smart' }
        })
      });

      if (!res.ok) throw new Error("스캔 요청 실패");

      const data = await res.json();
      setResults(data.vulnerabilities || []);
      setLogs(prev => [...prev, "스캔이 완료되었습니다.", `발견된 취약점: ${data.vulnerabilities?.length || 0}개`]);
      toast.success("스캔 완료!");
    } catch (error) {
      setLogs(prev => [...prev, "에러: 스캔 도중 오류가 발생했습니다."]);
      toast.error("스캔 실패");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("복사되었습니다.");
  };

  return (
    <div ref={pageRef} className="space-y-6 pb-10">
      {/* Header */}
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Toolkit Hub</h1>
          <p className="text-muted-foreground flex items-center gap-2 mt-1">
            <ShieldAlert className="h-4 w-4 text-primary" /> CTF Toolkit 통합 보안 관리 시스템
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setActiveTab("settings")}>
            <Settings2 className="h-4 w-4 mr-2" /> 글로벌 설정
          </Button>
          <Button disabled={loading} onClick={() => startScan("smart")}>
            {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Zap className="mr-2 h-4 w-4 text-yellow-500 fill-yellow-500" />}
            Smart Scan 시작
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-7 mb-8">
          <TabsTrigger value="dashboard">모드 선택</TabsTrigger>
          <TabsTrigger value="scanner">타겟 설정</TabsTrigger>
          <TabsTrigger value="cheatsheet">치트시트</TabsTrigger>
          <TabsTrigger value="guides">학습 가이드</TabsTrigger>
          <TabsTrigger value="utils">유틸리티</TabsTrigger>
          <TabsTrigger value="callback">중계기 로그</TabsTrigger>
          <TabsTrigger value="logs">스캔 결과</TabsTrigger>
        </TabsList>

        {/* ... (이전 탭 내용들) ... */}

        {/* 6. 중계기 로그 (OOB) */}
        <TabsContent value="callback">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Zap className="h-5 w-5 text-yellow-500" /> OOB Interaction Logs
                  </CardTitle>
                  <CardDescription>
                    외부에서 내 서버로 들어온 요청 기록입니다. Blind 공격 성공 여부를 확인하세요.
                  </CardDescription>
                </div>
                <div className="text-right">
                  <p className="text-xs font-mono bg-muted p-2 rounded border">
                    Callback URL: https://88motorcycle.synology.me:3001/api/hooks/scanner
                  </p>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border font-mono text-[12px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[150px]">Time</TableHead>
                      <TableHead className="w-[80px]">Method</TableHead>
                      <TableHead>Data / Payload</TableHead>
                      <TableHead className="w-[120px]">Source IP</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {callbackLogs.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} className="text-center py-10 text-muted-foreground italic">
                          수신된 로그가 없습니다.
                        </TableCell>
                      </TableRow>
                    ) : (
                      callbackLogs.map((log, i) => {
                        const details = JSON.parse(log.targetId || "{}");
                        return (
                          <TableRow key={i}>
                            <TableCell className="text-muted-foreground text-[10px]">
                              {new Date(log.createdAt).toLocaleString()}
                            </TableCell>
                            <TableCell><Badge variant="outline">{details.method}</Badge></TableCell>
                            <TableCell className="text-green-500 font-bold break-all">
                              {details.path}{Object.keys(details.params || {}).length > 0 && "?" + new URLSearchParams(details.params).toString()}
                              {details.body && <div className="text-[10px] text-slate-500 mt-1">Body: {JSON.stringify(details.body)}</div>}
                            </TableCell>
                            <TableCell>{details.ip}</TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 1. 모드 선택 대시보드 */}
        <TabsContent value="dashboard" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              { id: "smart", title: "Smart Scan", desc: "자동 분석 및 공격 조합", icon: Zap, color: "text-yellow-500" },
              { id: "sqli", title: "SQL Injection", desc: "DB 쿼리 삽입 및 데이터 탈취", icon: Database, color: "text-blue-500" },
              { id: "xss", title: "Cross-Site Scripting", desc: "악성 스크립트 삽입 및 쿠키 탈취", icon: Bug, color: "text-red-500" },
              { id: "cmdi", title: "Command Injection", desc: "OS 시스템 명령 실행", icon: Terminal, color: "text-green-500" },
              { id: "lfi", title: "Local File Inclusion", desc: "서버 내 민감 파일 읽기", icon: FileCode, color: "text-purple-500" },
              { id: "ssrf", title: "SSRF", desc: "내부 네트워크 요청 변조", icon: Globe, color: "text-cyan-500" },
              { id: "ssti", title: "SSTI", desc: "템플릿 엔진 코드 실행", icon: Languages, color: "text-orange-500" },
              { id: "xxe", title: "XXE", desc: "XML 외부 엔티티 취약점", icon: FileCode, color: "text-pink-500" },
              { id: "bruteforce", title: "Brute Force", desc: "디렉토리 및 비밀번호 열거", icon: Lock, color: "text-gray-500" },
            ].map((m) => (
              <Card key={m.id} className="hover:border-primary/50 transition-all cursor-pointer group" onClick={() => { setTarget({...target, param: ""}); setActiveTab("scanner"); }}>
                <CardHeader className="flex flex-row items-center space-y-0 gap-4">
                  <div className={`p-2 rounded-lg bg-muted group-hover:bg-primary/10`}>
                    <m.icon className={`h-6 w-6 ${m.color}`} />
                  </div>
                  <div>
                    <CardTitle className="text-lg">{m.title}</CardTitle>
                    <CardDescription>{m.desc}</CardDescription>
                  </div>
                </CardHeader>
                <CardFooter className="pt-0 flex justify-end">
                  <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); startScan(m.id); }}>
                    즉시 시작 <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                </CardFooter>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* 2. 타겟 및 세션 설정 */}
        <TabsContent value="scanner" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader><CardTitle>Target Configuration</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-4 gap-4">
                  <div className="space-y-2">
                    <Label>Method</Label>
                    <Select value={target.method} onValueChange={(v) => setTarget({...target, method: v})}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="GET">GET</SelectItem>
                        <SelectItem value="POST">POST</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="col-span-3 space-y-2">
                    <Label>Target URL</Label>
                    <Input placeholder="http://target.com/page" value={target.url} onChange={(e) => setTarget({...target, url: e.target.value})} />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>주입 파라미터 (Inject Param)</Label>
                  <Input placeholder="id, user, q..." value={target.param} onChange={(e) => setTarget({...target, param: e.target.value})} />
                </div>
                <div className="space-y-2">
                  <Label>POST Body Data</Label>
                  <Textarea placeholder="user=admin&pass=1234" value={target.data} onChange={(e) => setTarget({...target, data: e.target.value})} disabled={target.method === "GET"} />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle>Session & Auth</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label className="flex items-center gap-2"><Lock className="h-4 w-4" /> 쿠키 (Cookie / Session Token)</Label>
                  <Input placeholder="session=...; auth_token=..." value={options.cookie} onChange={(e) => setOptions({...options, cookie: e.target.value})} />
                </div>
                <Separator />
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <Label>Custom Headers (API Keys, etc.)</Label>
                    <Button variant="outline" size="sm" onClick={() => setHeaders([...headers, { name: "", value: "" }])}>
                      <Plus className="h-3 w-3 mr-1" /> 추가
                    </Button>
                  </div>
                  <ScrollArea className="h-[150px] pr-4">
                    {headers.map((h, i) => (
                      <div key={i} className="flex gap-2 mb-2">
                        <Input placeholder="Name" className="h-8" value={h.name} onChange={(e) => {
                          const n = [...headers]; n[i].name = e.target.value; setHeaders(n);
                        }} />
                        <Input placeholder="Value" className="h-8" value={h.value} onChange={(e) => {
                          const n = [...headers]; n[i].value = e.target.value; setHeaders(n);
                        }} />
                        <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setHeaders(headers.filter((_, idx) => idx !== i))}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    ))}
                  </ScrollArea>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 3. 치트시트 */}
        <TabsContent value="cheatsheet">
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <Card className="lg:col-span-1">
              <CardHeader><CardTitle className="text-sm uppercase tracking-wider">Attack Types</CardTitle></CardHeader>
              <CardContent className="p-2">
                {Object.keys(cheatsheets).map(key => (
                  <Button key={key} variant={selectedCheat === key ? "secondary" : "ghost"} className="w-full justify-start mb-1 capitalize" onClick={() => setSelectedCheat(key)}>
                    <ChevronRight className="h-4 w-4 mr-2" /> {key}
                  </Button>
                ))}
              </CardContent>
            </Card>
            <Card className="lg:col-span-3">
              <div ref={cheatScrollRef}>
              <ScrollArea className="h-[600px]">
                <CardHeader>
                  <CardTitle className="text-2xl capitalize">{selectedCheat} Cheat Sheet</CardTitle>
                </CardHeader>
                <CardContent className="space-y-8">
                  {cheatsheets[selectedCheat] && Object.entries(cheatsheets[selectedCheat].categories).map(([catKey, cat]) => (
                    <div key={catKey} className="space-y-4">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="bg-primary/5">{cat.title}</Badge>
                        <span className="text-xs text-muted-foreground">{cat.description}</span>
                      </div>
                      <div className="space-y-2">
                        {cat.payloads.map((p, idx) => (
                          <div key={idx} className="flex items-center justify-between p-3 border rounded-lg bg-muted/20 hover:bg-muted/40 group">
                            <div className="flex-1 overflow-hidden mr-4">
                              <code className="text-xs font-mono block truncate text-primary">{p.payload}</code>
                              <span className="text-[10px] text-muted-foreground">{p.description}</span>
                            </div>
                            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" onClick={() => copyToClipboard(p.payload)}>
                              <ClipboardCheck className="h-4 w-4" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </CardContent>
              </ScrollArea>
              </div>
            </Card>
          </div>
        </TabsContent>

        {/* 4. 학습 가이드 */}
        <TabsContent value="guides">
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <Card className="lg:col-span-1">
              <CardHeader><CardTitle className="text-sm uppercase tracking-wider">Attack Guides</CardTitle></CardHeader>
              <CardContent className="p-2">
                {Object.keys(guides).map(key => (
                  <Button key={key} variant={selectedGuide === key ? "secondary" : "ghost"} className="w-full justify-start mb-1 capitalize" onClick={() => setSelectedGuide(key)}>
                    <BookOpen className="h-4 w-4 mr-2" /> {key}
                  </Button>
                ))}
              </CardContent>
            </Card>
            <Card className="lg:col-span-3">
              <div ref={guideScrollRef}>
              <ScrollArea className="h-[600px]">
                {guides[selectedGuide] ? (
                  <div className="p-6 space-y-6">
                    <div>
                      <h2 className="text-3xl font-bold mb-2">{guides[selectedGuide].title}</h2>
                      <Badge className="bg-red-500">{guides[selectedGuide].severity.toUpperCase()}</Badge>
                      <Badge variant="outline" className="ml-2">{guides[selectedGuide].difficulty}</Badge>
                    </div>
                    <Separator />
                    <div className="prose prose-sm dark:prose-invert max-w-none">
                      <h3 className="text-lg font-semibold flex items-center gap-2"><Info className="h-4 w-4" /> Overview</h3>
                      <p className="text-muted-foreground whitespace-pre-wrap">{guides[selectedGuide].overview}</p>
                      
                      <h3 className="text-lg font-semibold mt-6">Impact</h3>
                      <ul className="list-disc pl-5 space-y-1">
                        {guides[selectedGuide].impact?.map((item: string, i: number) => (
                          <li key={i} className="text-muted-foreground">{item}</li>
                        ))}
                      </ul>

                      <h3 className="text-lg font-semibold mt-6">CTF Tips</h3>
                      <div className="bg-muted/50 p-4 rounded-lg border border-primary/20">
                        {guides[selectedGuide].ctf_tips?.map((tip: string, i: number) => (
                          <div key={i} className="flex gap-2 mb-2 text-sm">
                            <Zap className="h-4 w-4 text-yellow-500 shrink-0" /> {tip}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="h-full flex items-center justify-center text-muted-foreground">가이드를 선택해주세요.</div>
                )}
              </ScrollArea>
              </div>
            </Card>
          </div>
        </TabsContent>

        {/* 5. 유틸리티 (인코더/디코더) */}
        <TabsContent value="utils">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle>Encoder / Decoder Utility</CardTitle>
                <div className="flex border rounded-lg overflow-hidden">
                  <Button 
                    variant={encodeMode === "encode" ? "secondary" : "ghost"} 
                    className="rounded-none h-8 px-4 text-xs"
                    onClick={() => setEncodeMode("encode")}
                  >Encode</Button>
                  <Button 
                    variant={encodeMode === "decode" ? "secondary" : "ghost"} 
                    className="rounded-none h-8 px-4 text-xs"
                    onClick={() => setEncodeMode("decode")}
                  >Decode</Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label>{encodeMode === "encode" ? "입력 텍스트 (Payload to Encode)" : "인코딩된 텍스트 (Data to Decode)"}</Label>
                <Textarea 
                  placeholder={encodeMode === "encode" ? "admin' OR 1=1--" : "YWRtaW4nIE9SIDEnPScxLS0="} 
                  rows={4} 
                  value={encodeInput} 
                  onChange={(e) => setEncodeInput(e.target.value)} 
                />
                <Button onClick={runEncoder} className="w-full">변환 실행 ({encodeMode.toUpperCase()})</Button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(encodeOutput).map(([type, val]) => (
                  <div key={type} className="p-3 border rounded-lg space-y-1 bg-muted/10">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] uppercase font-bold text-muted-foreground">{type}</span>
                      <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => copyToClipboard(val)}>
                        <ClipboardCheck className="h-3 w-3" />
                      </Button>
                    </div>
                    <code className="text-xs break-all block text-primary">{val}</code>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 5. 스캔 결과 및 실시간 로그 */}
        <TabsContent value="logs" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="lg:col-span-1 h-[600px] flex flex-col bg-black border-slate-800">
              <CardHeader className="border-b border-slate-800 pb-3">
                <CardTitle className="text-sm text-slate-400 flex items-center gap-2">
                  <Terminal className="h-4 w-4" /> Live Terminal
                </CardTitle>
              </CardHeader>
              <CardContent ref={logTerminalRef} className="flex-1 overflow-auto p-4 font-mono text-[11px] text-green-500 space-y-1">
                {logs.map((log, i) => (
                  <div key={i}><span className="text-slate-600 mr-2">$</span>{log}</div>
                ))}
                {loading && <div className="animate-pulse">_</div>}
              </CardContent>
            </Card>

            <Card className="lg:col-span-2 h-[600px] flex flex-col">
              <CardHeader><CardTitle className="flex items-center gap-2 text-destructive"><Bug className="h-5 w-5" /> Vulnerability Findings ({results.length})</CardTitle></CardHeader>
              <CardContent ref={logResultsRef} className="flex-1 overflow-auto p-4 space-y-4">
                {results.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-muted-foreground opacity-30">
                    <Search className="h-12 w-12 mb-2" />
                    <p>탐지된 취약점이 아직 없습니다.</p>
                  </div>
                ) : (
                  results.map((res, i) => (
                    <div key={i} className="p-4 border rounded-xl border-destructive/20 bg-destructive/5 hover:border-destructive/50 transition-all">
                      <div className="flex justify-between items-start mb-3">
                        <Badge variant="destructive" className="px-3 py-1">{res.type}</Badge>
                        <Badge variant="outline" className="text-xs bg-background">Confidence: {res.confidence}</Badge>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-1">
                          <span className="text-[10px] font-bold text-muted-foreground uppercase">Payload</span>
                          <div className="p-2 bg-muted rounded font-mono text-[11px] break-all border group relative">
                            {res.payload}
                            <Button variant="ghost" size="sm" className="absolute top-1 right-1 h-6 w-6 opacity-0 group-hover:opacity-100" onClick={() => copyToClipboard(res.payload)}>
                              <ClipboardCheck className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="space-y-1">
                          <span className="text-[10px] font-bold text-muted-foreground uppercase">Evidence</span>
                          <p className="text-[11px] text-muted-foreground line-clamp-3 italic">"{res.evidence}"</p>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 6. 설정 (Advanced) */}
        <TabsContent value="settings">
          <Card>
            <CardHeader><CardTitle>Scanner Engine Settings</CardTitle></CardHeader>
            <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Proxy URL (Burp Suite, etc.)</Label>
                  <Input placeholder="http://127.0.0.1:8080" value={options.proxy} onChange={(e) => setOptions({...options, proxy: e.target.value})} />
                </div>
                <div className="space-y-2">
                  <Label>Request Timeout (Seconds)</Label>
                  <Input type="number" value={options.timeout} onChange={(e) => setOptions({...options, timeout: parseInt(e.target.value)})} />
                </div>
              </div>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Rate Limit (Requests per Second)</Label>
                  <Input type="number" value={options.rateLimit} onChange={(e) => setOptions({...options, rateLimit: parseInt(e.target.value)})} />
                </div>
                <div className="space-y-2">
                  <Label>Concurrent Threads</Label>
                  <Input type="number" value={options.threads} onChange={(e) => setOptions({...options, threads: parseInt(e.target.value)})} />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
