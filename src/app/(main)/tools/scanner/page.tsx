"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Shield, Play, Loader2 } from "lucide-react";

export default function ScannerPage() {
  const [target, setTarget] = useState("");
  const [results, setResults] = useState("");
  const [running, setRunning] = useState(false);

  async function runScan() {
    if (!target.trim()) return;
    setRunning(true);
    setResults("스캔 중... (이것은 플레이스홀더입니다 - 스캐너 백엔드를 연결하세요)\n");

    // Placeholder - would connect to actual scanner API
    setTimeout(() => {
      setResults(
        `스캔 결과: ${target}\n` +
        `================================\n` +
        `상태: 플레이스홀더\n` +
        `\n실제 스캔 기능을 활성화하려면\n` +
        `보안 스캐너 백엔드를 연결하세요.`
      );
      setRunning(false);
    }, 2000);
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <h1 className="text-2xl font-bold flex items-center gap-2">
        <Shield className="h-6 w-6" /> 보안 스캐너
      </h1>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">스캔 대상</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>대상 URL 또는 IP</Label>
            <div className="flex gap-2">
              <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://example.com" />
              <Button onClick={runScan} disabled={running}>
                {running ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}
                스캔
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {results && (
        <Card>
          <CardHeader><CardTitle className="text-base">결과</CardTitle></CardHeader>
          <CardContent>
            <Textarea value={results} readOnly className="font-mono text-sm min-h-[300px]" />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
