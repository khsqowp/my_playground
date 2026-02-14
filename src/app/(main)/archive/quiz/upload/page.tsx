"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CsvUploader } from "@/components/archive/CsvUploader";
import { toast } from "sonner";
import { Loader2, Upload } from "lucide-react";

interface ParsedQuestion {
  question: string;
  answer: string;
  hint?: string;
}

export default function QuizUploadPage() {
  const router = useRouter();
  const [title, setTitle] = useState("");
  const [questions, setQuestions] = useState<ParsedQuestion[]>([]);
  const [loading, setLoading] = useState(false);

  async function handleSubmit() {
    if (!title.trim()) { toast.error("제목을 입력해주세요"); return; }
    if (questions.length === 0) { toast.error("CSV를 먼저 업로드해주세요"); return; }

    setLoading(true);
    try {
      const res = await fetch("/api/archive/quiz", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, questions }),
      });
      if (!res.ok) throw new Error();
      toast.success(`${questions.length}개 문제가 포함된 퀴즈가 생성되었습니다!`);
      router.push("/archive/quiz");
    } catch {
      toast.error("퀴즈 생성에 실패했습니다");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <h1 className="text-2xl font-bold">퀴즈 CSV 업로드</h1>

      <div className="space-y-4">
        <div className="space-y-2">
          <Label>퀴즈 제목</Label>
          <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="예: 네트워크 보안 기초" />
        </div>

        <CsvUploader onParsed={setQuestions} />

        {questions.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">미리보기 ({questions.length}개 문제)</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="max-h-64 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left p-2">#</th>
                      <th className="text-left p-2">문제</th>
                      <th className="text-left p-2">답변</th>
                      <th className="text-left p-2">힌트</th>
                    </tr>
                  </thead>
                  <tbody>
                    {questions.map((q, i) => (
                      <tr key={i} className="border-b">
                        <td className="p-2">{i + 1}</td>
                        <td className="p-2 max-w-[200px] truncate">{q.question}</td>
                        <td className="p-2 max-w-[200px] truncate">{q.answer}</td>
                        <td className="p-2 max-w-[100px] truncate">{q.hint || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}

        <Button onClick={handleSubmit} disabled={loading || questions.length === 0} className="w-full">
          {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Upload className="mr-2 h-4 w-4" />}
          퀴즈 세트 생성
        </Button>
      </div>
    </div>
  );
}
