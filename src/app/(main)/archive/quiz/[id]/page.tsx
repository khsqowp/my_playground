"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, ArrowRight, Shuffle, Eye, RotateCcw, Lightbulb } from "lucide-react";

interface Question {
  id: string;
  question: string;
  answer: string;
  hint: string | null;
  order: number;
}

export default function QuizPlayPage() {
  const params = useParams();
  const id = params.id as string;

  const [title, setTitle] = useState("");
  const [questions, setQuestions] = useState<Question[]>([]);
  const [current, setCurrent] = useState(0);
  const [flipped, setFlipped] = useState(false);
  const [showHint, setShowHint] = useState(false);
  const [score, setScore] = useState({ knew: 0, didnt: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/archive/quiz/${id}`)
      .then((r) => r.json())
      .then((data) => {
        setTitle(data.title);
        setQuestions(data.questions);
        setLoading(false);
      });
  }, [id]);

  function shuffle() {
    const shuffled = [...questions].sort(() => Math.random() - 0.5);
    setQuestions(shuffled);
    setCurrent(0);
    setFlipped(false);
    setShowHint(false);
    setScore({ knew: 0, didnt: 0 });
  }

  function next(knew: boolean) {
    setScore((s) => knew ? { ...s, knew: s.knew + 1 } : { ...s, didnt: s.didnt + 1 });
    setFlipped(false);
    setShowHint(false);
    if (current < questions.length - 1) setCurrent((c) => c + 1);
  }

  function reset() {
    setCurrent(0);
    setFlipped(false);
    setShowHint(false);
    setScore({ knew: 0, didnt: 0 });
  }

  if (loading) return <div className="flex justify-center py-12">로딩 중...</div>;
  if (questions.length === 0) return <div className="text-center py-12">이 세트에 문제가 없습니다.</div>;

  const q = questions[current];
  const isLast = current === questions.length - 1;
  const isDone = score.knew + score.didnt === questions.length;

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/archive/quiz"><ArrowLeft className="mr-2 h-4 w-4" />뒤로</Link>
        </Button>
        <h1 className="text-lg font-bold">{title}</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={shuffle}><Shuffle className="mr-1 h-3 w-3" />섞기</Button>
          <Button variant="outline" size="sm" onClick={reset}><RotateCcw className="mr-1 h-3 w-3" />초기화</Button>
        </div>
      </div>

      <div className="flex items-center justify-between text-sm">
        <span>{current + 1} / {questions.length}</span>
        <div className="flex gap-3">
          <Badge variant="secondary" className="bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">알았음: {score.knew}</Badge>
          <Badge variant="secondary" className="bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">몰랐음: {score.didnt}</Badge>
        </div>
      </div>

      <div className="w-full bg-muted rounded-full h-2">
        <div className="bg-primary h-2 rounded-full transition-all" style={{ width: `${((current + 1) / questions.length) * 100}%` }} />
      </div>

      {isDone ? (
        <Card className="text-center py-12">
          <CardContent>
            <h2 className="text-2xl font-bold mb-4">완료!</h2>
            <p className="text-lg">점수: {score.knew}/{questions.length} ({Math.round((score.knew / questions.length) * 100)}%)</p>
            <Button onClick={reset} className="mt-4"><RotateCcw className="mr-2 h-4 w-4" />다시 풀기</Button>
          </CardContent>
        </Card>
      ) : (
        <Card className="min-h-[300px] cursor-pointer" onClick={() => setFlipped(!flipped)}>
          <CardContent className="flex flex-col items-center justify-center min-h-[300px] p-8 text-center">
            {flipped ? (
              <>
                <Badge variant="outline" className="mb-4">답변</Badge>
                <p className="text-xl whitespace-pre-wrap">{q.answer}</p>
              </>
            ) : (
              <>
                <Badge className="mb-4">문제</Badge>
                <p className="text-xl whitespace-pre-wrap">{q.question}</p>
              </>
            )}
          </CardContent>
        </Card>
      )}

      {!isDone && (
        <div className="flex items-center justify-between">
          <div>
            {q.hint && (
              <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); setShowHint(!showHint); }}>
                <Lightbulb className="mr-1 h-3 w-3" />힌트
              </Button>
            )}
          </div>
          {!flipped ? (
            <Button onClick={() => setFlipped(true)}><Eye className="mr-2 h-4 w-4" />답변 보기</Button>
          ) : (
            <div className="flex gap-2">
              <Button variant="outline" className="border-red-300" onClick={() => next(false)}>몰랐음</Button>
              <Button className="bg-green-600 hover:bg-green-700" onClick={() => next(true)}>알았음!</Button>
            </div>
          )}
        </div>
      )}

      {showHint && q.hint && (
        <div className="rounded-md bg-accent p-3 text-sm">{q.hint}</div>
      )}
    </div>
  );
}
