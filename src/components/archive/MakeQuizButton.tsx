"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Sparkles, Loader2 } from "lucide-react";
import { toast } from "sonner";

interface MakeQuizButtonProps {
  noteId: string;
  title: string;
  content: string;
}

export function MakeQuizButton({ noteId, title, content }: MakeQuizButtonProps) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  const handleClick = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/archive/quiz/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          topic: title,
          content: content.substring(0, 2000),
          count: 5,
          sourceNoteId: noteId,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "생성 실패");
      }
      const quizSet = await res.json();
      toast.success(`퀴즈 세트 "${quizSet.title}" 생성 완료!`);
      router.refresh();
    } catch (err: any) {
      toast.error(err.message || "퀴즈 생성 중 오류가 발생했습니다.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Button variant="outline" size="sm" onClick={handleClick} disabled={loading}>
      {loading ? (
        <>
          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          생성 중...
        </>
      ) : (
        <>
          <Sparkles className="mr-2 h-4 w-4" />
          노트로 퀴즈 만들기
        </>
      )}
    </Button>
  );
}
