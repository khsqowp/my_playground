export const dynamic = "force-dynamic";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { QuizCard } from "@/components/archive/QuizCard";
import { Button } from "@/components/ui/button";
import { QuizGenerateButton } from "@/components/archive/QuizGenerateButton";
import { Upload, HelpCircle } from "lucide-react";

export default async function QuizListPage() {
  const quizSets = await prisma.quizSet.findMany({
    include: {
      author: { select: { name: true } },
      _count: { select: { questions: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">퀴즈 세트</h1>
        <div className="flex gap-2">
          <QuizGenerateButton />
          <Button asChild>
            <Link href="/archive/quiz/upload"><Upload className="mr-2 h-4 w-4" />CSV 업로드</Link>
          </Button>
        </div>
      </div>

      {quizSets.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <HelpCircle className="h-12 w-12 mb-4" />
          <p>퀴즈 세트가 없습니다. CSV를 업로드하거나 AI로 생성해보세요!</p>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {quizSets.map((q) => (
            <QuizCard key={q.id} quiz={q} />
          ))}
        </div>
      )}
    </div>
  );
}
