export const dynamic = "force-dynamic";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { BookOpen, HelpCircle, Search, Plus } from "lucide-react";

export default async function ArchivePage() {
  const [noteCount, quizCount, recentNotes, recentQuizzes] = await Promise.all([
    prisma.note.count(),
    prisma.quizSet.count(),
    prisma.note.findMany({
      take: 5,
      orderBy: { createdAt: "desc" },
      select: { id: true, title: true, createdAt: true },
    }),
    prisma.quizSet.findMany({
      take: 5,
      orderBy: { createdAt: "desc" },
      include: { _count: { select: { questions: true } } },
    }),
  ]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">아카이브</h1>
        <div className="flex gap-2">
          <Button asChild variant="outline">
            <Link href="/archive/search"><Search className="mr-2 h-4 w-4" />검색</Link>
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Link href="/archive/notes">
          <Card className="transition-shadow hover:shadow-md">
            <CardHeader className="flex flex-row items-center gap-2">
              <BookOpen className="h-5 w-5" />
              <CardTitle>노트</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{noteCount}</p>
              <p className="text-sm text-muted-foreground">전체 노트</p>
            </CardContent>
          </Card>
        </Link>
        <Link href="/archive/quiz">
          <Card className="transition-shadow hover:shadow-md">
            <CardHeader className="flex flex-row items-center gap-2">
              <HelpCircle className="h-5 w-5" />
              <CardTitle>퀸즈</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{quizCount}</p>
              <p className="text-sm text-muted-foreground">퀸즈 세트</p>
            </CardContent>
          </Card>
        </Link>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-base">최근 노트</CardTitle>
            <Button size="sm" asChild><Link href="/archive/notes/write"><Plus className="mr-1 h-3 w-3" />새로 작성</Link></Button>
          </CardHeader>
          <CardContent>
            {recentNotes.length === 0 ? (
              <p className="text-sm text-muted-foreground">노트가 없습니다</p>
            ) : (
              <div className="space-y-2">
                {recentNotes.map((note) => (
                  <Link key={note.id} href={`/archive/notes/${note.id}`} className="block rounded px-3 py-2 text-sm hover:bg-accent">
                    {note.title}
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-base">최근 퀸즈 세트</CardTitle>
            <Button size="sm" asChild><Link href="/archive/quiz/upload"><Plus className="mr-1 h-3 w-3" />업로드</Link></Button>
          </CardHeader>
          <CardContent>
            {recentQuizzes.length === 0 ? (
              <p className="text-sm text-muted-foreground">퀸즈 세트가 없습니다</p>
            ) : (
              <div className="space-y-2">
                {recentQuizzes.map((q) => (
                  <Link key={q.id} href={`/archive/quiz/${q.id}`} className="flex items-center justify-between rounded px-3 py-2 text-sm hover:bg-accent">
                    <span>{q.title}</span>
                    <span className="text-muted-foreground">{q._count.questions}Q</span>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
