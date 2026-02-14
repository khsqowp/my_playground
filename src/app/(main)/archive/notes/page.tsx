export const dynamic = "force-dynamic";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { NoteCard } from "@/components/archive/NoteCard";
import { Button } from "@/components/ui/button";
import { Plus, BookOpen } from "lucide-react";

export default async function NotesPage() {
  const notes = await prisma.note.findMany({
    include: {
      category: { select: { name: true, color: true } },
      tags: { include: { tag: { select: { name: true } } } },
    },
    orderBy: { createdAt: "desc" },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">노트</h1>
        <Button asChild>
          <Link href="/archive/notes/write"><Plus className="mr-2 h-4 w-4" />노트 작성</Link>
        </Button>
      </div>

      {notes.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <BookOpen className="h-12 w-12 mb-4" />
          <p>노트가 없습니다. 첫 번째 노트를 작성해보세요!</p>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {notes.map((note) => (
            <NoteCard key={note.id} note={{ ...note, createdAt: note.createdAt.toISOString() }} />
          ))}
        </div>
      )}
    </div>
  );
}
