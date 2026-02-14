export const dynamic = "force-dynamic";
import { notFound } from "next/navigation";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { MarkdownRenderer } from "@/components/shared/MarkdownRenderer";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ArrowLeft, Edit, Calendar } from "lucide-react";
import { formatDate } from "@/lib/utils";

export default async function NoteDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  const note = await prisma.note.findUnique({
    where: { id },
    include: {
      author: { select: { name: true } },
      category: true,
      tags: { include: { tag: true } },
    },
  });

  if (!note) notFound();

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/archive/notes"><ArrowLeft className="mr-2 h-4 w-4" />뒤로</Link>
        </Button>
        <Button variant="ghost" size="sm" asChild>
          <Link href={`/archive/notes/write?edit=${note.id}`}>
            <Edit className="mr-1 h-3 w-3" />수정
          </Link>
        </Button>
      </div>

      <div className="space-y-3">
        <h1 className="text-3xl font-bold">{note.title}</h1>
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          {note.category && <Badge style={{ color: note.category.color || undefined }}>{note.category.name}</Badge>}
          <div className="flex items-center gap-1">
            <Calendar className="h-3 w-3" />
            {formatDate(note.createdAt)}
          </div>
          <span>{note.author.name}</span>
        </div>
        <div className="flex flex-wrap gap-1">
          {note.tags.map(({ tag }) => (
            <Badge key={tag.id} variant="outline">{tag.name}</Badge>
          ))}
        </div>
      </div>

      <Separator />

      <article className="prose prose-neutral dark:prose-invert max-w-none">
        <MarkdownRenderer content={note.content} />
      </article>
    </div>
  );
}
