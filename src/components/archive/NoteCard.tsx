import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatDate, truncate } from "@/lib/utils";
import { Calendar } from "lucide-react";

interface NoteCardProps {
  note: {
    id: string;
    title: string;
    content: string;
    category: { name: string; color: string | null } | null;
    tags: { tag: { name: string } }[];
    createdAt: string;
  };
}

export function NoteCard({ note }: NoteCardProps) {
  return (
    <Link href={`/archive/notes/${note.id}`}>
      <Card className="h-full transition-shadow hover:shadow-md">
        <CardHeader className="pb-2">
          {note.category && (
            <Badge variant="secondary" className="w-fit mb-1" style={{ color: note.category.color || undefined }}>
              {note.category.name}
            </Badge>
          )}
          <CardTitle className="text-base line-clamp-2">{note.title}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground line-clamp-3 mb-3">
            {truncate(note.content.replace(/[#*`\[\]]/g, ""), 120)}
          </p>
          <div className="flex flex-wrap gap-1 mb-2">
            {note.tags.slice(0, 3).map(({ tag }) => (
              <Badge key={tag.name} variant="outline" className="text-xs">{tag.name}</Badge>
            ))}
          </div>
          <div className="flex items-center gap-1 text-xs text-muted-foreground">
            <Calendar className="h-3 w-3" />
            {formatDate(note.createdAt)}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
