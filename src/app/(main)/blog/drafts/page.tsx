export const dynamic = "force-dynamic";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatDate } from "@/lib/utils";
import { ArrowLeft, Edit } from "lucide-react";

export default async function DraftsPage() {
  const drafts = await prisma.post.findMany({
    where: { published: false },
    include: {
      category: { select: { name: true } },
    },
    orderBy: { updatedAt: "desc" },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/blog"><ArrowLeft className="mr-2 h-4 w-4" />뒤로</Link>
        </Button>
        <h1 className="text-2xl font-bold">임시저장 ({drafts.length})</h1>
      </div>

      {drafts.length === 0 ? (
        <p className="text-muted-foreground">임시저장된 글이 없습니다</p>
      ) : (
        <div className="space-y-3">
          {drafts.map((draft) => (
            <Card key={draft.id}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{draft.title}</CardTitle>
                  <Button variant="ghost" size="sm" asChild>
                    <Link href={`/blog/edit/${draft.id}`}>
                      <Edit className="mr-1 h-3 w-3" /> 수정
                    </Link>
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  {draft.category && <Badge variant="outline">{draft.category.name}</Badge>}
                  <span>수정일 {formatDate(draft.updatedAt)}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
