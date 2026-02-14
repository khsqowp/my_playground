import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { HelpCircle } from "lucide-react";

interface QuizCardProps {
  quiz: {
    id: string;
    title: string;
    description: string | null;
    visibility: string;
    _count: { questions: number };
  };
}

export function QuizCard({ quiz }: QuizCardProps) {
  return (
    <Link href={`/archive/quiz/${quiz.id}`}>
      <Card className="h-full transition-shadow hover:shadow-md">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <HelpCircle className="h-4 w-4" />
            {quiz.title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {quiz.description && (
            <p className="text-sm text-muted-foreground mb-2">{quiz.description}</p>
          )}
          <div className="flex items-center gap-2">
            <Badge variant="secondary">{quiz._count.questions}개 문제</Badge>
            <Badge variant="outline">{quiz.visibility}</Badge>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
