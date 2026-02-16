import Link from "next/link";
import { PublicNav } from "@/components/layout/PublicNav";
import { Button } from "@/components/ui/button";
import { PenSquare, UserCircle } from "lucide-react";

export default function Home() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <PublicNav />
      
      <main className="flex-1 flex flex-col items-center justify-center p-6 text-center">
        <div className="space-y-6 max-w-md w-full">
          <div className="space-y-2">
            <h1 className="text-4xl font-bold tracking-tight">
              보안으로 리다이렉트 중
            </h1>
            <p className="text-muted-foreground">
              개인 공부와 프로젝트를 기록하는 공간입니다.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-3 pt-4">
            <Button asChild variant="outline" size="lg" className="h-16 text-lg justify-start px-6 gap-4 border-2">
              <Link href="/blog">
                <PenSquare className="h-5 w-5 text-primary" />
                <span>블로그</span>
              </Link>
            </Button>

            <Button asChild variant="outline" size="lg" className="h-16 text-lg justify-start px-6 gap-4 border-2">
              <Link href="/portfolio">
                <UserCircle className="h-5 w-5 text-blue-500" />
                <span>포트폴리오</span>
              </Link>
            </Button>
          </div>

          <div className="pt-8 text-[10px] text-muted-foreground uppercase tracking-[0.2em]">
            under construction
          </div>
        </div>
      </main>

      <footer className="py-6 text-center text-[11px] text-muted-foreground border-t bg-muted/5">
        &copy; {new Date().getFullYear()} 보안으로 리다이렉트 중
      </footer>
    </div>
  );
}
