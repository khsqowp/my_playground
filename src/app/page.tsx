import Link from "next/link";
import { PublicNav } from "@/components/layout/PublicNav";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PenSquare, UserCircle, ShieldAlert, Sparkles } from "lucide-react";

export default function Home() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <PublicNav />
      
      <main className="flex-1 flex flex-col items-center justify-center p-6 relative overflow-hidden">
        {/* Background Decoration */}
        <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-primary/10 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />

        <div className="z-10 text-center space-y-8 max-w-4xl w-full">
          <div className="space-y-4">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-muted border text-xs font-medium text-muted-foreground animate-bounce">
              <ShieldAlert className="h-3.5 w-3.5 text-primary" />
              보안 강화 및 리팩토링 진행 중
            </div>
            <h1 className="text-5xl md:text-7xl font-black tracking-tighter bg-gradient-to-b from-foreground to-foreground/50 bg-clip-text text-transparent">
              보안으로 리팩토링중
            </h1>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              기술적 호기심과 보안 테스팅을 위한 저의 개인 놀이터입니다.<br />
              현재 기능을 하나씩 리팩토링하며 채워가고 있습니다.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 w-full max-w-2xl mx-auto pt-8">
            <Link href="/blog" className="group">
              <Card className="relative h-full overflow-hidden border-2 transition-all hover:border-primary/50 hover:shadow-xl hover:shadow-primary/10 bg-card/50 backdrop-blur">
                <CardContent className="p-8 flex flex-col items-center text-center space-y-4">
                  <div className="p-4 rounded-2xl bg-primary/10 group-hover:bg-primary/20 transition-colors">
                    <PenSquare className="h-10 w-10 text-primary" />
                  </div>
                  <div className="space-y-2">
                    <h2 className="text-2xl font-bold">블로그 입장</h2>
                    <p className="text-sm text-muted-foreground">
                      개발 지식, 보안 취약점 연구 및<br />일상의 기록들을 확인해보세요.
                    </p>
                  </div>
                  <Button variant="ghost" className="group-hover:translate-x-1 transition-transform">
                    구경하러 가기 &rarr;
                  </Button>
                </CardContent>
              </Card>
            </Link>

            <Link href="/portfolio" className="group">
              <Card className="relative h-full overflow-hidden border-2 transition-all hover:border-primary/50 hover:shadow-xl hover:shadow-primary/10 bg-card/50 backdrop-blur">
                <CardContent className="p-8 flex flex-col items-center text-center space-y-4">
                  <div className="p-4 rounded-2xl bg-blue-500/10 group-hover:bg-blue-500/20 transition-colors">
                    <UserCircle className="h-10 w-10 text-blue-500" />
                  </div>
                  <div className="space-y-2">
                    <h2 className="text-2xl font-bold">포트폴리오</h2>
                    <p className="text-sm text-muted-foreground">
                      진행했던 프로젝트들과<br />기술적 역량을 정리해두었습니다.
                    </p>
                  </div>
                  <Button variant="ghost" className="group-hover:translate-x-1 transition-transform">
                    프로젝트 보기 &rarr;
                  </Button>
                </CardContent>
              </Card>
            </Link>
          </div>

          <div className="pt-12 flex items-center justify-center gap-6 text-muted-foreground">
            <div className="flex items-center gap-2 text-sm italic">
              <Sparkles className="h-4 w-4" />
              Everything is under construction...
            </div>
          </div>
        </div>
      </main>

      <footer className="py-6 border-t bg-muted/20">
        <div className="container text-center text-xs text-muted-foreground">
          &copy; {new Date().getFullYear()} 보안으로 리팩토링중. All rights reserved.
        </div>
      </footer>
    </div>
  );
}
