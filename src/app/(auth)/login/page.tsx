"use client";

import { Suspense, useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Bike, Loader2 } from "lucide-react";
import { toast } from "sonner";

import Link from "next/link";

function LoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") || "/dashboard";

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const result = await signIn("credentials", {
        email,
        password,
        redirect: false,
      });

      console.log("Login Result:", result);
      setLoading(false);

      if (result?.error) {
        if (result.code === "pending_approval" || result.error.includes("pending_approval")) {
          setError("가입 승인 대기 중입니다. 관리자 승인 후 로그인할 수 있습니다.");
        } else if (result.code === "rejected_account" || result.error.includes("rejected_account")) {
          setError("가입이 거절되었거나 정지된 계정입니다. 관리자에게 문의하세요.");
        } else if (result.error === "CredentialsSignin") {
          setError("이메일/비밀번호가 올바르지 않거나 계정이 아직 승인되지 않았습니다.");
        } else {
          setError(result.error || "로그인에 실패했습니다. 정보를 다시 확인해주세요.");
        }
      } else {
        toast.success("로그인 성공!");
        router.push(callbackUrl);
        router.refresh();
      }
    } catch (err: any) {
      setLoading(false);
      setError("로그인 중 오류가 발생했습니다.");
    }
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-4">
          <Bike className="h-12 w-12" />
        </div>
        <CardTitle className="text-2xl font-bold">88Motorcycle</CardTitle>
        <CardDescription>개인 플랫폼에 로그인하세요</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor="email">이메일</Label>
            <Input
              id="email"
              type="email"
              placeholder="admin@88motorcycle.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">비밀번호</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            로그인
          </Button>
        </form>
        <div className="text-center text-sm text-muted-foreground mt-4">
          계정이 없으신가요?{" "}
          <Link href="/register" className="text-primary underline underline-offset-4 hover:text-primary/80">
            가입 신청하기
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}

export default function LoginPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Suspense fallback={<div className="animate-pulse">로딩 중...</div>}>
        <LoginForm />
      </Suspense>
    </div>
  );
}
