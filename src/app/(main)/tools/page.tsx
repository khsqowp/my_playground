import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Shield, Terminal } from "lucide-react";

export default function ToolsPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">도구</h1>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Link href="/tools/scanner">
          <Card className="hover:shadow-md transition-shadow">
            <CardHeader>
              <Shield className="h-8 w-8 mb-2" />
              <CardTitle>보안 스캐너</CardTitle>
              <CardDescription>진단 스크립트 및 보안 점검 실행</CardDescription>
            </CardHeader>
          </Card>
        </Link>
        <Card className="opacity-50">
          <CardHeader>
            <Terminal className="h-8 w-8 mb-2" />
            <CardTitle>추가 도구</CardTitle>
            <CardDescription>추후 추가 예정...</CardDescription>
          </CardHeader>
        </Card>
      </div>
    </div>
  );
}
