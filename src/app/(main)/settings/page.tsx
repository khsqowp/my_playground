import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { User, Shield, Server } from "lucide-react";

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">설정</h1>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Link href="/settings/profile">
          <Card className="hover:shadow-md transition-shadow">
            <CardHeader>
              <User className="h-8 w-8 mb-2" />
              <CardTitle>프로필</CardTitle>
              <CardDescription>계정 정보 관리</CardDescription>
            </CardHeader>
          </Card>
        </Link>
        <Link href="/settings/access">
          <Card className="hover:shadow-md transition-shadow">
            <CardHeader>
              <Shield className="h-8 w-8 mb-2" />
              <CardTitle>접근 관리</CardTitle>
              <CardDescription>사용자 및 권한 관리</CardDescription>
            </CardHeader>
          </Card>
        </Link>
        <Link href="/settings/system">
          <Card className="hover:shadow-md transition-shadow">
            <CardHeader>
              <Server className="h-8 w-8 mb-2" />
              <CardTitle>시스템</CardTitle>
              <CardDescription>사이트 설정 및 구성</CardDescription>
            </CardHeader>
          </Card>
        </Link>
      </div>
    </div>
  );
}
