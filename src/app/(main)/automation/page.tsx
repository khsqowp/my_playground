export const dynamic = "force-dynamic";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Webhook, ScrollText, Brain } from "lucide-react";

export default async function AutomationPage() {
  const [webhookCount, logCount, aiCount] = await Promise.all([
    prisma.webhookConfig.count({ where: { enabled: true } }),
    prisma.webhookLog.count(),
    prisma.aiConfig.count(),
  ]);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">자동화</h1>
      <div className="grid gap-4 sm:grid-cols-3">
        <Link href="/automation/webhooks">
          <Card className="hover:shadow-md transition-shadow">
            <CardHeader className="flex flex-row items-center gap-2 pb-2">
              <Webhook className="h-5 w-5" />
              <CardTitle className="text-base">웹훅</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{webhookCount}</p>
              <p className="text-sm text-muted-foreground">활성 웹훅</p>
            </CardContent>
          </Card>
        </Link>
        <Link href="/automation/logs">
          <Card className="hover:shadow-md transition-shadow">
            <CardHeader className="flex flex-row items-center gap-2 pb-2">
              <ScrollText className="h-5 w-5" />
              <CardTitle className="text-base">로그</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{logCount}</p>
              <p className="text-sm text-muted-foreground">전체 로그</p>
            </CardContent>
          </Card>
        </Link>
        <Link href="/automation/ai">
          <Card className="hover:shadow-md transition-shadow">
            <CardHeader className="flex flex-row items-center gap-2 pb-2">
              <Brain className="h-5 w-5" />
              <CardTitle className="text-base">AI 설정</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{aiCount}</p>
              <p className="text-sm text-muted-foreground">설정된 제공자</p>
            </CardContent>
          </Card>
        </Link>
      </div>
    </div>
  );
}
