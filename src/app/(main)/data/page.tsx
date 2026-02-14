export const dynamic = "force-dynamic";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { StickyNote, Database, Search, Upload, Folder } from "lucide-react";

export default async function DataPage() {
  const [memoCount, collectionCount, recordCount] = await Promise.all([
    prisma.memo.count(),
    prisma.dataCollection.count(),
    prisma.dataRecord.count(),
  ]);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">데이터 관리</h1>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Link href="/data/collections">
          <Card className="hover:shadow-md transition-shadow cursor-pointer h-full">
            <CardHeader className="flex flex-row items-center gap-2 pb-2">
              <Database className="h-5 w-5 text-blue-500" />
              <CardTitle className="text-base">DB 탐색기 (Collections)</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">데이터베이스 모델 및 데이터 조회</p>
            </CardContent>
          </Card>
        </Link>
        <Link href="/data/files">
          <Card className="hover:shadow-md transition-shadow cursor-pointer h-full">
            <CardHeader className="flex flex-row items-center gap-2 pb-2">
              <Folder className="h-5 w-5 text-yellow-500" />
              <CardTitle className="text-base">파일 탐색기 (Files)</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">프로젝트 파일 열람 및 다운로드</p>
            </CardContent>
          </Card>
        </Link>

        {/* Existing Links */}
        <Link href="/data/memo">
          <Card className="hover:shadow-md transition-shadow h-full">
            <CardHeader className="flex flex-row items-center gap-2 pb-2">
              <StickyNote className="h-5 w-5" />
              <CardTitle className="text-base">메모</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{memoCount}</p>
            </CardContent>
          </Card>
        </Link>

        <Link href="/data/search">
          <Card className="hover:shadow-md transition-shadow h-full">
            <CardHeader className="flex flex-row items-center gap-2 pb-2">
              <Search className="h-5 w-5" />
              <CardTitle className="text-base">검색</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">통합 검색</p>
            </CardContent>
          </Card>
        </Link>

        {/* Legacy Collection (Optional, moved to end or hidden if replaced) */}
        {/* We keep it accessible but deemphasized if needed, or replace entirely. 
            User replaced "Collection" concept with DB Explorer. 
            Let's keep 'browse' as 'Custom Data' if user still has data there. */}
        <Link href="/data/browse">
          <Card className="hover:shadow-md transition-shadow opacity-60 h-full">
            <CardHeader className="flex flex-row items-center gap-2 pb-2">
              <Database className="h-5 w-5 text-gray-400" />
              <CardTitle className="text-base">Custom Data</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">Legacy Collections: {collectionCount}</p>
            </CardContent>
          </Card>
        </Link>
      </div>
    </div>
  );
}
