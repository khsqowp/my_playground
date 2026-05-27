export const dynamic = "force-dynamic";

import Link from "next/link";
import { redirect } from "next/navigation";
import {
  Archive,
  BookOpen,
  Database,
  FileArchive,
  FileText,
  Globe2,
  Inbox,
  StickyNote,
} from "lucide-react";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { listCaptures, listWatchlist } from "@/lib/site-archive";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { QuickMemo } from "@/components/dashboard/QuickMemo";
import { RecentActivity } from "@/components/dashboard/RecentActivity";
import { CustomLinks } from "@/components/dashboard/CustomLinks";
import { ClockCard } from "@/components/dashboard/ClockCard";

async function getDashboardData(userId: string) {
  const [posts, notes, memos, archiveFiles, recentPosts, recentFiles, watches, captures] = await Promise.all([
    prisma.post.count({ where: { authorId: userId } }),
    prisma.note.count({ where: { authorId: userId } }),
    prisma.memo.count({ where: { authorId: userId } }),
    prisma.archiveFile.count({ where: { authorId: userId } }),
    prisma.post.findMany({
      where: { authorId: userId },
      orderBy: { updatedAt: "desc" },
      take: 4,
      select: { id: true, title: true, published: true, updatedAt: true },
    }),
    prisma.archiveFile.findMany({
      where: { authorId: userId },
      orderBy: { updatedAt: "desc" },
      take: 5,
      select: { id: true, fileName: true, folder: true, aiStatus: true, updatedAt: true },
    }),
    listWatchlist(userId),
    listCaptures(userId),
  ]);

  const recentCaptures = captures.slice(0, 5);
  const unreadArchivePrompt = recentCaptures.filter((capture) => {
    const capturedAt = new Date(capture.data.capturedAt).getTime();
    return Number.isFinite(capturedAt) && Date.now() - capturedAt < 1000 * 60 * 60 * 24 * 7;
  });

  return {
    stats: {
      posts,
      notes,
      memos,
      archiveFiles,
      siteWatches: watches.length,
      siteCaptures: captures.length,
      dailyWatches: watches.filter((watch) => watch.data.enabled && watch.data.schedule === "daily").length,
    },
    recentPosts,
    recentFiles,
    recentCaptures,
    unreadArchivePrompt,
  };
}

function formatDate(value: Date | string) {
  return new Date(value).toLocaleDateString("ko-KR", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");

  const { stats, recentPosts, recentFiles, recentCaptures, unreadArchivePrompt } = await getDashboardData(session.user.id);

  const primaryLinks = [
    {
      title: "사이트 아카이브",
      description: "페이지를 로컬 저장본으로 보관",
      href: "/archive/sites",
      icon: Globe2,
    },
    {
      title: "RAG 프로젝트 관리",
      description: "파일 자료와 벡터화 상태 관리",
      href: "/archive/files/manage",
      icon: FileArchive,
    },
    {
      title: "데이터 허브",
      description: "JSON 컬렉션과 레코드 관리",
      href: "/data",
      icon: Database,
    },
    {
      title: "글 관리",
      description: "블로그 글과 초안 정리",
      href: "/manage/blog",
      icon: FileText,
    },
  ];

  return (
    <div className="space-y-6 px-4 py-6 lg:px-8">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">대시보드</h1>
          <p className="mt-1 text-muted-foreground">
            오늘 확인할 저장본, 자료 상태, 최근 작업을 한 화면에서 봅니다.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge variant="secondary">{stats.dailyWatches}개 자동 아카이브 활성</Badge>
          <Badge variant="outline">{stats.siteCaptures}개 사이트 저장본</Badge>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
        <Card>
          <CardHeader>
            <CardTitle>오늘 볼 것</CardTitle>
            <CardDescription>최근 저장된 사이트 아카이브와 확인할 자료를 우선 표시합니다.</CardDescription>
          </CardHeader>
          <CardContent>
            {unreadArchivePrompt.length === 0 ? (
              <div className="flex items-center gap-3 rounded-md border p-4 text-sm text-muted-foreground">
                <Inbox className="h-5 w-5" />
                최근 7일 내 새 사이트 저장본이 없습니다.
              </div>
            ) : (
              <div className="space-y-3">
                {unreadArchivePrompt.slice(0, 4).map((capture) => (
                  <Link
                    key={capture.id}
                    href="/archive/sites"
                    className="block rounded-md border p-4 transition-colors hover:bg-accent/50"
                  >
                    <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                      <div className="min-w-0">
                        <div className="truncate font-medium">{capture.data.title}</div>
                        <div className="mt-1 truncate text-xs text-muted-foreground">{capture.data.sourceUrl}</div>
                      </div>
                      <Badge variant={capture.data.changed ? "secondary" : "outline"}>
                        {capture.data.changed ? "변경됨" : "확인됨"}
                      </Badge>
                    </div>
                    <p className="mt-2 line-clamp-2 text-sm text-muted-foreground">{capture.data.textPreview}</p>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <ClockCard />
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
        {[
          { label: "글", value: stats.posts, icon: FileText },
          { label: "노트", value: stats.notes, icon: BookOpen },
          { label: "메모", value: stats.memos, icon: StickyNote },
          { label: "파일", value: stats.archiveFiles, icon: FileArchive },
          { label: "수집 URL", value: stats.siteWatches, icon: Globe2 },
          { label: "페이지 저장본", value: stats.siteCaptures, icon: Archive },
        ].map((item) => (
          <Card key={item.label}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{item.label}</CardTitle>
              <item.icon className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{item.value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {primaryLinks.map((link) => (
          <Link key={link.href} href={link.href}>
            <Card className="h-full transition-colors hover:bg-accent/50">
              <CardContent className="flex items-start gap-4 p-5">
                <div className="rounded-md bg-primary/10 p-2 text-primary">
                  <link.icon className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="font-semibold">{link.title}</h2>
                  <p className="mt-1 text-sm text-muted-foreground">{link.description}</p>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>최근 사이트 저장본</CardTitle>
            <CardDescription>자동 또는 수동으로 로컬에 저장한 페이지입니다.</CardDescription>
          </CardHeader>
          <CardContent>
            {recentCaptures.length === 0 ? (
              <p className="py-10 text-center text-sm text-muted-foreground">아직 사이트 저장본이 없습니다.</p>
            ) : (
              <div className="space-y-3">
                {recentCaptures.map((capture) => (
                  <Link key={capture.id} href="/archive/sites" className="block rounded-md border p-3 hover:bg-accent/50">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium">{capture.data.title}</div>
                        <div className="mt-1 truncate text-xs text-muted-foreground">{capture.data.folder}</div>
                      </div>
                      <span className="shrink-0 text-xs text-muted-foreground">{formatDate(capture.data.capturedAt)}</span>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>최근 RAG 파일</CardTitle>
            <CardDescription>최근 업로드되거나 갱신된 아카이브 파일입니다.</CardDescription>
          </CardHeader>
          <CardContent>
            {recentFiles.length === 0 ? (
              <p className="py-10 text-center text-sm text-muted-foreground">아직 파일 아카이브가 없습니다.</p>
            ) : (
              <div className="space-y-3">
                {recentFiles.map((file) => (
                  <Link key={file.id} href={`/archive/files/${file.id}`} className="block rounded-md border p-3 hover:bg-accent/50">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium">{file.fileName}</div>
                        <div className="mt-1 flex flex-wrap gap-2">
                          <Badge variant="outline">{file.folder}</Badge>
                          <Badge variant="secondary">{file.aiStatus}</Badge>
                        </div>
                      </div>
                      <span className="shrink-0 text-xs text-muted-foreground">{formatDate(file.updatedAt)}</span>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <QuickMemo />
        <RecentActivity />
        <CustomLinks />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>최근 글</CardTitle>
          <CardDescription>마지막으로 수정한 글과 발행 상태입니다.</CardDescription>
        </CardHeader>
        <CardContent>
          {recentPosts.length === 0 ? (
            <p className="py-10 text-center text-sm text-muted-foreground">아직 글이 없습니다.</p>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {recentPosts.map((post) => (
                <Link key={post.id} href={`/blog/edit/${post.id}`} className="rounded-md border p-4 hover:bg-accent/50">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate font-medium">{post.title}</div>
                      <div className="mt-1 text-xs text-muted-foreground">{formatDate(post.updatedAt)}</div>
                    </div>
                    <Badge variant={post.published ? "secondary" : "outline"}>{post.published ? "발행" : "초안"}</Badge>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
