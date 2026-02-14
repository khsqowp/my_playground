export const dynamic = "force-dynamic";
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { WidgetGrid } from '@/components/dashboard/WidgetGrid';
import { QuickMemo } from '@/components/dashboard/QuickMemo';
import { RecentActivity } from '@/components/dashboard/RecentActivity';
import { CustomLinks } from '@/components/dashboard/CustomLinks';
import prisma from '@/lib/prisma';
import { FileText, BookOpen, StickyNote, Database, Zap, Archive } from 'lucide-react';
import Link from 'next/link';

// Server Component - fetches data directly from Prisma
async function getDashboardStats(userId: string) {
  const [postsCount, notesCount, memosCount] = await Promise.all([
    prisma.post.count({
      where: { authorId: userId },
    }),
    prisma.note.count({
      where: { authorId: userId },
    }),
    prisma.memo.count({
      where: { authorId: userId },
    }),
  ]);

  return {
    posts: postsCount,
    notes: notesCount,
    memos: memosCount,
  };
}

async function getRecentPosts(userId: string) {
  return await prisma.post.findMany({
    where: { authorId: userId },
    orderBy: { createdAt: 'desc' },
    take: 3,
    select: {
      id: true,
      title: true,
      published: true,
      createdAt: true,
    },
  });
}

// Quick links configuration
const quickLinks = [
  {
    title: '블로그 글',
    description: '블로그 글 작성 및 관리',
    href: '/blog',
    icon: FileText,
    color: 'bg-blue-500',
  },
  {
    title: '아카이브',
    description: '학습 노트 및 자료 모음',
    href: '/archive',
    icon: BookOpen,
    color: 'bg-green-500',
  },
  {
    title: '데이터 허브',
    description: '콜렉션 및 레코드 관리',
    href: '/data',
    icon: Database,
    color: 'bg-purple-500',
  },
  {
    title: '자동화',
    description: '웹훅 및 AI 연동',
    href: '/automation',
    icon: Zap,
    color: 'bg-yellow-500',
  },
];

import { auth } from "@/lib/auth";
import { redirect } from "next/navigation";

export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;

  const stats = await getDashboardStats(userId);
  const recentPosts = await getRecentPosts(userId);

  return (
    <div className="container mx-auto px-4 py-8 space-y-8">
      {/* Welcome Section */}
      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">돌아오신 것을 환영합니다!</h1>
        <p className="text-muted-foreground">
          오늘의 콘텐츠 현황을 확인하세요.
        </p>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">전체 글</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.posts}</div>
            <p className="text-xs text-muted-foreground mt-1">
              발행 및 임시저장 글
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">학습 노트</CardTitle>
            <BookOpen className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.notes}</div>
            <p className="text-xs text-muted-foreground mt-1">
              아카이브된 학습 자료
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">빠른 메모</CardTitle>
            <StickyNote className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.memos}</div>
            <p className="text-xs text-muted-foreground mt-1">
              저장된 메모 및 리마인더
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Quick Links Grid */}
      <div>
        <h2 className="text-xl font-semibold mb-4">빠른 접근</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {quickLinks.map((link) => {
            const Icon = link.icon;
            return (
              <Link key={link.href} href={link.href}>
                <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                  <CardContent className="p-6">
                    <div className="flex items-start space-x-4">
                      <div className={`${link.color} p-3 rounded-lg`}>
                        <Icon className="h-6 w-6 text-white" />
                      </div>
                      <div className="flex-1">
                        <h3 className="font-semibold mb-1">{link.title}</h3>
                        <p className="text-sm text-muted-foreground">
                          {link.description}
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </Link>
            );
          })}
        </div>
      </div>

      {/* Widget Grid - Client Components */}
      <div>
        <h2 className="text-xl font-semibold mb-4">대시보드 위젯</h2>
        <WidgetGrid>
          <QuickMemo />
          <RecentActivity />
          <CustomLinks />
        </WidgetGrid>
      </div>

      {/* Recent Posts */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg font-semibold">최근 글</CardTitle>
            <Link
              href="/blog"
              className="text-sm text-primary hover:underline"
            >
              전체 보기
            </Link>
          </div>
        </CardHeader>
        <CardContent>
          {recentPosts.length === 0 ? (
            <div className="text-center py-12">
              <Archive className="w-12 h-12 text-muted-foreground/50 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground mb-4">
                아직 글이 없습니다. 글을 작성해보세요!
              </p>
              <Link href="/blog/new">
                <button className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors">
                  첫 번째 글 작성하기
                </button>
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {recentPosts.map((post) => (
                <Link
                  key={post.id}
                  href={`/blog/${post.id}`}
                  className="block p-4 rounded-lg border hover:bg-accent/50 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h3 className="font-medium mb-1">{post.title}</h3>
                      <p className="text-xs text-muted-foreground">
                        {new Date(post.createdAt).toLocaleDateString('ko-KR', {
                          month: 'short',
                          day: 'numeric',
                          year: 'numeric',
                        })}
                      </p>
                    </div>
                    <span
                      className={`text-xs px-2 py-1 rounded ${post.published
                        ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                        : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                        }`}
                    >
                      {post.published ? '발행됨' : '임시저장'}
                    </span>
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
