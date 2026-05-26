"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Database,
  ExternalLink,
  FileArchive,
  FolderTree,
  HardDrive,
  Loader2,
  RefreshCcw,
  Search,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface ProjectSummary {
  project: string;
  fileCount: number;
  directoryCount: number;
  supportedCount: number;
  totalSize: number;
  updatedAt: string | null;
  extensions: Record<string, number>;
}

interface StatsResponse {
  root: string;
  defaultProject: string;
  projects: ProjectSummary[];
  totals: {
    fileCount: number;
    directoryCount: number;
    supportedCount: number;
    totalSize: number;
  };
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function topExtensions(extensions: Record<string, number>) {
  return Object.entries(extensions)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
}

export function RagFileManager({ title = "파일 전체 관리" }: { title?: string }) {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [reindexing, setReindexing] = useState<string | null>(null);

  const loadStats = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/rag/files?action=stats");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "전체 현황 조회 실패");
      setStats(data);
    } catch (error: any) {
      toast.error(error.message || "전체 관리 정보를 불러오지 못했습니다.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const filteredProjects = useMemo(() => {
    const projects = stats?.projects || [];
    const q = query.trim().toLowerCase();
    if (!q) return projects;
    return projects.filter((project) => project.project.toLowerCase().includes(q));
  }, [query, stats]);

  const reindexProject = async (project: string) => {
    setReindexing(project);
    try {
      const res = await fetch("/api/rag/files?action=reindex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ project, recreate: true }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || data.error || "재색인 요청 실패");
      toast.success(`${project} 재색인을 시작했습니다.`);
    } catch (error: any) {
      toast.error(error.message || "재색인을 시작하지 못했습니다.");
    } finally {
      setReindexing(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <FileArchive className="h-6 w-6 text-primary" />
            {title}
          </h1>
          <p className="mt-1 text-xs text-muted-foreground">
            RAG 자료 루트: {stats?.root || "로딩 중"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" asChild>
            <Link href="/archive/files">
              <ExternalLink className="mr-2 h-4 w-4" />
              파일 아카이브
            </Link>
          </Button>
          <Button variant="outline" asChild>
            <Link href="/data/files">
              <ExternalLink className="mr-2 h-4 w-4" />
              데이터 파일
            </Link>
          </Button>
          <Button onClick={loadStats} disabled={loading}>
            {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCcw className="mr-2 h-4 w-4" />}
            새로고침
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Database className="h-4 w-4 text-primary" />
              프로젝트
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{stats?.projects.length || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <FileArchive className="h-4 w-4 text-blue-500" />
              전체 파일
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{stats?.totals.fileCount || 0}</p>
            <p className="text-xs text-muted-foreground">지원 형식 {stats?.totals.supportedCount || 0}개</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <FolderTree className="h-4 w-4 text-yellow-500" />
              폴더
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{stats?.totals.directoryCount || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <HardDrive className="h-4 w-4 text-emerald-500" />
              총 용량
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{formatBytes(stats?.totals.totalSize || 0)}</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="gap-3 sm:flex-row sm:items-center sm:justify-between">
          <CardTitle className="text-base">프로젝트별 관리</CardTitle>
          <div className="flex h-9 min-w-64 items-center gap-2 rounded-md border px-3">
            <Search className="h-4 w-4 text-muted-foreground" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="프로젝트 검색"
              className="min-w-0 flex-1 bg-transparent text-sm outline-none"
            />
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              전체 현황 계산 중
            </div>
          ) : filteredProjects.length === 0 ? (
            <div className="py-12 text-center text-sm text-muted-foreground">프로젝트가 없습니다.</div>
          ) : (
            <div className="divide-y rounded-md border">
              {filteredProjects.map((project) => (
                <div key={project.project} className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
                  <div className="min-w-0 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="truncate font-semibold">{project.project}</h2>
                      {project.project === stats?.defaultProject && <Badge>기본</Badge>}
                      <Badge variant="secondary">{project.fileCount} files</Badge>
                      <Badge variant="outline">{formatBytes(project.totalSize)}</Badge>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {topExtensions(project.extensions).map(([ext, count]) => (
                        <Badge key={ext} variant="outline" className="text-[10px]">
                          {ext} {count}
                        </Badge>
                      ))}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      폴더 {project.directoryCount}개 · 지원 형식 {project.supportedCount}개
                      {project.updatedAt ? ` · 최근 변경 ${new Date(project.updatedAt).toLocaleString()}` : ""}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant="outline" asChild>
                      <Link href={`/archive/files?project=${encodeURIComponent(project.project)}`}>열기</Link>
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => reindexProject(project.project)}
                      disabled={reindexing === project.project}
                    >
                      {reindexing === project.project && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      재색인
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
