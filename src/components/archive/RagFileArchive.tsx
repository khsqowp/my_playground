"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  ArrowUp,
  Database,
  Download,
  File,
  FileArchive,
  FileText,
  Folder,
  Image as ImageIcon,
  Loader2,
  RefreshCcw,
  Search,
  Trash2,
  Upload,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface RagItem {
  name: string;
  path: string;
  isDirectory: boolean;
  size: number;
  updatedAt: string;
  extension: string;
  supported: boolean;
}

interface PreviewState {
  type: "text" | "image" | "pdf" | "binary" | "error" | "loading";
  content?: string;
  mimeType?: string;
  size?: number;
}

const SUPPORTED_ACCEPT = [
  ".pdf",
  ".docx",
  ".pptx",
  ".xlsx",
  ".md",
  ".txt",
  ".hwp",
  ".hwpx",
  ".mp3",
  ".m4a",
  ".wav",
  ".flac",
  ".aac",
  ".ogg",
  ".opus",
  ".mp4",
  ".mov",
  ".mkv",
  ".avi",
  ".webm",
  ".m4v",
].join(",");

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function fileIcon(item?: RagItem) {
  if (!item) return <File className="h-4 w-4 text-muted-foreground" />;
  if (item.isDirectory) return <Folder className="h-4 w-4 text-yellow-500" />;
  const ext = item.extension.toLowerCase();
  if (["md", "txt", "hwp", "hwpx", "docx"].includes(ext)) return <FileText className="h-4 w-4 text-blue-500" />;
  if (["jpg", "jpeg", "png", "gif", "webp", "svg"].includes(ext)) return <ImageIcon className="h-4 w-4 text-emerald-500" />;
  if (["zip", "pptx", "xlsx"].includes(ext)) return <FileArchive className="h-4 w-4 text-orange-500" />;
  return <File className="h-4 w-4 text-muted-foreground" />;
}

function parentPath(currentPath: string) {
  if (!currentPath) return "";
  const parts = currentPath.split("/").filter(Boolean);
  parts.pop();
  return parts.join("/");
}

function joinPath(base: string, name: string) {
  return base ? `${base}/${name}` : name;
}

export function RagFileArchive({
  title = "파일 아카이브",
  managerHref = "/archive/files/manage",
  initialProject,
}: {
  title?: string;
  managerHref?: string;
  initialProject?: string;
}) {
  const [projects, setProjects] = useState<string[]>([]);
  const [project, setProject] = useState(initialProject || "inbox");
  const [root, setRoot] = useState("");
  const [currentPath, setCurrentPath] = useState("");
  const [items, setItems] = useState<RagItem[]>([]);
  const [selected, setSelected] = useState<RagItem | null>(null);
  const [preview, setPreview] = useState<PreviewState | null>(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [reindexing, setReindexing] = useState(false);
  const [query, setQuery] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const filteredItems = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((item) => item.name.toLowerCase().includes(q));
  }, [items, query]);

  const downloadUrl = selected
    ? `/api/rag/files?action=download&project=${encodeURIComponent(project)}&path=${encodeURIComponent(selected.path)}`
    : "#";

  const loadProjects = useCallback(async () => {
    const res = await fetch("/api/rag/files?action=projects");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "프로젝트 목록 조회 실패");
    setProjects(data.projects || []);
    setRoot(data.root || "");
    const preferredProject = initialProject || data.defaultProject;
    const nextProject = (data.projects || []).includes(preferredProject)
      ? preferredProject
      : data.projects?.[0] || preferredProject || "inbox";
    setProject((prev) => (data.projects || []).includes(prev) ? prev : nextProject);
  }, [initialProject]);

  const loadItems = useCallback(async (nextProject = project, nextPath = currentPath) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        action: "list",
        project: nextProject,
        path: nextPath,
      });
      const res = await fetch(`/api/rag/files?${params}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "파일 목록 조회 실패");
      setItems(data.items || []);
    } catch (error: any) {
      toast.error(error.message || "파일 목록을 불러오지 못했습니다.");
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [currentPath, project]);

  const loadPreview = useCallback(async (item: RagItem) => {
    if (item.isDirectory) return;
    setPreview({ type: "loading" });
    try {
      const params = new URLSearchParams({
        action: "content",
        project,
        path: item.path,
      });
      const res = await fetch(`/api/rag/files?${params}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "미리보기 실패");
      setPreview(data);
    } catch {
      setPreview({ type: "error" });
    }
  }, [project]);

  useEffect(() => {
    loadProjects().catch((error) => toast.error(error.message || "RAG 프로젝트를 불러오지 못했습니다."));
  }, [loadProjects]);

  useEffect(() => {
    if (project) {
      setSelected(null);
      setPreview(null);
      loadItems(project, currentPath);
    }
  }, [project, currentPath, loadItems]);

  const openItem = (item: RagItem) => {
    if (item.isDirectory) {
      setCurrentPath(item.path);
      setSelected(null);
      setPreview(null);
      return;
    }
    setSelected(item);
    loadPreview(item);
  };

  const handleProjectChange = (nextProject: string) => {
    setProject(nextProject);
    setCurrentPath("");
    setSelected(null);
    setPreview(null);
  };

  const handleUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    if (files.length === 0) return;

    setUploading(true);
    try {
      const form = new FormData();
      form.append("project", project);
      form.append("path", currentPath);
      files.forEach((file) => form.append("files", file));

      const res = await fetch("/api/rag/files", { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "업로드 실패");

      toast.success(`${data.uploaded?.length || files.length}개 파일을 업로드했습니다.`);
      loadItems(project, currentPath);
    } catch (error: any) {
      toast.error(error.message || "업로드 중 오류가 발생했습니다.");
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleDelete = async () => {
    if (!selected || selected.isDirectory) return;
    if (!confirm(`"${selected.name}" 파일을 삭제하시겠습니까?`)) return;

    setDeleting(true);
    try {
      const res = await fetch("/api/rag/files", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ project, path: selected.path }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "삭제 실패");

      toast.success("파일이 삭제되었습니다.");
      setSelected(null);
      setPreview(null);
      loadItems(project, currentPath);
    } catch (error: any) {
      toast.error(error.message || "삭제 중 오류가 발생했습니다.");
    } finally {
      setDeleting(false);
    }
  };

  const handleReindex = async () => {
    setReindexing(true);
    try {
      const res = await fetch("/api/rag/files?action=reindex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ project, recreate: true }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || data.error || "재색인 요청 실패");
      toast.success(`재색인을 시작했습니다. job: ${data.job_id || "queued"}`);
    } catch (error: any) {
      toast.error(error.message || "재색인을 시작하지 못했습니다.");
    } finally {
      setReindexing(false);
    }
  };

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <Database className="h-6 w-6 text-primary" />
            {title}
          </h1>
          <p className="mt-1 text-xs text-muted-foreground">
            RAG 자료 루트: {root || "설정되지 않음"}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={project}
            onChange={(event) => handleProjectChange(event.target.value)}
            className="h-9 rounded-md border bg-background px-3 text-sm"
          >
            {projects.length === 0 ? (
              <option value={project}>{project}</option>
            ) : (
              projects.map((name) => <option key={name} value={name}>{name}</option>)
            )}
          </select>
          <Button variant="outline" size="sm" onClick={() => loadItems(project, currentPath)}>
            <RefreshCcw className="mr-2 h-4 w-4" />
            새로고침
          </Button>
          <Button variant="outline" size="sm" asChild>
            <Link href={managerHref}>
              <Database className="mr-2 h-4 w-4" />
              전체 관리
            </Link>
          </Button>
          <Button variant="outline" size="sm" onClick={handleReindex} disabled={reindexing}>
            {reindexing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Database className="mr-2 h-4 w-4" />}
            RAG 재색인
          </Button>
          <Button size="sm" onClick={() => fileInputRef.current?.click()} disabled={uploading}>
            {uploading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Upload className="mr-2 h-4 w-4" />}
            파일 업로드
          </Button>
          <input ref={fileInputRef} type="file" accept={SUPPORTED_ACCEPT} multiple className="hidden" onChange={handleUpload} />
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-[380px_minmax(0,1fr)]">
        <Card className="min-h-0 overflow-hidden">
          <CardContent className="flex h-full flex-col p-0">
            <div className="border-b p-3">
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="icon"
                  disabled={!currentPath}
                  onClick={() => {
                    setCurrentPath(parentPath(currentPath));
                    setSelected(null);
                    setPreview(null);
                  }}
                >
                  <ArrowUp className="h-4 w-4" />
                </Button>
                <div className="min-w-0 flex-1 rounded-md bg-muted px-2 py-1 font-mono text-xs">
                  <span className="truncate block">/{project}{currentPath ? `/${currentPath}` : ""}</span>
                </div>
              </div>
              <div className="mt-3 flex items-center gap-2 rounded-md border px-2">
                <Search className="h-4 w-4 text-muted-foreground" />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="현재 폴더에서 파일명 검색"
                  className="h-9 min-w-0 flex-1 bg-transparent text-sm outline-none"
                />
              </div>
            </div>

            <ScrollArea className="flex-1">
              <div className="space-y-1 p-2">
                {loading && (
                  <div className="flex items-center justify-center py-10 text-sm text-muted-foreground">
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    로딩 중
                  </div>
                )}
                {!loading && filteredItems.length === 0 && (
                  <div className="py-10 text-center text-sm text-muted-foreground">파일이 없습니다.</div>
                )}
                {!loading && filteredItems.map((item) => (
                  <button
                    key={item.path}
                    onClick={() => openItem(item)}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md px-2 py-2 text-left text-sm hover:bg-muted",
                      selected?.path === item.path && "bg-muted"
                    )}
                  >
                    <span className="shrink-0">{fileIcon(item)}</span>
                    <span className="min-w-0 flex-1 truncate">{item.name}</span>
                    {!item.isDirectory && (
                      <Badge variant={item.supported ? "secondary" : "outline"} className="shrink-0 text-[10px]">
                        {item.extension || "file"}
                      </Badge>
                    )}
                  </button>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        <Card className="min-h-0 overflow-hidden">
          <CardContent className="flex h-full flex-col p-0">
            {selected ? (
              <>
                <div className="flex flex-wrap items-center justify-between gap-3 border-b p-4">
                  <div className="flex min-w-0 items-center gap-3">
                    {fileIcon(selected)}
                    <div className="min-w-0">
                      <h2 className="truncate text-sm font-semibold">{selected.name}</h2>
                      <p className="text-xs text-muted-foreground">
                        {formatBytes(selected.size)} · {new Date(selected.updatedAt).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" asChild>
                      <a href={downloadUrl}>
                        <Download className="mr-2 h-4 w-4" />
                        다운로드
                      </a>
                    </Button>
                    <Button variant="destructive" size="sm" onClick={handleDelete} disabled={deleting}>
                      {deleting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
                      삭제
                    </Button>
                  </div>
                </div>

                <div className="min-h-0 flex-1 overflow-auto bg-muted/20 p-4">
                  {preview?.type === "loading" && (
                    <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                      <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                      미리보기 로딩 중
                    </div>
                  )}
                  {preview?.type === "text" && (
                    <pre className="min-h-full whitespace-pre-wrap rounded-md border bg-background p-4 text-xs leading-relaxed">
                      {preview.content}
                    </pre>
                  )}
                  {preview?.type === "image" && preview.content && (
                    <div className="flex h-full items-center justify-center">
                      <img src={preview.content} alt={selected.name} className="max-h-full max-w-full rounded-md border bg-background object-contain" />
                    </div>
                  )}
                  {preview?.type === "pdf" && (
                    <iframe title={selected.name} src={downloadUrl} className="h-full min-h-[640px] w-full rounded-md border bg-background" />
                  )}
                  {(preview?.type === "binary" || !preview) && (
                    <div className="flex h-full flex-col items-center justify-center gap-3 text-muted-foreground">
                      <File className="h-12 w-12 opacity-50" />
                      <p className="text-sm">미리보기를 지원하지 않는 파일입니다.</p>
                    </div>
                  )}
                  {preview?.type === "error" && (
                    <div className="flex h-full flex-col items-center justify-center gap-3 text-destructive">
                      <File className="h-12 w-12 opacity-50" />
                      <p className="text-sm">파일을 읽을 수 없습니다.</p>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="flex h-full flex-col items-center justify-center gap-4 text-muted-foreground">
                <Folder className="h-14 w-14 opacity-30" />
                <div className="text-center">
                  <p className="font-medium">파일을 선택하세요</p>
                  <p className="text-sm">RAG 자료 루트의 문서를 조회, 업로드, 삭제할 수 있습니다.</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
