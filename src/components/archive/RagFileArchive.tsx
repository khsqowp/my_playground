"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  ArrowUp,
  Bot,
  Database,
  Download,
  File,
  FileArchive,
  FileText,
  Folder,
  Image as ImageIcon,
  Loader2,
  MessageSquare,
  RefreshCcw,
  Search,
  Send,
  Trash2,
  Upload,
  User,
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

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

interface CacheStatus {
  enabled: boolean;
  count: number;
  expired_count: number;
  legacy_count: number;
  total_bytes: number;
  ttl_seconds: number;
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
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [reindexing, setReindexing] = useState(false);
  const [cacheStatus, setCacheStatus] = useState<CacheStatus | null>(null);
  const [cacheLoading, setCacheLoading] = useState(false);
  const [cacheClearing, setCacheClearing] = useState(false);
  const [query, setQuery] = useState("");
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const chatScrollRef = useRef<HTMLDivElement>(null);

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

  const loadCacheStatus = useCallback(async (nextProject = project) => {
    setCacheLoading(true);
    try {
      const params = new URLSearchParams({
        action: "cache-status",
        project: nextProject,
      });
      const res = await fetch(`/api/rag/files?${params}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || data.error || "캐시 상태 조회 실패");
      setCacheStatus(data);
    } catch (error: any) {
      setCacheStatus(null);
      toast.error(error.message || "캐시 상태를 불러오지 못했습니다.");
    } finally {
      setCacheLoading(false);
    }
  }, [project]);

  useEffect(() => {
    loadProjects().catch((error) => toast.error(error.message || "RAG 프로젝트를 불러오지 못했습니다."));
  }, [loadProjects]);

  useEffect(() => {
    if (project) {
      setSelected(null);
      loadItems(project, currentPath);
      loadCacheStatus(project);
    }
  }, [project, currentPath, loadItems, loadCacheStatus]);

  useEffect(() => {
    setChatMessages([
      {
        role: "assistant",
        content: `"${project}" 프로젝트에 색인된 문서를 기준으로 답변합니다.`,
      },
    ]);
    setChatInput("");
  }, [project]);

  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [chatMessages, chatLoading]);

  const openItem = (item: RagItem) => {
    if (item.isDirectory) {
      setCurrentPath(item.path);
      setSelected(null);
      return;
    }
    setSelected(item);
  };

  const handleProjectChange = (nextProject: string) => {
    setProject(nextProject);
    setCurrentPath("");
    setSelected(null);
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
      loadCacheStatus(project);
    } catch (error: any) {
      toast.error(error.message || "재색인을 시작하지 못했습니다.");
    } finally {
      setReindexing(false);
    }
  };

  const handleClearCache = async () => {
    if (!confirm(`"${project}" 프로젝트의 RAG 답변 캐시를 삭제하시겠습니까?`)) return;
    setCacheClearing(true);
    try {
      const res = await fetch("/api/rag/files?action=cache-clear", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ project, includeLegacy: true }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || data.error || "캐시 삭제 실패");
      setCacheStatus(data.status || null);
      toast.success(`${data.removed || 0}개 캐시 항목을 삭제했습니다.`);
    } catch (error: any) {
      toast.error(error.message || "캐시 삭제 중 오류가 발생했습니다.");
    } finally {
      setCacheClearing(false);
    }
  };

  const handleChatSubmit = async () => {
    const message = chatInput.trim();
    if (!message || chatLoading) return;

    setChatMessages((prev) => [...prev, { role: "user", content: message }]);
    setChatInput("");
    setChatLoading(true);

    try {
      const res = await fetch("/api/persona/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message,
          project,
          history: chatMessages.slice(-8),
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || data.detail || "질문 처리 실패");
      setChatMessages((prev) => [
        ...prev,
        { role: "assistant", content: data.response || "답변을 생성하지 못했습니다." },
      ]);
    } catch (error: any) {
      setChatMessages((prev) => [
        ...prev,
        { role: "assistant", content: error.message || "질문 처리 중 오류가 발생했습니다." },
      ]);
    } finally {
      setChatLoading(false);
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
          {cacheStatus && (
            <p className="mt-1 text-xs text-muted-foreground">
              답변 캐시: {cacheStatus.enabled ? `${cacheStatus.count}개 / ${formatBytes(cacheStatus.total_bytes)}` : "비활성화"}
              {cacheStatus.expired_count > 0 ? `, 만료 ${cacheStatus.expired_count}개` : ""}
              {cacheStatus.legacy_count > 0 ? `, 이전 형식 ${cacheStatus.legacy_count}개` : ""}
            </p>
          )}
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
          <Button variant="outline" size="sm" onClick={() => loadCacheStatus(project)} disabled={cacheLoading}>
            {cacheLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCcw className="mr-2 h-4 w-4" />}
            캐시 상태
          </Button>
          <Button variant="outline" size="sm" onClick={handleClearCache} disabled={cacheClearing || cacheLoading}>
            {cacheClearing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
            캐시 삭제
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
            <div className="flex flex-wrap items-center justify-between gap-3 border-b p-4">
              <div className="flex min-w-0 items-center gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary/10">
                  <MessageSquare className="h-5 w-5 text-primary" />
                </div>
                <div className="min-w-0">
                  <h2 className="truncate text-sm font-semibold">{project} 프로젝트 채팅</h2>
                  <p className="text-xs text-muted-foreground">
                    현재 폴더: /{project}{currentPath ? `/${currentPath}` : ""}
                  </p>
                </div>
              </div>
              {selected && (
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <div className="flex min-w-0 items-center gap-2 rounded-md bg-muted px-2 py-1 text-xs">
                    {fileIcon(selected)}
                    <span className="max-w-[220px] truncate">{selected.name}</span>
                    <span className="text-muted-foreground">{formatBytes(selected.size)}</span>
                  </div>
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
              )}
            </div>

            <div ref={chatScrollRef} className="min-h-0 flex-1 overflow-auto bg-muted/20 p-4">
              <div className="space-y-4">
                {chatMessages.map((message, index) => (
                  <div
                    key={`${message.role}-${index}`}
                    className={cn("flex gap-3", message.role === "user" ? "justify-end" : "justify-start")}
                  >
                    {message.role === "assistant" && (
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/10">
                        <Bot className="h-4 w-4 text-primary" />
                      </div>
                    )}
                    <div
                      className={cn(
                        "max-w-[82%] whitespace-pre-wrap rounded-md px-3 py-2 text-sm leading-relaxed",
                        message.role === "user" ? "bg-primary text-primary-foreground" : "border bg-background"
                      )}
                    >
                      {message.content}
                    </div>
                    {message.role === "user" && (
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
                        <User className="h-4 w-4" />
                      </div>
                    )}
                  </div>
                ))}
                {chatLoading && (
                  <div className="flex gap-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/10">
                      <Bot className="h-4 w-4 text-primary" />
                    </div>
                    <div className="flex items-center rounded-md border bg-background px-3 py-2 text-sm text-muted-foreground">
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      답변 생성 중
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="border-t p-4">
              <div className="flex gap-2">
                <textarea
                  value={chatInput}
                  onChange={(event) => setChatInput(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      handleChatSubmit();
                    }
                  }}
                  placeholder={`${project} 프로젝트 문서에 대해 질문`}
                  className="min-h-10 max-h-32 min-w-0 flex-1 resize-none rounded-md border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                  rows={1}
                />
                <Button onClick={handleChatSubmit} disabled={chatLoading || !chatInput.trim()} className="h-10">
                  {chatLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                </Button>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                답변은 현재 선택한 프로젝트의 RAG 색인 기준입니다. 새 파일은 재색인 후 반영됩니다.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
