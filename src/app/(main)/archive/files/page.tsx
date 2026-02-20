"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  FileArchive,
  FileText,
  File,
  Upload,
  Trash2,
  Loader2,
  Search,
  CheckCircle2,
  XCircle,
  MinusCircle,
  Clock,
  FolderOpen,
  Folder,
  ChevronRight,
  ChevronDown,
  CheckSquare,
  Square,
  FolderInput,
  Sparkles,
  RotateCcw,
  Wand2,
} from "lucide-react";
import { toast } from "sonner";
import { format } from "date-fns";
import { ko } from "date-fns/locale";
import { cn } from "@/lib/utils";

const BATCH_SIZE = 3;
const ALLOWED_EXTENSIONS = ["zip", "pdf", "txt", "md", "docx", "xlsx", "pptx"];

function FileIcon({ ext, size = 5 }: { ext: string; size?: number }) {
  const cls = `h-${size} w-${size}`;
  if (ext === "zip") return <FileArchive className={cn(cls, "text-yellow-500")} />;
  if (["txt", "md"].includes(ext)) return <FileText className={cn(cls, "text-blue-500")} />;
  if (ext === "pdf") return <File className={cn(cls, "text-red-500")} />;
  if (ext === "docx") return <File className={cn(cls, "text-blue-700")} />;
  if (ext === "xlsx") return <File className={cn(cls, "text-green-600")} />;
  if (ext === "pptx") return <File className={cn(cls, "text-orange-500")} />;
  return <File className={cn(cls, "text-muted-foreground")} />;
}

function AiStatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; variant: any }> = {
    DONE: { label: "AI 분석 완료", variant: "default" },
    PENDING: { label: "대기 중", variant: "secondary" },
    PROCESSING: { label: "분석 중", variant: "secondary" },
    FAILED: { label: "분석 실패", variant: "destructive" },
    SKIPPED: { label: "텍스트 추출 미지원", variant: "outline" },
  };
  const info = map[status] || { label: status, variant: "outline" };
  return <Badge variant={info.variant}>{info.label}</Badge>;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

interface QueueItem {
  file: File;
  status: "waiting" | "uploading" | "done" | "skipped" | "error";
  error?: string;
}

interface FolderNode {
  name: string;
  fullPath: string;
  children: FolderNode[];
}

function buildFolderTree(folders: string[]): FolderNode[] {
  const root: FolderNode[] = [];
  const map: Record<string, FolderNode> = {};

  for (const folder of folders) {
    const parts = folder.split("/");
    let currentPath = "";
    let currentLevel = root;

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      currentPath = currentPath ? `${currentPath}/${part}` : part;

      if (!map[currentPath]) {
        const node: FolderNode = { name: part, fullPath: currentPath, children: [] };
        map[currentPath] = node;
        currentLevel.push(node);
      }
      currentLevel = map[currentPath].children;
    }
  }

  return root;
}

function FolderTree({
  nodes,
  selectedFolder,
  onSelect,
  level = 0,
}: {
  nodes: FolderNode[];
  selectedFolder: string;
  onSelect: (folder: string) => void;
  level?: number;
}) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const toggle = (p: string) => setExpanded((prev) => ({ ...prev, [p]: !prev[p] }));

  return (
    <div>
      {nodes.map((node) => {
        const hasChildren = node.children.length > 0;
        const isExpanded = expanded[node.fullPath];
        const isSelected = selectedFolder === node.fullPath;

        return (
          <div key={node.fullPath}>
            <button
              onClick={() => {
                onSelect(node.fullPath);
                if (hasChildren) toggle(node.fullPath);
              }}
              className={cn(
                "w-full flex items-center gap-1.5 px-2 py-1 text-sm rounded-md text-left hover:bg-muted/60 transition-colors",
                isSelected ? "bg-muted font-medium text-foreground" : "text-muted-foreground"
              )}
              style={{ paddingLeft: `${8 + level * 14}px` }}
            >
              {hasChildren ? (
                isExpanded ? (
                  <ChevronDown className="h-3 w-3 shrink-0" />
                ) : (
                  <ChevronRight className="h-3 w-3 shrink-0" />
                )
              ) : (
                <span className="w-3 shrink-0" />
              )}
              {isSelected ? (
                <FolderOpen className="h-3.5 w-3.5 shrink-0 text-primary" />
              ) : (
                <Folder className="h-3.5 w-3.5 shrink-0" />
              )}
              <span className="truncate">{node.name}</span>
            </button>
            {hasChildren && isExpanded && (
              <FolderTree
                nodes={node.children}
                selectedFolder={selectedFolder}
                onSelect={onSelect}
                level={level + 1}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function ArchiveFilesPage() {
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [movingId, setMovingId] = useState<string | null>(null);
  const [folders, setFolders] = useState<string[]>([]);
  const [selectedFolder, setSelectedFolder] = useState<string>("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Upload state
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState({ done: 0, total: 0 });

  // Multi-select state
  const [selectMode, setSelectMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Bulk action state
  const [showBulkMoveDialog, setShowBulkMoveDialog] = useState(false);
  const [bulkMoveInput, setBulkMoveInput] = useState("");
  const [isBulkMoving, setIsBulkMoving] = useState(false);
  const [isBulkReclassifying, setIsBulkReclassifying] = useState(false);
  const [isReclassifyingAll, setIsReclassifyingAll] = useState(false);
  const [isReclassifyingFailed, setIsReclassifyingFailed] = useState(false);
  const [isReorganizing, setIsReorganizing] = useState(false);

  const fetchFolders = useCallback(() => {
    fetch("/api/archive/files?folderList=1")
      .then((r) => r.json())
      .then((data) => {
        if (data.folders) setFolders(data.folders);
      });
  }, []);

  const fetchFiles = useCallback((q = "", folder = "") => {
    setLoading(true);
    const params = new URLSearchParams();
    if (q) params.set("search", q);
    if (folder) params.set("folder", folder);
    fetch(`/api/archive/files?${params}`)
      .then((r) => r.json())
      .then((data) => {
        if (data.files) setFiles(data.files);
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchFolders();
    fetchFiles();
  }, [fetchFolders, fetchFiles]);

  // 분석 실패 파일 자동 재시도: 마운트 시 1회 + 10분마다
  useEffect(() => {
    const reclassifyFailed = () => {
      fetch("/api/archive/files/reclassify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ failedOnly: true }),
      }).catch(() => {});
    };
    reclassifyFailed();
    const interval = setInterval(reclassifyFailed, 10 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  const handleFolderSelect = (folder: string) => {
    const next = selectedFolder === folder ? "" : folder;
    setSelectedFolder(next);
    fetchFiles(search, next);
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchFiles(search, selectedFolder);
  };

  // ── 파일 선택 ──────────────────────────────────────────
  const toggleFileSelect = (id: string) => {
    setSelectMode(true);
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleSelectAll = () => {
    setSelectedIds(new Set(files.map((f) => f.id)));
  };

  const handleClearSelect = () => {
    setSelectedIds(new Set());
    setSelectMode(false);
  };

  // ── 업로드 ─────────────────────────────────────────────
  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(e.target.files || []);
    if (selected.length === 0) return;

    const invalid = selected.filter((f) => {
      const ext = f.name.split(".").pop()?.toLowerCase() || "";
      return !ALLOWED_EXTENSIONS.includes(ext);
    });
    if (invalid.length > 0) {
      toast.error(`지원하지 않는 파일 형식: ${invalid.map((f) => f.name).join(", ")}`);
    }

    const valid = selected.filter((f) => {
      const ext = f.name.split(".").pop()?.toLowerCase() || "";
      return ALLOWED_EXTENSIONS.includes(ext);
    });
    if (valid.length === 0) return;

    const newQueue: QueueItem[] = valid.map((f) => ({ file: f, status: "waiting" }));
    setQueue(newQueue);
    setUploadProgress({ done: 0, total: valid.length });
    startBatchUpload(newQueue);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const uploadSingleFile = async (item: QueueItem, index: number): Promise<boolean> => {
    setQueue((prev) => prev.map((q, i) => (i === index ? { ...q, status: "uploading" } : q)));
    const formData = new FormData();
    formData.append("file", item.file);
    try {
      const res = await fetch("/api/archive/files/upload", { method: "POST", body: formData });
      // 중복 파일 → 스킵 처리 (에러 아님)
      if (res.status === 409) {
        setQueue((prev) =>
          prev.map((q, i) => (i === index ? { ...q, status: "skipped", error: "중복 파일 건너뜀" } : q))
        );
        return true;
      }
      if (!res.ok) {
        const text = await res.text();
        let errMsg = `업로드 실패 (${res.status})`;
        try { errMsg = JSON.parse(text)?.error || errMsg; } catch {}
        throw new Error(errMsg);
      }
      setQueue((prev) => prev.map((q, i) => (i === index ? { ...q, status: "done" } : q)));
      return true;
    } catch (err: any) {
      setQueue((prev) =>
        prev.map((q, i) => (i === index ? { ...q, status: "error", error: err.message } : q))
      );
      return false;
    }
  };

  const startBatchUpload = async (items: QueueItem[]) => {
    setIsUploading(true);
    let doneCount = 0;
    for (let batchStart = 0; batchStart < items.length; batchStart += BATCH_SIZE) {
      const batch = items.slice(batchStart, batchStart + BATCH_SIZE);
      const batchIndices = batch.map((_, i) => batchStart + i);
      const results = await Promise.all(
        batch.map((item, i) => uploadSingleFile(item, batchIndices[i]))
      );
      doneCount += results.filter(Boolean).length;
      setUploadProgress({ done: doneCount, total: items.length });
    }
    if (items.length - doneCount > 0) {
      toast.error(`${doneCount}개 완료, ${items.length - doneCount}개 실패`);
    } else {
      toast.success(`${doneCount}개 파일 업로드 완료!`);
    }
    setIsUploading(false);
    fetchFolders();
    fetchFiles(search, selectedFolder);
    setTimeout(() => setQueue([]), 3000);
  };

  // ── 단일 삭제 ──────────────────────────────────────────
  const handleDelete = async (id: string, fileName: string) => {
    if (!confirm(`"${fileName}" 파일을 삭제하시겠습니까?`)) return;
    setDeletingId(id);
    try {
      const res = await fetch("/api/archive/files", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      if (!res.ok) throw new Error("삭제 실패");
      toast.success("파일이 삭제되었습니다.");
      setFiles((prev) => prev.filter((f) => f.id !== id));
      setSelectedIds((prev) => { const next = new Set(prev); next.delete(id); return next; });
      fetchFolders();
    } catch {
      toast.error("삭제 중 오류가 발생했습니다.");
    } finally {
      setDeletingId(null);
    }
  };

  // ── 단일 폴더 이동 ─────────────────────────────────────
  const handleMoveFolder = async (fileId: string, currentFolder: string) => {
    const newFolder = window.prompt(
      "이동할 폴더 경로를 입력하세요 (예: 개발/TypeScript):",
      currentFolder
    );
    if (!newFolder || newFolder.trim() === currentFolder) return;
    setMovingId(fileId);
    try {
      const res = await fetch("/api/archive/files", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: fileId, folder: newFolder.trim() }),
      });
      if (!res.ok) throw new Error("이동 실패");
      toast.success(`"${newFolder.trim()}" 폴더로 이동했습니다.`);
      fetchFolders();
      fetchFiles(search, selectedFolder);
    } catch {
      toast.error("폴더 이동 중 오류가 발생했습니다.");
    } finally {
      setMovingId(null);
    }
  };

  // ── 일괄 폴더 이동 ─────────────────────────────────────
  const handleBulkMove = async () => {
    if (!bulkMoveInput.trim()) return;
    setIsBulkMoving(true);
    try {
      const res = await fetch("/api/archive/files", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: Array.from(selectedIds), folder: bulkMoveInput.trim() }),
      });
      if (!res.ok) throw new Error("이동 실패");
      const data = await res.json();
      toast.success(`${data.updated}개 파일을 "${bulkMoveInput.trim()}"으로 이동했습니다.`);
      setShowBulkMoveDialog(false);
      setBulkMoveInput("");
      handleClearSelect();
      fetchFolders();
      fetchFiles(search, selectedFolder);
    } catch {
      toast.error("폴더 이동 중 오류가 발생했습니다.");
    } finally {
      setIsBulkMoving(false);
    }
  };

  // ── 선택 파일 재분류 ───────────────────────────────────
  const handleBulkReclassify = async () => {
    if (selectedIds.size === 0) return;
    setIsBulkReclassifying(true);
    try {
      const res = await fetch("/api/archive/files/reclassify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: Array.from(selectedIds) }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "실패");
      toast.success(
        `${data.queued}개 파일 재분류를 시작했습니다. 완료 후 새로고침하세요.`,
        { duration: 5000 }
      );
      handleClearSelect();
    } catch {
      toast.error("재분류 중 오류가 발생했습니다.");
    } finally {
      setIsBulkReclassifying(false);
    }
  };

  // ── 분석 실패 재시도 ───────────────────────────────────
  const handleReclassifyFailed = async () => {
    setIsReclassifyingFailed(true);
    try {
      const res = await fetch("/api/archive/files/reclassify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ failedOnly: true }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "실패");
      if (data.queued === 0) {
        toast.info("분석 실패 파일이 없습니다.");
      } else {
        toast.success(`${data.queued}개 분석 실패 파일 재분류를 시작했습니다.`, { duration: 5000 });
      }
    } catch {
      toast.error("재분류 중 오류가 발생했습니다.");
    } finally {
      setIsReclassifyingFailed(false);
    }
  };

  // ── 전체 폴더 재구성 (글로벌 클러스터링) ──────────────
  const handleReorganizeAll = async () => {
    const totalCount = files.length;
    if (
      !confirm(
        `전체 파일(${totalCount}개)의 폴더 구조를 AI로 최적화합니다.\n` +
          "비슷한 폴더들이 통합되고 일관성 없는 이름이 정리됩니다.\n" +
          "기존 폴더 분류가 변경될 수 있습니다. 계속하시겠습니까?"
      )
    )
      return;

    setIsReorganizing(true);
    try {
      const res = await fetch("/api/archive/files/reorganize", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "실패");
      toast.success(
        `${data.total}개 파일 폴더 재구성을 시작했습니다. 약 1~2분 후 새로고침하세요.`,
        { duration: 8000 }
      );
      // 백그라운드 처리 완료 예상 시간 후 자동 새로고침
      setTimeout(() => {
        fetchFolders();
        fetchFiles(search, "");
        setSelectedFolder("");
      }, 90000); // 90초 후 자동 새로고침
    } catch (e: any) {
      toast.error(e.message || "재구성 중 오류가 발생했습니다.");
    } finally {
      setIsReorganizing(false);
    }
  };

  // ── 미분류 전체 자동 정리 ──────────────────────────────
  const handleReclassifyAll = async () => {
    const unclassifiedCount = files.filter((f) => f.folder === "미분류").length;
    if (unclassifiedCount === 0 && selectedFolder !== "미분류") {
      // 전체 미분류 개수 확인 필요
    }
    if (
      !confirm(
        `"미분류" 폴더의 파일들을 AI로 자동 분류합니다. 백그라운드에서 처리되므로 시간이 걸릴 수 있습니다. 계속하시겠습니까?`
      )
    )
      return;

    setIsReclassifyingAll(true);
    try {
      const res = await fetch("/api/archive/files/reclassify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ unclassifiedOnly: true }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "실패");
      if (data.queued === 0) {
        toast.info("미분류 파일이 없습니다.");
      } else {
        toast.success(
          `${data.queued}개 미분류 파일 자동 정리를 시작했습니다. 완료 후 새로고침하세요.`,
          { duration: 6000 }
        );
      }
    } catch {
      toast.error("자동 정리 중 오류가 발생했습니다.");
    } finally {
      setIsReclassifyingAll(false);
    }
  };

  const folderTree = buildFolderTree(folders);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <FileArchive className="h-6 w-6 text-primary" />
          파일 아카이브
        </h1>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleReorganizeAll}
            disabled={isReorganizing}
            title="전체 파일을 AI로 일괄 분석하여 폴더 구조를 최적화합니다 (비슷한 폴더 통합, 일관성 개선)"
          >
            {isReorganizing ? (
              <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Wand2 className="mr-2 h-3.5 w-3.5" />
            )}
            전체 재구성
          </Button>
                    <Button
            variant="outline"
            size="sm"
            onClick={handleReclassifyFailed}
            disabled={isReclassifyingFailed}
            title="분석 실패 파일을 다시 시도합니다 (10분마다 자동 재시도)"
          >
            {isReclassifyingFailed ? (
              <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
            ) : (
              <RotateCcw className="mr-2 h-3.5 w-3.5" />
            )}
            실패 재시도
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleReclassifyAll}
            disabled={isReclassifyingAll}
            title="미분류 파일을 AI로 자동 정리"
          >
            {isReclassifyingAll ? (
              <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Sparkles className="mr-2 h-3.5 w-3.5" />
            )}
            미분류 자동 정리
          </Button>
          <Button onClick={() => fileInputRef.current?.click()} disabled={isUploading}>
            {isUploading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                {uploadProgress.done}/{uploadProgress.total} 처리 중...
              </>
            ) : (
              <>
                <Upload className="mr-2 h-4 w-4" />
                파일 업로드
              </>
            )}
          </Button>
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept=".zip,.pdf,.txt,.md,.docx,.xlsx,.pptx"
          multiple
          onChange={handleFileSelect}
          className="hidden"
        />
      </div>

      {/* Upload Queue */}
      {queue.length > 0 && (
        <Card className="p-4">
          <p className="text-sm font-medium mb-3">
            업로드 진행 중 ({uploadProgress.done}/{uploadProgress.total})
          </p>
          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {queue.map((item, i) => (
              <div key={i} className="flex items-center gap-2 text-sm">
                {item.status === "waiting" && (
                  <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                )}
                {item.status === "uploading" && (
                  <Loader2 className="h-3.5 w-3.5 text-primary animate-spin shrink-0" />
                )}
                {item.status === "done" && (
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />
                )}
                {item.status === "skipped" && (
                  <MinusCircle className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                )}
                {item.status === "error" && (
                  <XCircle className="h-3.5 w-3.5 text-destructive shrink-0" />
                )}
                <span
                  className={cn(
                    "truncate",
                    item.status === "done" && "text-muted-foreground",
                    item.status === "skipped" && "text-muted-foreground line-through",
                    item.status === "error" && "text-destructive"
                  )}
                >
                  {item.file.name}
                </span>
                {item.error && (
                  <span className="text-xs text-destructive ml-auto shrink-0 max-w-40 truncate">
                    {item.error}
                  </span>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Main layout */}
      <div className="flex gap-4">
        {/* Folder sidebar */}
        <aside className="w-52 shrink-0">
          <Card className="p-2">
            <button
              onClick={() => {
                setSelectedFolder("");
                fetchFiles(search, "");
              }}
              className={cn(
                "w-full flex items-center gap-1.5 px-2 py-1.5 text-sm rounded-md text-left hover:bg-muted/60 transition-colors mb-1",
                selectedFolder === ""
                  ? "bg-muted font-medium text-foreground"
                  : "text-muted-foreground"
              )}
            >
              <FolderOpen className="h-3.5 w-3.5 shrink-0 text-primary" />
              <span className="flex-1">전체 파일</span>
              {!loading && (
                <span className="text-xs text-muted-foreground font-normal">{files.length}</span>
              )}
            </button>
            {folderTree.length > 0 && <div className="border-t border-border/50 pt-1" />}
            <FolderTree
              nodes={folderTree}
              selectedFolder={selectedFolder}
              onSelect={handleFolderSelect}
            />
          </Card>
        </aside>

        {/* File area */}
        <div className="flex-1 min-w-0 space-y-3">
          {/* Search + select toolbar */}
          <div className="flex gap-2 items-center">
            <form onSubmit={handleSearch} className="flex gap-2 flex-1">
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="파일명, AI 요약, 태그 검색..."
                className="flex-1 rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
              <Button type="submit" variant="outline" size="sm">
                <Search className="h-4 w-4" />
              </Button>
            </form>
            <Button
              variant={selectMode ? "default" : "outline"}
              size="sm"
              onClick={() => {
                if (selectMode) handleClearSelect();
                else setSelectMode(true);
              }}
            >
              <CheckSquare className="mr-1.5 h-3.5 w-3.5" />
              {selectMode ? "선택 해제" : "선택 모드"}
            </Button>
          </div>

          {!loading && (
            <p className="text-xs text-muted-foreground flex items-center gap-1">
              {selectedFolder ? (
                <>
                  <Folder className="h-3 w-3" />
                  {selectedFolder} · {files.length}개
                </>
              ) : (
                <>총 {files.length}개 파일</>
              )}
            </p>
          )}

          {/* Select all row */}
          {selectMode && files.length > 0 && (
            <div className="flex items-center gap-3 text-sm text-muted-foreground px-1">
              <button
                onClick={selectedIds.size === files.length ? handleClearSelect : handleSelectAll}
                className="flex items-center gap-1.5 hover:text-foreground transition-colors"
              >
                {selectedIds.size === files.length ? (
                  <CheckSquare className="h-4 w-4 text-primary" />
                ) : (
                  <Square className="h-4 w-4" />
                )}
                전체 선택
              </button>
              {selectedIds.size > 0 && (
                <span className="text-primary font-medium">{selectedIds.size}개 선택됨</span>
              )}
            </div>
          )}

          {loading ? (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-40 bg-muted animate-pulse rounded-lg" />
              ))}
            </div>
          ) : files.length === 0 ? (
            <Card className="p-12 text-center text-muted-foreground border-dashed">
              <FileArchive className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>
                {selectedFolder
                  ? `"${selectedFolder}" 폴더에 파일이 없습니다.`
                  : "업로드된 파일이 없습니다."}
              </p>
              {!selectedFolder && (
                <p className="text-sm mt-1">
                  zip, pdf, txt, md, docx, xlsx, pptx 파일을 업로드할 수 있습니다.
                </p>
              )}
            </Card>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {files.map((file) => {
                const isSelected = selectedIds.has(file.id);
                return (
                  <Card
                    key={file.id}
                    className={cn(
                      "overflow-hidden transition-all cursor-default",
                      selectMode && "hover:ring-1 hover:ring-primary/50",
                      isSelected
                        ? "ring-2 ring-primary bg-primary/5"
                        : "hover:ring-1 hover:ring-primary"
                    )}
                    onClick={() => selectMode && toggleFileSelect(file.id)}
                  >
                    <CardContent className="p-4 space-y-3">
                      <div className="flex items-start justify-between gap-2">
                        {/* Checkbox (select mode) */}
                        {selectMode && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleFileSelect(file.id);
                            }}
                            className="shrink-0 mt-0.5"
                          >
                            {isSelected ? (
                              <CheckSquare className="h-4 w-4 text-primary" />
                            ) : (
                              <Square className="h-4 w-4 text-muted-foreground" />
                            )}
                          </button>
                        )}
                        <div className="flex items-center gap-2 min-w-0 flex-1">
                          <FileIcon ext={file.extension} />
                          <span className="font-medium text-sm truncate">{file.fileName}</span>
                        </div>
                        {!selectMode && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 shrink-0 text-muted-foreground hover:text-destructive"
                            onClick={(e) => {
                              e.preventDefault();
                              handleDelete(file.id, file.fileName);
                            }}
                            disabled={deletingId === file.id}
                          >
                            {deletingId === file.id ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : (
                              <Trash2 className="h-3 w-3" />
                            )}
                          </Button>
                        )}
                      </div>

                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span>{formatBytes(file.fileSize)}</span>
                        <span>•</span>
                        <span>
                          {format(new Date(file.createdAt), "yyyy-MM-dd", { locale: ko })}
                        </span>
                      </div>

                      {/* Folder badge */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (!selectMode) handleMoveFolder(file.id, file.folder);
                        }}
                        disabled={movingId === file.id || selectMode}
                        className={cn(
                          "flex items-center gap-1 text-xs text-muted-foreground transition-colors",
                          !selectMode && "hover:text-foreground"
                        )}
                        title={selectMode ? file.folder : "클릭하여 폴더 이동"}
                      >
                        {movingId === file.id ? (
                          <Loader2 className="h-3 w-3 animate-spin shrink-0" />
                        ) : (
                          <Folder className="h-3 w-3 shrink-0" />
                        )}
                        <span className="truncate">{file.folder}</span>
                      </button>

                      <AiStatusBadge status={file.aiStatus} />

                      {file.aiSummary && (
                        <p className="text-xs text-muted-foreground line-clamp-2">
                          {file.aiSummary}
                        </p>
                      )}

                      {file.aiTags && (
                        <div className="flex flex-wrap gap-1">
                          {file.aiTags
                            .split(",")
                            .slice(0, 4)
                            .map((tag: string) => (
                              <Badge key={tag} variant="secondary" className="text-[10px]">
                                {tag.trim()}
                              </Badge>
                            ))}
                        </div>
                      )}

                      {!selectMode && (
                        <Link
                          href={`/archive/files/${file.id}`}
                          className="block text-xs text-primary hover:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          상세 보기 →
                        </Link>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Floating bulk action bar */}
      {selectMode && selectedIds.size > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50">
          <div className="flex items-center gap-2 bg-background border rounded-full shadow-lg px-4 py-2">
            <span className="text-sm font-medium text-primary">{selectedIds.size}개 선택</span>
            <div className="w-px h-4 bg-border" />
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setBulkMoveInput("");
                setShowBulkMoveDialog(true);
              }}
            >
              <FolderInput className="mr-1.5 h-3.5 w-3.5" />
              폴더 이동
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleBulkReclassify}
              disabled={isBulkReclassifying}
            >
              {isBulkReclassifying ? (
                <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
              ) : (
                <RotateCcw className="mr-1.5 h-3.5 w-3.5" />
              )}
              재분류
            </Button>
            <Button size="sm" variant="ghost" onClick={handleClearSelect}>
              취소
            </Button>
          </div>
        </div>
      )}

      {/* Bulk move dialog */}
      <Dialog open={showBulkMoveDialog} onOpenChange={setShowBulkMoveDialog}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>
              {selectedIds.size}개 파일 폴더 이동
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <label className="text-sm font-medium">이동할 폴더 경로</label>
            <input
              type="text"
              value={bulkMoveInput}
              onChange={(e) => setBulkMoveInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleBulkMove()}
              placeholder="예: 개발/TypeScript"
              autoFocus
              className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
            <p className="text-xs text-muted-foreground">
              슬래시(/)로 하위 폴더를 구분합니다.
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="ghost"
              onClick={() => setShowBulkMoveDialog(false)}
              disabled={isBulkMoving}
            >
              취소
            </Button>
            <Button onClick={handleBulkMove} disabled={isBulkMoving || !bulkMoveInput.trim()}>
              {isBulkMoving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              이동
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
