"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  FileArchive,
  FileText,
  File,
  Upload,
  Trash2,
  Loader2,
  Search,
} from "lucide-react";
import { toast } from "sonner";
import { format } from "date-fns";
import { ko } from "date-fns/locale";

function FileIcon({ ext }: { ext: string }) {
  if (ext === "zip") return <FileArchive className="h-5 w-5 text-yellow-500" />;
  if (["txt", "md"].includes(ext)) return <FileText className="h-5 w-5 text-blue-500" />;
  if (ext === "pdf") return <File className="h-5 w-5 text-red-500" />;
  if (ext === "docx") return <File className="h-5 w-5 text-blue-700" />;
  if (ext === "xlsx") return <File className="h-5 w-5 text-green-600" />;
  if (ext === "pptx") return <File className="h-5 w-5 text-orange-500" />;
  return <File className="h-5 w-5 text-muted-foreground" />;
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

export default function ArchiveFilesPage() {
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [uploading, setUploading] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchFiles = (q = "") => {
    setLoading(true);
    const params = new URLSearchParams();
    if (q) params.set("search", q);
    fetch(`/api/archive/files?${params}`)
      .then((r) => r.json())
      .then((data) => {
        if (data.files) setFiles(data.files);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchFiles(search);
  };

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/archive/files/upload", {
        method: "POST",
        body: formData,
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "업로드 실패");
      }
      toast.success("파일 업로드 및 AI 분석 완료!");
      fetchFiles(search);
    } catch (err: any) {
      toast.error(err.message || "업로드 중 오류가 발생했습니다.");
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

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
    } catch {
      toast.error("삭제 중 오류가 발생했습니다.");
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <FileArchive className="h-6 w-6 text-primary" />
          파일 아카이브
        </h1>
        <Button onClick={() => fileInputRef.current?.click()} disabled={uploading}>
          {uploading ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Upload className="mr-2 h-4 w-4" />
          )}
          파일 업로드
        </Button>
        <input
          ref={fileInputRef}
          type="file"
          accept=".zip,.pdf,.txt,.md,.docx,.xlsx,.pptx"
          onChange={handleUpload}
          className="hidden"
        />
      </div>

      <form onSubmit={handleSearch} className="flex gap-2">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="파일명, AI 요약, 태그 검색..."
          className="flex-1 rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
        />
        <Button type="submit" variant="outline">
          <Search className="h-4 w-4" />
        </Button>
      </form>

      {loading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-40 bg-muted animate-pulse rounded-lg" />
          ))}
        </div>
      ) : files.length === 0 ? (
        <Card className="p-12 text-center text-muted-foreground border-dashed">
          <FileArchive className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>업로드된 파일이 없습니다.</p>
          <p className="text-sm mt-1">zip, pdf, txt, md, docx, xlsx, pptx 파일을 업로드해보세요.</p>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {files.map((file) => (
            <Card key={file.id} className="overflow-hidden hover:ring-1 hover:ring-primary transition-all">
              <CardContent className="p-4 space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <FileIcon ext={file.extension} />
                    <span className="font-medium text-sm truncate">{file.fileName}</span>
                  </div>
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
                </div>

                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>{formatBytes(file.fileSize)}</span>
                  <span>•</span>
                  <span>{format(new Date(file.createdAt), "yyyy-MM-dd", { locale: ko })}</span>
                </div>

                <AiStatusBadge status={file.aiStatus} />

                {file.aiSummary && (
                  <p className="text-xs text-muted-foreground line-clamp-2">{file.aiSummary}</p>
                )}

                {file.aiTags && (
                  <div className="flex flex-wrap gap-1">
                    {file.aiTags.split(",").slice(0, 4).map((tag: string) => (
                      <Badge key={tag} variant="secondary" className="text-[10px]">
                        {tag.trim()}
                      </Badge>
                    ))}
                  </div>
                )}

                <Link
                  href={`/archive/files/${file.id}`}
                  className="block text-xs text-primary hover:underline"
                >
                  상세 보기 →
                </Link>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
