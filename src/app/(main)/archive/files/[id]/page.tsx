export const dynamic = "force-dynamic";
import { notFound } from "next/navigation";
import Link from "next/link";
import prisma from "@/lib/prisma";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  ArrowLeft,
  FileArchive,
  File,
  FileText,
  ChevronRight,
  ChevronDown,
  Download,
  Folder,
} from "lucide-react";
import { formatDate } from "@/lib/utils";
import FilePreview from "@/components/archive/FilePreview";
import FolderEditor from "@/components/archive/FolderEditor";

interface ZipEntry {
  name: string;
  path: string;
  size: number;
  isDir: boolean;
  children?: ZipEntry[];
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function ZipTreeNode({ entry, depth = 0 }: { entry: ZipEntry; depth?: number }) {
  if (entry.isDir) {
    return (
      <details className="group" style={{ marginLeft: depth * 16 }}>
        <summary className="flex items-center gap-1 cursor-pointer py-0.5 text-sm">
          <ChevronRight className="h-3 w-3 group-open:hidden shrink-0" />
          <ChevronDown className="h-3 w-3 hidden group-open:block shrink-0" />
          <FileArchive className="h-3 w-3 text-yellow-500 shrink-0" />
          <span className="font-medium">{entry.name}/</span>
        </summary>
        <div>
          {entry.children?.map((child) => (
            <ZipTreeNode key={child.path} entry={child} depth={depth + 1} />
          ))}
        </div>
      </details>
    );
  }

  return (
    <div
      className="flex items-center gap-1 py-0.5 text-sm"
      style={{ marginLeft: (depth + 1) * 16 }}
    >
      <FileText className="h-3 w-3 text-muted-foreground shrink-0" />
      <span>{entry.name}</span>
      {entry.size > 0 && (
        <span className="text-xs text-muted-foreground ml-auto">{formatBytes(entry.size)}</span>
      )}
    </div>
  );
}

function FileIcon({ ext }: { ext: string }) {
  if (ext === "zip") return <FileArchive className="h-6 w-6 text-yellow-500" />;
  if (["txt", "md"].includes(ext)) return <FileText className="h-6 w-6 text-blue-500" />;
  if (ext === "pdf") return <File className="h-6 w-6 text-red-500" />;
  if (ext === "docx") return <File className="h-6 w-6 text-blue-700" />;
  if (ext === "xlsx") return <File className="h-6 w-6 text-green-600" />;
  if (ext === "pptx") return <File className="h-6 w-6 text-orange-500" />;
  return <File className="h-6 w-6 text-muted-foreground" />;
}

const STATUS_INFO: Record<string, { label: string; variant: any }> = {
  DONE: { label: "AI 분석 완료", variant: "default" },
  PENDING: { label: "대기 중", variant: "secondary" },
  PROCESSING: { label: "분석 중", variant: "secondary" },
  FAILED: { label: "분석 실패", variant: "destructive" },
  SKIPPED: { label: "AI 분석 미지원 (미리보기 제공)", variant: "outline" },
};

const PREVIEW_EXTS = ["txt", "md", "docx", "xlsx"];

export default async function ArchiveFileDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  const file = await prisma.archiveFile.findUnique({
    where: { id },
    include: { author: { select: { name: true } } },
  });

  if (!file) notFound();

  const statusInfo = STATUS_INFO[file.aiStatus] || { label: file.aiStatus, variant: "outline" };
  const zipTree = file.zipTree as ZipEntry[] | null;
  const canPreview = PREVIEW_EXTS.includes(file.extension);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/archive/files">
            <ArrowLeft className="mr-2 h-4 w-4" />
            파일 아카이브
          </Link>
        </Button>
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-3">
          <FileIcon ext={file.extension} />
          <h1 className="text-2xl font-bold break-all">{file.fileName}</h1>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
          <span>{formatBytes(file.fileSize)}</span>
          <span>•</span>
          <span className="uppercase font-mono">{file.extension}</span>
          <span>•</span>
          <span>{formatDate(file.createdAt)}</span>
          <span>•</span>
          <span>{file.author.name}</span>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant={statusInfo.variant}>{statusInfo.label}</Badge>
          <div className="flex items-center gap-1 text-xs text-muted-foreground">
            <Folder className="h-3 w-3" />
            <FolderEditor fileId={file.id} initialFolder={file.folder} />
          </div>
        </div>
      </div>

      <Separator />

      {/* AI Analysis */}
      {(file.aiSummary || file.aiTags) && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">AI 분석 결과</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {file.aiSummary && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1">요약</p>
                <p className="text-sm">{file.aiSummary}</p>
              </div>
            )}
            {file.aiTags && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1">태그</p>
                <div className="flex flex-wrap gap-1">
                  {file.aiTags.split(",").map((tag: string) => (
                    <Badge key={tag} variant="secondary">
                      {tag.trim()}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* PDF Viewer */}
      {file.extension === "pdf" && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <File className="h-4 w-4 text-red-500" />
              PDF 미리보기
            </CardTitle>
          </CardHeader>
          <CardContent>
            <iframe
              src={`${file.filePath}#toolbar=1&navpanes=0`}
              className="w-full rounded-md border"
              style={{ height: "70vh", minHeight: "500px" }}
              title={file.fileName}
            />
          </CardContent>
        </Card>
      )}

      {/* Inline viewer for txt / md / docx / xlsx */}
      {canPreview && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <FileText className="h-4 w-4 text-blue-500" />
              파일 미리보기
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border bg-muted/20 p-4 max-h-[60vh] overflow-auto">
              <FilePreview fileId={file.id} />
            </div>
          </CardContent>
        </Card>
      )}

      {/* ZIP Tree */}
      {file.extension === "zip" && zipTree && zipTree.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <FileArchive className="h-4 w-4" />
              ZIP 파일 구조
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border bg-muted/30 p-3 font-mono max-h-[500px] overflow-y-auto">
              {zipTree.map((entry) => (
                <ZipTreeNode key={entry.path} entry={entry} />
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Download */}
      <Card>
        <CardContent className="p-4">
          <a
            href={file.filePath}
            download={file.fileName}
            className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
          >
            <Download className="h-4 w-4" />
            {file.fileName} 다운로드
          </a>
        </CardContent>
      </Card>
    </div>
  );
}
