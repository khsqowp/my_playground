"use client";

import { useState, useCallback } from "react";
import { Upload, X, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface FileUploadProps {
  onUpload: (url: string) => void;
  accept?: string;
  maxSize?: number;
}

export function FileUpload({
  onUpload,
  accept = "image/*",
  maxSize = 10,
}: FileUploadProps) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);

  const handleFile = useCallback(
    async (file: File) => {
      if (file.size > maxSize * 1024 * 1024) {
        toast.error(`파일 크기는 ${maxSize}MB 이하여야 합니다`);
        return;
      }

      if (file.type.startsWith("image/")) {
        setPreview(URL.createObjectURL(file));
      }

      setUploading(true);
      try {
        const formData = new FormData();
        formData.append("file", file);

        const res = await fetch("/api/upload", { method: "POST", body: formData });
        if (!res.ok) throw new Error("Upload failed");

        const data = await res.json();
        onUpload(data.url);
        toast.success("파일이 업로드되었습니다");
      } catch {
        toast.error("업로드에 실패했습니다");
        setPreview(null);
      } finally {
        setUploading(false);
      }
    },
    [maxSize, onUpload]
  );

  return (
    <div
      className={cn(
        "relative rounded-lg border-2 border-dashed p-6 text-center transition-colors",
        dragging ? "border-primary bg-primary/5" : "border-muted-foreground/25"
      )}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files[0];
        if (file) handleFile(file);
      }}
    >
      {preview && (
        <div className="mb-4 relative inline-block">
          <img src={preview} alt="미리보기" className="max-h-32 rounded" />
          <Button
            size="icon"
            variant="destructive"
            className="absolute -top-2 -right-2 h-6 w-6"
            onClick={() => setPreview(null)}
          >
            <X className="h-3 w-3" />
          </Button>
        </div>
      )}

      {uploading ? (
        <Loader2 className="mx-auto h-8 w-8 animate-spin text-muted-foreground" />
      ) : (
        <>
          <Upload className="mx-auto h-8 w-8 text-muted-foreground" />
          <p className="mt-2 text-sm text-muted-foreground">
            드래그 앤 드롭 또는{" "}
            <label className="cursor-pointer text-primary underline">
              파일 선택
              <input
                type="file"
                className="hidden"
                accept={accept}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) handleFile(file);
                }}
              />
            </label>
          </p>
          <p className="mt-1 text-xs text-muted-foreground">최대 {maxSize}MB</p>
        </>
      )}
    </div>
  );
}
