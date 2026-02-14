"use client";

import { useState, useCallback } from "react";
import Papa from "papaparse";
import { Upload } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface CsvUploaderProps {
  onParsed: (data: { question: string; answer: string; hint?: string }[]) => void;
}

export function CsvUploader({ onParsed }: CsvUploaderProps) {
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState("");

  const handleFile = useCallback(
    (file: File) => {
      if (!file.name.endsWith(".csv")) {
        toast.error("CSV 파일을 업로드해주세요");
        return;
      }

      setFileName(file.name);

      Papa.parse(file, {
        header: true,
        skipEmptyLines: true,
        complete(results) {
          const questions = (results.data as Record<string, string>[])
            .filter((row) => row.question && row.answer)
            .map((row) => ({
              question: row.question.trim(),
              answer: row.answer.trim(),
              hint: row.hint?.trim() || undefined,
            }));

          if (questions.length === 0) {
            toast.error("유효한 문제가 없습니다. CSV에 'question'과 'answer' 열이 필요합니다.");
            return;
          }

          onParsed(questions);
          toast.success(`${questions.length}개 문제가 파싱되었습니다`);
        },
        error() {
          toast.error("CSV 파싱에 실패했습니다");
        },
      });
    },
    [onParsed]
  );

  return (
    <div
      className={cn(
        "rounded-lg border-2 border-dashed p-8 text-center transition-colors",
        dragging ? "border-primary bg-primary/5" : "border-muted-foreground/25"
      )}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files[0];
        if (file) handleFile(file);
      }}
    >
      <Upload className="mx-auto h-8 w-8 text-muted-foreground" />
      <p className="mt-2 text-sm text-muted-foreground">
        CSV 드래그 앤 드롭 또는{" "}
        <label className="cursor-pointer text-primary underline">
          파일 선택
          <input type="file" accept=".csv" className="hidden" onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
          }} />
        </label>
      </p>
      <p className="mt-1 text-xs text-muted-foreground">
        형식: question, answer, hint (선택사항)
      </p>
      {fileName && <p className="mt-2 text-sm font-medium">{fileName}</p>}
    </div>
  );
}
