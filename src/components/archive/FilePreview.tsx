"use client";

import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

interface PreviewData {
  type: "text" | "markdown" | "html" | "table";
  content?: string;
  sheets?: Record<string, string[][]>;
}

export default function FilePreview({ fileId }: { fileId: string }) {
  const [data, setData] = useState<PreviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/archive/files/${fileId}/preview`)
      .then(async (r) => {
        if (!r.ok) throw new Error("미리보기를 불러올 수 없습니다.");
        return r.json();
      })
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [fileId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground gap-2">
        <Loader2 className="h-4 w-4 animate-spin" />
        <span className="text-sm">불러오는 중...</span>
      </div>
    );
  }

  if (error) {
    return <p className="text-sm text-muted-foreground py-4 text-center">{error}</p>;
  }

  if (!data) return null;

  if (data.type === "text") {
    return (
      <pre className="text-xs font-mono whitespace-pre-wrap break-all leading-relaxed">
        {data.content}
      </pre>
    );
  }

  if (data.type === "markdown") {
    return (
      <pre className="text-xs font-mono whitespace-pre-wrap break-all leading-relaxed">
        {data.content}
      </pre>
    );
  }

  if (data.type === "html") {
    return (
      <div
        className="prose prose-sm dark:prose-invert max-w-none text-sm"
        dangerouslySetInnerHTML={{ __html: data.content || "" }}
      />
    );
  }

  if (data.type === "table" && data.sheets) {
    return (
      <div className="space-y-6">
        {Object.entries(data.sheets).map(([sheetName, rows]) => (
          <div key={sheetName}>
            <p className="text-xs font-semibold text-muted-foreground mb-2">{sheetName}</p>
            <div className="overflow-auto max-h-96">
              <table className="text-xs border-collapse w-full">
                <tbody>
                  {rows.map((row, ri) => (
                    <tr key={ri} className={ri === 0 ? "bg-muted/50 font-medium" : ""}>
                      {(row as string[]).map((cell, ci) => (
                        <td
                          key={ci}
                          className="border border-border px-2 py-1 whitespace-nowrap max-w-48 truncate"
                          title={String(cell)}
                        >
                          {String(cell)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </div>
    );
  }

  return null;
}
