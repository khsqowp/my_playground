"use client";

import { useState } from "react";
import { Loader2, Pencil } from "lucide-react";
import { toast } from "sonner";
import { useRouter } from "next/navigation";

export default function FolderEditor({
  fileId,
  initialFolder,
}: {
  fileId: string;
  initialFolder: string;
}) {
  const [folder, setFolder] = useState(initialFolder);
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(initialFolder);
  const [saving, setSaving] = useState(false);
  const router = useRouter();

  const handleSave = async () => {
    if (!value.trim() || value.trim() === folder) {
      setEditing(false);
      return;
    }
    setSaving(true);
    try {
      const res = await fetch("/api/archive/files", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: fileId, folder: value.trim() }),
      });
      if (!res.ok) throw new Error("이동 실패");
      setFolder(value.trim());
      toast.success(`"${value.trim()}" 폴더로 이동했습니다.`);
      router.refresh();
    } catch {
      toast.error("폴더 이동 중 오류가 발생했습니다.");
    } finally {
      setSaving(false);
      setEditing(false);
    }
  };

  if (editing) {
    return (
      <span className="flex items-center gap-1">
        <input
          autoFocus
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleSave();
            if (e.key === "Escape") { setEditing(false); setValue(folder); }
          }}
          className="text-xs border rounded px-1.5 py-0.5 bg-background focus:outline-none focus:ring-1 focus:ring-primary w-48"
          placeholder="폴더 경로 (예: 개발/TypeScript)"
        />
        {saving ? (
          <Loader2 className="h-3 w-3 animate-spin" />
        ) : (
          <button onClick={handleSave} className="text-xs text-primary hover:underline">저장</button>
        )}
        <button
          onClick={() => { setEditing(false); setValue(folder); }}
          className="text-xs text-muted-foreground hover:text-foreground"
        >
          취소
        </button>
      </span>
    );
  }

  return (
    <button
      onClick={() => { setEditing(true); setValue(folder); }}
      className="flex items-center gap-1 hover:text-foreground transition-colors group"
      title="클릭하여 폴더 변경"
    >
      <span>{folder}</span>
      <Pencil className="h-2.5 w-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
    </button>
  );
}
