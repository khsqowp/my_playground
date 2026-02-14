"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { Send, Sparkles } from "lucide-react";

interface MemoInputProps {
  onSaved?: () => void;
}

export function MemoInput({ onSaved }: MemoInputProps) {
  const [content, setContent] = useState("");
  const [tag, setTag] = useState("");
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!content.trim()) return;
    setSaving(true);
    try {
      const res = await fetch("/api/data/memo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, categoryTag: tag || null }),
      });
      if (!res.ok) throw new Error();
      setContent("");
      setTag("");
      toast.success("메모가 저장되었습니다");
      onSaved?.();
    } catch {
      toast.error("저장에 실패했습니다");
    } finally {
      setSaving(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      handleSave();
    }
  }

  return (
    <div className="space-y-2">
      <Textarea
        placeholder="빠른 메모... (Ctrl+Enter로 저장)"
        value={content}
        onChange={(e) => setContent(e.target.value)}
        onKeyDown={handleKeyDown}
        className="min-h-[100px]"
      />
      <div className="flex gap-2">
        <Input
          placeholder="태그 (선택사항)"
          value={tag}
          onChange={(e) => setTag(e.target.value)}
          className="max-w-[200px]"
        />
        <Button
          variant="outline"
          size="icon"
          disabled={saving || !content.trim()}
          onClick={async () => {
            if (!content.trim()) return;
            const toastId = toast.loading("AI 분석 중...");
            try {
              const res = await fetch("/api/automation/ai/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text: content, type: "tagging" }),
              });
              if (!res.ok) throw new Error();
              const data = await res.json();
              if (data.tags && data.tags.length > 0) {
                setTag(data.tags.join(", "));
                toast.success("태그가 자동 생성되었습니다", { id: toastId });
              } else {
                toast.error("AI가 태그를 생성하지 못했습니다", { id: toastId });
              }
            } catch {
              toast.error("AI 분석 실패", { id: toastId });
            }
          }}
          title="AI 자동 태그 생성"
        >
          <Sparkles className="h-4 w-4 text-purple-500" />
        </Button>
        <Button onClick={handleSave} disabled={saving || !content.trim()}>
          <Send className="mr-2 h-4 w-4" />
          저장
        </Button>
      </div>
    </div>
  );
}
