"use client";

import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Copy, Check } from "lucide-react";
import { toast } from "sonner";

interface ShareDialogProps {
  targetType: "POST" | "NOTE" | "QUIZSET" | "COLLECTION";
  targetId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ShareDialog({
  targetType,
  targetId,
  open,
  onOpenChange,
}: ShareDialogProps) {
  const [loading, setLoading] = useState(false);
  const [shareUrl, setShareUrl] = useState("");
  const [copied, setCopied] = useState(false);
  const [expiresIn, setExpiresIn] = useState("");
  const [maxAccess, setMaxAccess] = useState("");
  const [password, setPassword] = useState("");

  async function handleCreate() {
    setLoading(true);
    try {
      const body: Record<string, unknown> = { targetType, targetId };
      if (expiresIn) {
        const date = new Date();
        date.setHours(date.getHours() + parseInt(expiresIn));
        body.expiresAt = date.toISOString();
      }
      if (maxAccess) body.maxAccess = parseInt(maxAccess);
      if (password) body.password = password;

      const res = await fetch("/api/share", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) throw new Error("Failed to create share link");
      const data = await res.json();
      setShareUrl(`${window.location.origin}/share/${data.token}`);
      toast.success("공유 링크가 생성되었습니다");
    } catch {
      toast.error("공유 링크 생성에 실패했습니다");
    } finally {
      setLoading(false);
    }
  }

  function handleCopy() {
    navigator.clipboard.writeText(shareUrl);
    setCopied(true);
    toast.success("클립보드에 복사되었습니다");
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>공유 링크</DialogTitle>
          <DialogDescription>이 콘텐츠의 공유 링크를 생성합니다.</DialogDescription>
        </DialogHeader>

        {shareUrl ? (
          <div className="space-y-4">
            <div className="flex gap-2">
              <Input value={shareUrl} readOnly />
              <Button size="icon" variant="outline" onClick={handleCopy}>
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>만료 시간 (시간 단위, 선택사항)</Label>
              <Input
                type="number"
                placeholder="예: 24"
                value={expiresIn}
                onChange={(e) => setExpiresIn(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>최대 접근 횟수 (선택사항)</Label>
              <Input
                type="number"
                placeholder="예: 10"
                value={maxAccess}
                onChange={(e) => setMaxAccess(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>비밀번호 (선택사항)</Label>
              <Input
                type="password"
                placeholder="비밀번호 설정"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <Button onClick={handleCreate} disabled={loading} className="w-full">
              {loading ? "생성 중..." : "공유 링크 생성"}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
