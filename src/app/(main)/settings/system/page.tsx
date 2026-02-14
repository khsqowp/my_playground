"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { Save, Loader2 } from "lucide-react";

export default function SystemSettingsPage() {
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetch("/api/settings")
      .then((r) => r.json())
      .then((data) => {
        const map: Record<string, string> = {};
        data.settings?.forEach((s: { key: string; value: string }) => {
          map[s.key] = s.value;
        });
        setSettings(map);
      });
  }, []);

  function updateSetting(key: string, value: string) {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSave() {
    setLoading(true);
    try {
      const res = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ _updateSettings: true, settings }),
      });
      if (!res.ok) throw new Error();
      toast.success("설정이 저장되었습니다");
    } catch {
      toast.error("설정 저장에 실패했습니다");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold">시스템 설정</h1>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">일반</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>사이트 이름</Label>
            <Input
              value={settings.site_name || ""}
              onChange={(e) => updateSetting("site_name", e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>사이트 설명</Label>
            <Input
              value={settings.site_description || ""}
              onChange={(e) => updateSetting("site_description", e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>페이지당 글 수</Label>
            <Input
              type="number"
              value={settings.posts_per_page || "10"}
              onChange={(e) => updateSetting("posts_per_page", e.target.value)}
            />
          </div>
          <Button onClick={handleSave} disabled={loading}>
            {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
            설정 저장
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
