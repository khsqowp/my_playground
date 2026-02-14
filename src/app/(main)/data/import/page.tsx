"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { FileUpload } from "@/components/shared/FileUpload";
import { toast } from "sonner";
import { Upload, Loader2 } from "lucide-react";

export default function DataImportPage() {
  const [collections, setCollections] = useState<{ id: string; name: string }[]>([]);
  const [collectionId, setCollectionId] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetch("/api/settings?_collections=true")
      .then((r) => r.json())
      .then((data) => { if (data.collections) setCollections(data.collections); })
      .catch(() => { });
  }, []);

  async function handleImport() {
    if (!file || !collectionId) { toast.error("콜렉션과 파일을 선택해주세요"); return; }
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("collectionId", collectionId);
      const res = await fetch("/api/data/import", { method: "POST", body: formData });
      if (!res.ok) throw new Error();
      const data = await res.json();
      toast.success(`${data.imported}개 레코드가 가져와졌습니다`);
    } catch {
      toast.error("가져오기에 실패했습니다");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold">데이터 가져오기</h1>
      <div className="space-y-4">
        <div className="space-y-2">
          <Label>대상 콜렉션</Label>
          <Select value={collectionId} onValueChange={setCollectionId}>
            <SelectTrigger><SelectValue placeholder="콜렉션 선택" /></SelectTrigger>
            <SelectContent>
              {collections.map((c) => (<SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>파일 (CSV 또는 JSON)</Label>
          <div
            className="rounded-lg border-2 border-dashed p-6 text-center"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) setFile(f); }}
          >
            <Upload className="mx-auto h-8 w-8 text-muted-foreground" />
            <label className="mt-2 block cursor-pointer text-sm text-primary underline">
              파일 선택
              <input type="file" accept=".csv,.json" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)} />
            </label>
            {file && <p className="mt-2 text-sm font-medium">{file.name}</p>}
          </div>
        </div>
        <Button onClick={handleImport} disabled={loading || !file || !collectionId} className="w-full">
          {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Upload className="mr-2 h-4 w-4" />}
          가져오기
        </Button>
      </div>
    </div>
  );
}
