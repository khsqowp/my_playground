"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DataTable } from "@/components/data/DataTable";
import { Plus, Database } from "lucide-react";
import { toast } from "sonner";

interface Collection {
  id: string;
  name: string;
  description: string | null;
  schema: { name: string; type: string }[];
  _count?: { records: number };
}

interface Record_ {
  id: string;
  data: Record<string, unknown>;
}

export default function DataBrowsePage() {
  const [collections, setCollections] = useState<Collection[]>([]);
  const [selected, setSelected] = useState<Collection | null>(null);
  const [records, setRecords] = useState<Record_[]>([]);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newFields, setNewFields] = useState("name:string");
  const [dialogOpen, setDialogOpen] = useState(false);

  useEffect(() => {
    fetch("/api/settings?_collections=true")
      .then((r) => r.json())
      .then((data) => { if (data.collections) setCollections(data.collections); })
      .catch(() => { });
  }, []);

  useEffect(() => {
    if (!selected) return;
    fetch(`/api/data/export?collectionId=${selected.id}&format=json`)
      .then((r) => r.json())
      .then((data) => setRecords(Array.isArray(data) ? data.map((d: Record<string, unknown>, i: number) => ({ id: String(i), data: d })) : []))
      .catch(() => { });
  }, [selected]);

  async function createCollection() {
    if (!newName.trim()) return;
    const schema = newFields.split(",").map((f) => {
      const [name, type] = f.trim().split(":");
      return { name: name.trim(), type: type?.trim() || "string" };
    });

    try {
      const res = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ _createCollection: true, name: newName, description: newDesc, schema }),
      });
      if (!res.ok) throw new Error();
      const created = await res.json();
      setCollections((prev) => [...prev, created]);
      setDialogOpen(false);
      setNewName("");
      setNewDesc("");
      toast.success("콜렉션이 생성되었습니다");
    } catch {
      toast.error("생성에 실패했습니다");
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">데이터 찾아보기</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button><Plus className="mr-2 h-4 w-4" />새 콜렉션</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>새 콜렉션</DialogTitle></DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>이름</Label>
                <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="콜렉션 이름" />
              </div>
              <div className="space-y-2">
                <Label>설명</Label>
                <Input value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="선택사항" />
              </div>
              <div className="space-y-2">
                <Label>필드 (이름:타입, 쉼표로 구분)</Label>
                <Input value={newFields} onChange={(e) => setNewFields(e.target.value)} placeholder="name:string, age:number" />
              </div>
              <Button onClick={createCollection} className="w-full">생성</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4 lg:grid-cols-4">
        <div className="space-y-2">
          {collections.map((c) => (
            <Card
              key={c.id}
              className={`cursor-pointer transition-shadow hover:shadow-sm ${selected?.id === c.id ? "border-primary" : ""}`}
              onClick={() => setSelected(c)}
            >
              <CardContent className="p-3">
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4" />
                  <span className="font-medium text-sm">{c.name}</span>
                </div>
              </CardContent>
            </Card>
          ))}
          {collections.length === 0 && <p className="text-sm text-muted-foreground">콜렉션이 없습니다</p>}
        </div>

        <div className="lg:col-span-3">
          {selected ? (
            <Card>
              <CardHeader>
                <CardTitle>{selected.name}</CardTitle>
              </CardHeader>
              <CardContent>
                <DataTable
                  columns={selected.schema.map((s) => s.name)}
                  data={records.map((r) => r.data)}
                />
              </CardContent>
            </Card>
          ) : (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              콜렉션을 선택하여 레코드를 확인하세요
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
