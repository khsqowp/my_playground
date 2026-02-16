"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { Plus, Database, Clock, LayoutGrid, List } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogTrigger,
  DialogFooter
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";

export default function MeetingsListPage() {
  const [projects, setProjects] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [newProjectName, setNewProjectName] = useState("");
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjects = async () => {
    try {
      const res = await fetch("/api/automation/meetings/list");
      if (res.ok) {
        const data = await res.json();
        setProjects(data);
      }
    } catch (error) {
      toast.error("프로젝트 목록을 불러오지 못했습니다.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateProject = async () => {
    if (!newProjectName) return;
    try {
      const res = await fetch("/api/automation/meetings/list", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newProjectName })
      });
      if (res.ok) {
        toast.success("새 프로젝트가 생성되었습니다.");
        setIsDialogOpen(false);
        setNewProjectName("");
        fetchProjects();
      } else {
        toast.error("이미 존재하는 이름이거나 생성이 불가능합니다.");
      }
    } catch (error) {
      toast.error("오류가 발생했습니다.");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold">회의 및 프로젝트 관리</h1>
          <p className="text-sm text-muted-foreground">진행 중인 모든 프로젝트의 수집 로그를 관리합니다.</p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              새 프로젝트 생성
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>새 프로젝트 생성</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="name">프로젝트 이름</Label>
                <Input 
                  id="name" 
                  placeholder="예: SK_Rookies_FinalPJT" 
                  value={newProjectName}
                  onChange={(e) => setNewProjectName(e.target.value)}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsDialogOpen(false)}>취소</Button>
              <Button onClick={handleCreateProject}>생성하기</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-40 rounded-xl bg-muted animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <Link key={project.id} href={`/data/meetings/${project.name}`}>
              <Card className="hover:shadow-lg transition-all cursor-pointer border-2 hover:border-blue-500 h-full group">
                <CardHeader>
                  <div className="flex justify-between items-start">
                    <div className="p-2 bg-blue-50 rounded-lg group-hover:bg-blue-500 transition-colors">
                      <Database className="h-6 w-6 text-blue-500 group-hover:text-white" />
                    </div>
                    <Badge variant="outline" className="text-[10px]">
                      {project._count?.activityLogs || 0} Logs
                    </Badge>
                  </div>
                  <CardTitle className="mt-4 text-xl">{project.name}</CardTitle>
                  <CardDescription className="line-clamp-2">
                    {project.description || "등록된 설명이 없습니다."}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center text-xs text-muted-foreground gap-4">
                    <div className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(project.createdAt).toLocaleDateString()}
                    </div>
                    <div className="flex items-center gap-1">
                      <LayoutGrid className="h-3 w-3" />
                      {project._count?.sessions || 0} Sessions
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
          
          {projects.length === 0 && (
            <Card className="col-span-full border-dashed p-12 flex flex-col items-center justify-center text-center opacity-60">
              <Database className="h-12 w-12 mb-4 text-muted-foreground" />
              <p>생성된 프로젝트가 없습니다.</p>
              <p className="text-sm text-muted-foreground mt-1">우측 상단 버튼을 눌러 첫 프로젝트를 시작해 보세요.</p>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function Badge({ children, variant, className }: any) {
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
      variant === 'outline' ? 'border text-muted-foreground' : 'bg-primary text-primary-foreground'
    } ${className}`}>
      {children}
    </span>
  );
}
