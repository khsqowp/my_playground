"use client";

import { useState, useEffect } from "react";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuTrigger 
} from "@/components/ui/dropdown-menu";
import { 
  Dialog, 
  DialogContent, 
  DialogDescription, 
  DialogFooter, 
  DialogHeader, 
  DialogTitle,
  DialogTrigger
} from "@/components/ui/dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { toast } from "sonner";
import { MoreHorizontal, UserCheck, UserX, Shield, Trash2, Clock, Settings2 } from "lucide-react";
import { format } from "date-fns";
import ko from "date-fns/locale/ko";

interface Permission {
  view: boolean;
  use: boolean;
}

interface Permissions {
  dashboard: Permission;
  blog: Permission;
  portfolio: Permission;
  archive: Permission;
  data: Permission;
  automation: Permission;
  activity: Permission;
  persona: Permission;
  tools: Permission;
  links: Permission;
}

interface User {
  id: string;
  name: string;
  email: string;
  phone: string;
  birthDate: string;
  role: string;
  status: string;
  permissions: Permissions | null;
  createdAt: string;
}

const PERMISSION_LABELS: Record<keyof Permissions, string> = {
  dashboard: "대시보드",
  blog: "블로그",
  portfolio: "포트폴리오",
  archive: "아카이브",
  data: "데이터",
  automation: "자동화",
  activity: "활동로그",
  persona: "페르소나 AI",
  tools: "도구",
  links: "링크"
};

const DEFAULT_PERMISSIONS: Permissions = {
  dashboard: { view: false, use: false },
  blog: { view: false, use: false },
  portfolio: { view: false, use: false },
  archive: { view: false, use: false },
  data: { view: false, use: false },
  automation: { view: false, use: false },
  activity: { view: false, use: false },
  persona: { view: false, use: false },
  tools: { view: false, use: false },
  links: { view: false, use: false },
};

export default function UserManagementPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [editPermissions, setEditPermissions] = useState<Permissions>(DEFAULT_PERMISSIONS);
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/admin/users");
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      }
    } catch (error) {
      toast.error("사용자 목록을 불러오지 못했습니다.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleOpenPermissions = (user: User) => {
    setSelectedUser(user);
    setEditPermissions(user.permissions || DEFAULT_PERMISSIONS);
    setIsDialogOpen(true);
  };

  const togglePermission = (key: keyof Permissions, type: 'view' | 'use') => {
    setEditPermissions(prev => ({
      ...prev,
      [key]: {
        ...prev[key],
        [type]: !prev[key][type]
      }
    }));
  };

  const savePermissions = async () => {
    if (!selectedUser) return;
    
    try {
      const res = await fetch("/api/admin/users", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          userId: selectedUser.id, 
          permissions: editPermissions,
          status: selectedUser.status === 'PENDING' ? 'APPROVED' : selectedUser.status
        })
      });
      if (res.ok) {
        toast.success("권한 정보가 업데이트되었습니다.");
        setIsDialogOpen(false);
        fetchUsers();
      }
    } catch (error) {
      toast.error("업데이트 실패");
    }
  };

  const updateUser = async (userId: string, data: any) => {
    try {
      const res = await fetch("/api/admin/users", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, ...data })
      });
      if (res.ok) {
        toast.success("사용자 정보가 업데이트되었습니다.");
        fetchUsers();
      }
    } catch (error) {
      toast.error("업데이트 실패");
    }
  };

  const deleteUser = async (userId: string) => {
    if (!confirm("정말로 이 사용자를 추방(삭제)하시겠습니까?")) return;
    try {
      const res = await fetch(`/api/admin/users?userId=${userId}`, {
        method: "DELETE"
      });
      if (res.ok) {
        toast.success("사용자가 삭제되었습니다.");
        fetchUsers();
      }
    } catch (error) {
      toast.error("삭제 실패");
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">사용자 및 권한 관리</h1>
        <p className="text-sm text-muted-foreground">회원가입 승인 및 서비스별 상세 권한을 관리합니다.</p>
      </div>

      <div className="border rounded-lg bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>사용자 정보</TableHead>
              <TableHead>연락처/생일</TableHead>
              <TableHead>가입일</TableHead>
              <TableHead>상태</TableHead>
              <TableHead>등급</TableHead>
              <TableHead className="text-right">관리</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              [1, 2, 3].map(i => (
                <TableRow key={i}><TableCell colSpan={6} className="h-12 bg-muted animate-pulse" /></TableRow>
              ))
            ) : users.length === 0 ? (
              <TableRow><TableCell colSpan={6} className="text-center py-10 text-muted-foreground">가입된 사용자가 없습니다.</TableCell></TableRow>
            ) : (
              users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="font-medium">{user.name}</span>
                      <span className="text-xs text-muted-foreground">{user.email}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col text-xs">
                      <span>{user.phone || '-'}</span>
                      <span className="text-muted-foreground">{user.birthDate || '-'}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {format(new Date(user.createdAt), "yyyy-MM-dd", { locale: ko })}
                  </TableCell>
                  <TableCell>
                    <Badge variant={user.status === 'APPROVED' ? 'secondary' : user.status === 'PENDING' ? 'outline' : 'destructive'}>
                      {user.status === 'APPROVED' ? '승인완료' : user.status === 'PENDING' ? '승인대기' : '정지/거절'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="default" className={user.role === 'OWNER' ? 'bg-purple-500' : user.role === 'ADMIN' ? 'bg-blue-500' : 'bg-slate-500'}>
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => handleOpenPermissions(user)}>
                        <Settings2 className="h-4 w-4 mr-1" /> 권한설정
                      </Button>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon"><MoreHorizontal className="h-4 w-4" /></Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          {user.status === 'PENDING' && (
                            <DropdownMenuItem onClick={() => handleOpenPermissions(user)}>
                              <UserCheck className="h-4 w-4 mr-2 text-green-600" /> 승인하기
                            </DropdownMenuItem>
                          )}
                          {user.status === 'APPROVED' && (
                            <DropdownMenuItem onClick={() => updateUser(user.id, { status: 'REJECTED' })}>
                              <UserX className="h-4 w-4 mr-2 text-red-600" /> 정지시키기
                            </DropdownMenuItem>
                          )}
                          {user.status === 'REJECTED' && (
                            <DropdownMenuItem onClick={() => updateUser(user.id, { status: 'APPROVED' })}>
                              <UserCheck className="h-4 w-4 mr-2 text-green-600" /> 다시 승인
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuItem onClick={() => updateUser(user.id, { role: user.role === 'ADMIN' ? 'USER' : 'ADMIN' })}>
                            <Shield className="h-4 w-4 mr-2" /> 등급 변경
                          </DropdownMenuItem>
                          <DropdownMenuItem className="text-destructive" onClick={() => deleteUser(user.id)}>
                            <Trash2 className="h-4 w-4 mr-2" /> 추방하기
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{selectedUser?.name} 권한 설정</DialogTitle>
            <DialogDescription>
              각 서비스별 보기 및 사용 권한을 설정합니다. {selectedUser?.status === 'PENDING' && "저장 시 자동으로 승인 처리됩니다."}
            </DialogDescription>
          </DialogHeader>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 py-4">
            {(Object.keys(PERMISSION_LABELS) as Array<keyof Permissions>).map((key) => (
              <div key={key} className="flex items-center justify-between p-3 border rounded-lg bg-muted/30">
                <span className="font-medium text-sm">{PERMISSION_LABELS[key]}</span>
                <div className="flex gap-4">
                  <div className="flex items-center space-x-2">
                    <Checkbox 
                      id={`${key}-view`} 
                      checked={editPermissions[key].view}
                      onCheckedChange={() => togglePermission(key, 'view')}
                    />
                    <label htmlFor={`${key}-view`} className="text-xs font-medium leading-none cursor-pointer">보기</label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox 
                      id={`${key}-use`} 
                      checked={editPermissions[key].use}
                      onCheckedChange={() => togglePermission(key, 'use')}
                    />
                    <label htmlFor={`${key}-use`} className="text-xs font-medium leading-none cursor-pointer">사용</label>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setIsDialogOpen(false)}>취소</Button>
            <Button onClick={savePermissions}>저장하기</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
