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
import { toast } from "sonner";
import { MoreHorizontal, UserCheck, UserX, Shield, Trash2, Clock } from "lucide-react";
import { format } from "date-fns";
import { ko } from "date-fns/locale";

interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  status: string;
  createdAt: string;
}

export default function UserManagementPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(true);

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
        <p className="text-sm text-muted-foreground">회원가입 승인 및 사용자 등급을 관리합니다.</p>
      </div>

      <div className="border rounded-lg bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>사용자</TableHead>
              <TableHead>이메일</TableHead>
              <TableHead>가입일</TableHead>
              <TableHead>상태</TableHead>
              <TableHead>권한</TableHead>
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
                  <TableCell className="font-medium">{user.name}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{user.email}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {format(new Date(user.createdAt), "yyyy-MM-dd", { locale: ko })}
                  </TableCell>
                  <TableCell>
                    <Badge variant={user.status === 'APPROVED' ? 'secondary' : user.status === 'PENDING' ? 'outline' : 'destructive'}>
                      {user.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="default" className={user.role === 'OWNER' ? 'bg-purple-500' : user.role === 'ADMIN' ? 'bg-blue-500' : 'bg-slate-500'}>
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon"><MoreHorizontal className="h-4 w-4" /></Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        {user.status === 'PENDING' && (
                          <DropdownMenuItem onClick={() => updateUser(user.id, { status: 'APPROVED' })}>
                            <UserCheck className="h-4 w-4 mr-2 text-green-600" /> 승인하기
                          </DropdownMenuItem>
                        )}
                        {user.status === 'APPROVED' && (
                          <DropdownMenuItem onClick={() => updateUser(user.id, { status: 'REJECTED' })}>
                            <UserX className="h-4 w-4 mr-2 text-red-600" /> 거절/정지
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuItem onClick={() => updateUser(user.id, { role: user.role === 'ADMIN' ? 'USER' : 'ADMIN' })}>
                          <Shield className="h-4 w-4 mr-2" /> 권한 변경
                        </DropdownMenuItem>
                        <DropdownMenuItem className="text-destructive" onClick={() => deleteUser(user.id)}>
                          <Trash2 className="h-4 w-4 mr-2" /> 추방하기
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
