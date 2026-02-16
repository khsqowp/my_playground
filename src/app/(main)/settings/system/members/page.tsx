"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TableList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { UserCheck, UserX, Trash2, Phone } from "lucide-react";
import { formatDate } from "@/lib/utils";

export default function MembersManagementPage() {
  const [members, setMembers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchMembers = async () => {
    try {
      const res = await fetch("/api/admin/members");
      const data = await res.json();
      setMembers(data);
    } catch (error) {
      toast.error("멤버 목록을 불러오지 못했습니다.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchMembers(); }, []);

  const handleUpdateStatus = async (id: string, status: string) => {
    try {
      const res = await fetch("/api/admin/members", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, status }),
      });
      if (!res.ok) throw new Error();
      toast.success(status === "APPROVED" ? "승인되었습니다." : "거절되었습니다.");
      fetchMembers();
    } catch {
      toast.error("처리에 실패했습니다.");
    }
  };

  const handleEvict = async (id: string) => {
    if (!confirm("정말 이 멤버를 추방하시겠습니까? 관련 데이터가 모두 삭제될 수 있습니다.")) return;
    try {
      const res = await fetch(`/api/admin/members?id=${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error();
      toast.success("멤버가 추방되었습니다.");
      fetchMembers();
    } catch {
      toast.error("추방 처리에 실패했습니다.");
    }
  };

  const pendingUsers = members.filter(m => m.status === "PENDING");
  const approvedUsers = members.filter(m => m.status === "APPROVED");

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">멤버 관리</h1>

      <Tabs defaultValue="pending" className="w-full">
        <div className="flex items-center justify-between mb-4">
          <div className="flex gap-2">
            <TabsTrigger value="pending" className="relative">
              가입 신청
              {pendingUsers.length > 0 && (
                <span className="ml-2 bg-primary text-primary-foreground text-[10px] px-1.5 py-0.5 rounded-full">
                  {pendingUsers.length}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger value="approved">활동 멤버</TabsTrigger>
          </div>
        </div>

        <TabsContent value="pending">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">가입 신청 대기</CardTitle>
              <CardDescription>승인이 필요한 사용자 목록입니다.</CardDescription>
            </CardHeader>
            <CardContent>
              {pendingUsers.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-10">새로운 가입 신청이 없습니다.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>이름</TableHead>
                      <TableHead>이메일/연락처</TableHead>
                      <TableHead>신청일</TableHead>
                      <TableHead className="text-right">작업</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {pendingUsers.map((user) => (
                      <TableRow key={user.id}>
                        <TableCell className="font-medium">{user.name}</TableCell>
                        <TableCell>
                          <div className="text-xs">{user.email}</div>
                          <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                            <Phone className="h-2 w-2" /> {user.phone || "미등록"}
                          </div>
                        </TableCell>
                        <TableCell className="text-xs">{formatDate(user.createdAt)}</TableCell>
                        <TableCell className="text-right flex justify-end gap-2">
                          <Button size="sm" variant="outline" className="h-8 text-green-600" onClick={() => handleUpdateStatus(user.id, "APPROVED")}>
                            <UserCheck className="h-4 w-4 mr-1" /> 승인
                          </Button>
                          <Button size="sm" variant="ghost" className="h-8 text-destructive" onClick={() => handleUpdateStatus(user.id, "REJECTED")}>
                            <UserX className="h-4 w-4 mr-1" /> 거절
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="approved">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">가입된 멤버</CardTitle>
              <CardDescription>현재 시스템을 이용 중인 멤버들입니다.</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>이름</TableHead>
                    <TableHead>역할/상태</TableHead>
                    <TableHead>가입일</TableHead>
                    <TableHead className="text-right">작업</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {approvedUsers.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell className="font-medium">
                        {user.name}
                        <div className="text-[10px] text-muted-foreground">{user.email}</div>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Badge variant={user.role === "OWNER" ? "default" : "secondary"} className="text-[10px]">
                            {user.role}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs">{formatDate(user.createdAt)}</TableCell>
                      <TableCell className="text-right">
                        {user.role !== "OWNER" && (
                          <Button size="sm" variant="ghost" className="h-8 text-destructive" onClick={() => handleEvict(user.id)}>
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
