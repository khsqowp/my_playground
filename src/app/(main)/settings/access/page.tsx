"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Plus, Shield } from "lucide-react";
import { toast } from "sonner";

interface UserItem {
  id: string;
  email: string;
  name: string;
  role: string;
  createdAt: string;
}

export default function AccessPage() {
  const [users, setUsers] = useState<UserItem[]>([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("USER");

  useEffect(() => {
    fetch("/api/settings?_users=true")
      .then((r) => r.json())
      .then((data) => { if (data.users) setUsers(data.users); })
      .catch(() => { });
  }, []);

  async function createUser() {
    if (!email || !name || !password) return;
    try {
      const res = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ _createUser: true, email, name, password, role }),
      });
      if (!res.ok) throw new Error();
      toast.success("사용자가 생성되었습니다");
      setDialogOpen(false);
      setEmail("");
      setName("");
      setPassword("");
      // Reload
      const data = await fetch("/api/settings?_users=true").then((r) => r.json());
      if (data.users) setUsers(data.users);
    } catch {
      toast.error("사용자 생성에 실패했습니다");
    }
  }

  const roleColor: Record<string, string> = {
    OWNER: "bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300",
    ADMIN: "bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300",
    USER: "bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300",
    GUEST: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">접근 관리</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button><Plus className="mr-2 h-4 w-4" />사용자 추가</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>사용자 생성</DialogTitle></DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2"><Label>이메일</Label><Input value={email} onChange={(e) => setEmail(e.target.value)} /></div>
              <div className="space-y-2"><Label>이름</Label><Input value={name} onChange={(e) => setName(e.target.value)} /></div>
              <div className="space-y-2"><Label>비밀번호</Label><Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
              <div className="space-y-2">
                <Label>역할</Label>
                <Select value={role} onValueChange={setRole}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ADMIN">관리자</SelectItem>
                    <SelectItem value="USER">사용자</SelectItem>
                    <SelectItem value="GUEST">게스트</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button onClick={createUser} className="w-full">생성</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="space-y-3">
        {users.map((user) => (
          <Card key={user.id}>
            <CardContent className="flex items-center justify-between p-4">
              <div className="flex items-center gap-3">
                <Shield className="h-5 w-5 text-muted-foreground" />
                <div>
                  <p className="font-medium">{user.name}</p>
                  <p className="text-sm text-muted-foreground">{user.email}</p>
                </div>
              </div>
              <Badge className={roleColor[user.role] || ""}>{user.role}</Badge>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
