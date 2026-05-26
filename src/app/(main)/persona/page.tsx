"use client";

import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Bot, Folder, Send, User, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";

interface Message {
  role: "user" | "assistant";
  content: string;
}

export default function PersonaPage() {
  const [messages, setMessages] = useState<Message[]>([
    { role: "assistant", content: "안녕하세요! 김한수 님의 페르소나 AI 비서입니다. 무엇을 도와드릴까요?" }
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [projects, setProjects] = useState<string[]>([]);
  const [project, setProject] = useState("inbox");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  useEffect(() => {
    fetch("/api/rag/files?action=projects")
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "프로젝트 목록 조회 실패");
        setProjects(data.projects || []);
        const defaultProject = data.defaultProject || "inbox";
        setProject((prev) => (data.projects || []).includes(prev) ? prev : defaultProject);
      })
      .catch(() => {
        setProjects(["inbox"]);
      });
  }, []);

  const handleProjectChange = (nextProject: string) => {
    setProject(nextProject);
    setMessages([
      {
        role: "assistant",
        content: `"${nextProject}" 프로젝트 문서를 기준으로 답변합니다.`,
      },
    ]);
  };

  const onSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMsg = input.trim();
    setInput("");
    setMessages(prev => [...prev, { role: "user", content: userMsg }]);
    setIsLoading(true);

    try {
      const res = await fetch("/api/persona/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userMsg,
          project,
          history: messages.slice(-6),
        }),
      });

      if (!res.ok) throw new Error("대화 중 오류가 발생했습니다.");

      const data = await res.json();
      setMessages(prev => [...prev, { role: "assistant", content: data.response }]);
    } catch (error: any) {
      setMessages(prev => [...prev, { role: "assistant", content: "⚠️ 오류가 발생했습니다: " + error.message }]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] max-w-4xl mx-auto">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">페르소나 AI 채팅</h1>
        </div>
        <label className="flex items-center gap-2 rounded-md border bg-background px-3 py-2 text-sm">
          <Folder className="h-4 w-4 text-muted-foreground" />
          <select
            value={project}
            onChange={(event) => handleProjectChange(event.target.value)}
            className="bg-transparent outline-none"
          >
            {projects.length === 0 ? (
              <option value={project}>{project}</option>
            ) : (
              projects.map((name) => <option key={name} value={name}>{name}</option>)
            )}
          </select>
        </label>
      </div>

      <Card className="flex-1 flex flex-col p-4 mb-4 overflow-hidden bg-background/50 backdrop-blur">
        <ScrollArea className="flex-1 pr-4" ref={scrollRef}>
          <div className="space-y-4">
            {messages.map((m, i) => (
              <div key={i} className={cn("flex gap-3", m.role === "user" ? "justify-end" : "justify-start")}>
                {m.role === "assistant" && (
                  <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center">
                    <Bot className="h-5 w-5 text-primary" />
                  </div>
                )}
                <div className={cn(
                  "max-w-[80%] rounded-lg p-3 text-sm",
                  m.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted"
                )}>
                  {m.content}
                </div>
                {m.role === "user" && (
                  <div className="h-8 w-8 rounded-full bg-muted flex items-center justify-center">
                    <User className="h-5 w-5" />
                  </div>
                )}
              </div>
            ))}
            {isLoading && (
              <div className="flex gap-3 justify-start">
                <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center animate-pulse">
                  <Bot className="h-5 w-5 text-primary" />
                </div>
                <div className="bg-muted rounded-lg p-3 text-sm animate-pulse">
                  답변을 생각 중입니다...
                </div>
              </div>
            )}
          </div>
        </ScrollArea>

        <div className="flex gap-2 mt-4 pt-4 border-t">
          <Input
            placeholder="학습 내용이나 프로젝트에 대해 물어보세요..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && onSend()}
          />
          <Button onClick={onSend} disabled={isLoading}>
            <Send className="h-4 w-4" />
          </Button>
        </div>
      </Card>
      <p className="text-xs text-muted-foreground text-center">
        이 AI는 사용자님의 노트를 기반으로 답변합니다. 정보가 부족할 경우 실제와 다를 수 있습니다.
      </p>
    </div>
  );
}
