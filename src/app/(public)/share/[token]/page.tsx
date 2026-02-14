"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { MarkdownRenderer } from "@/components/shared/MarkdownRenderer";
import { Lock, AlertCircle } from "lucide-react";

export default function SharePage() {
  const params = useParams();
  const token = params.token as string;

  const [content, setContent] = useState<{ type: string; content: Record<string, unknown> } | null>(null);
  const [error, setError] = useState("");
  const [needsPassword, setNeedsPassword] = useState(false);
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(true);

  async function loadContent(pwd?: string) {
    setLoading(true);
    const url = pwd
      ? `/api/share/${token}?password=${encodeURIComponent(pwd)}`
      : `/api/share/${token}`;

    const res = await fetch(url);
    const data = await res.json();

    if (data.needsPassword) {
      setNeedsPassword(true);
    } else if (data.error) {
      setError(data.error);
    } else {
      setContent(data);
    }
    setLoading(false);
  }

  useEffect(() => { loadContent(); }, [token]);

  if (loading) return <div className="flex min-h-screen items-center justify-center">Loading...</div>;

  if (needsPassword) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <Lock className="mx-auto h-8 w-8 mb-2" />
            <CardTitle>Password Required</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Input
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && loadContent(password)}
            />
            <Button onClick={() => loadContent(password)} className="w-full">Access</Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md text-center">
          <CardContent className="pt-6">
            <AlertCircle className="mx-auto h-12 w-12 text-destructive mb-4" />
            <p className="text-lg font-medium">{error}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!content) return null;

  const c = content.content as Record<string, string>;

  return (
    <div className="min-h-screen bg-background p-4 md:p-8">
      <div className="mx-auto max-w-4xl">
        <Card>
          <CardHeader>
            <CardTitle>{c.title || "Shared Content"}</CardTitle>
          </CardHeader>
          <CardContent>
            {c.content && (
              <article className="prose prose-neutral dark:prose-invert max-w-none">
                <MarkdownRenderer content={c.content} />
              </article>
            )}
            {content.type === "QUIZSET" && (
              <p className="text-muted-foreground">Quiz shared content - view in app for interactive mode.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
