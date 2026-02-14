"use client";

import { useState, useRef, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { MarkdownRenderer } from "@/components/shared/MarkdownRenderer";
import { Bold, Italic, Heading, Code, Link, Image, List } from "lucide-react";

interface MarkdownEditorProps {
  value: string;
  onChange: (value: string) => void;
}

export function MarkdownEditor({ value, onChange }: MarkdownEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [tab, setTab] = useState("write");

  const insertText = useCallback(
    (before: string, after = "") => {
      const textarea = textareaRef.current;
      if (!textarea) return;

      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const selected = value.substring(start, end);
      const newText =
        value.substring(0, start) +
        before +
        selected +
        after +
        value.substring(end);
      onChange(newText);

      setTimeout(() => {
        textarea.focus();
        textarea.selectionStart = start + before.length;
        textarea.selectionEnd = start + before.length + selected.length;
      }, 0);
    },
    [value, onChange]
  );

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Tab") {
      e.preventDefault();
      insertText("  ");
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1 border-b pb-2">
        <Button type="button" variant="ghost" size="icon" className="h-8 w-8" onClick={() => insertText("**", "**")}>
          <Bold className="h-4 w-4" />
        </Button>
        <Button type="button" variant="ghost" size="icon" className="h-8 w-8" onClick={() => insertText("*", "*")}>
          <Italic className="h-4 w-4" />
        </Button>
        <Button type="button" variant="ghost" size="icon" className="h-8 w-8" onClick={() => insertText("## ")}>
          <Heading className="h-4 w-4" />
        </Button>
        <Button type="button" variant="ghost" size="icon" className="h-8 w-8" onClick={() => insertText("`", "`")}>
          <Code className="h-4 w-4" />
        </Button>
        <Button type="button" variant="ghost" size="icon" className="h-8 w-8" onClick={() => insertText("[", "](url)")}>
          <Link className="h-4 w-4" />
        </Button>
        <Button type="button" variant="ghost" size="icon" className="h-8 w-8" onClick={() => insertText("![alt](", ")")}>
          <Image className="h-4 w-4" />
        </Button>
        <Button type="button" variant="ghost" size="icon" className="h-8 w-8" onClick={() => insertText("- ")}>
          <List className="h-4 w-4" />
        </Button>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="write">작성</TabsTrigger>
          <TabsTrigger value="preview">미리보기</TabsTrigger>
          <TabsTrigger value="split">분할</TabsTrigger>
        </TabsList>

        <TabsContent value="write">
          <Textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="마크다운을 작성하세요..."
            className="min-h-[500px] font-mono text-sm"
          />
        </TabsContent>

        <TabsContent value="preview">
          <div className="min-h-[500px] rounded-md border p-4">
            <MarkdownRenderer content={value} />
          </div>
        </TabsContent>

        <TabsContent value="split">
          <div className="grid grid-cols-2 gap-4">
            <Textarea
              ref={textareaRef}
              value={value}
              onChange={(e) => onChange(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="마크다운을 작성하세요..."
              className="min-h-[500px] font-mono text-sm"
            />
            <div className="min-h-[500px] overflow-y-auto rounded-md border p-4">
              <MarkdownRenderer content={value} />
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
