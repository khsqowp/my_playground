'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Save, Pin, Trash2, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { format } from 'date-fns';

interface Memo {
  id: string;
  content: string;
  pinned: boolean;
  createdAt: string;
  updatedAt: string;
}

export function QuickMemo() {
  const [content, setContent] = useState('');
  const [memos, setMemos] = useState<Memo[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isFetching, setIsFetching] = useState(true);

  // Fetch recent memos on mount
  useEffect(() => {
    fetchMemos();
  }, []);

  const fetchMemos = async () => {
    try {
      setIsFetching(true);
      const response = await fetch('/api/data/memo?limit=5');
      if (!response.ok) throw new Error('Failed to fetch memos');
      const data = await response.json();
      setMemos(data.memos || []);
    } catch (error) {
      console.error('Failed to fetch memos:', error);
      toast.error('메모를 불러오지 못했습니다');
    } finally {
      setIsFetching(false);
    }
  };

  const handleSave = async () => {
    if (!content.trim()) {
      toast.error('메모 내용을 입력해주세요');
      return;
    }

    try {
      setIsLoading(true);
      const response = await fetch('/api/data/memo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: content.trim() }),
      });

      if (!response.ok) throw new Error('Failed to save memo');

      const data = await response.json();
      setMemos((prev) => [data.memo, ...prev]);
      setContent('');
      toast.success('메모가 저장되었습니다!');
    } catch (error) {
      console.error('Failed to save memo:', error);
      toast.error('메모 저장에 실패했습니다');
    } finally {
      setIsLoading(false);
    }
  };

  const handleTogglePin = async (memoId: string, currentPinned: boolean) => {
    try {
      const response = await fetch(`/api/data/memo/${memoId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pinned: !currentPinned }),
      });

      if (!response.ok) throw new Error('Failed to update memo');

      const data = await response.json();
      setMemos((prev) =>
        prev
          .map((m) => (m.id === memoId ? data.memo : m))
          .sort((a, b) => {
            if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
            return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
          })
      );
      toast.success(data.memo.pinned ? '메모가 고정되었습니다' : '메모 고정이 해제되었습니다');
    } catch (error) {
      console.error('Failed to toggle pin:', error);
      toast.error('메모 업데이트에 실패했습니다');
    }
  };

  const handleDelete = async (memoId: string) => {
    try {
      const response = await fetch(`/api/data/memo/${memoId}`, {
        method: 'DELETE',
      });

      if (!response.ok) throw new Error('Failed to delete memo');

      setMemos((prev) => prev.filter((m) => m.id !== memoId));
      toast.success('메모가 삭제되었습니다');
    } catch (error) {
      console.error('Failed to delete memo:', error);
      toast.error('메모 삭제에 실패했습니다');
    }
  };

  return (
    <Card className="h-full flex flex-col">
      <CardHeader>
        <CardTitle className="text-lg font-semibold">빠른 메모</CardTitle>
      </CardHeader>
      <CardContent className="flex-1 flex flex-col space-y-4">
        {/* Input Section */}
        <div className="space-y-2">
          <Textarea
            placeholder="빠른 메모를 작성하세요..."
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="min-h-[80px] resize-none"
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                handleSave();
              }
            }}
          />
          <Button
            onClick={handleSave}
            disabled={isLoading || !content.trim()}
            className="w-full"
            size="sm"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                저장 중...
              </>
            ) : (
              <>
                <Save className="w-4 h-4 mr-2" />
                메모 저장
              </>
            )}
          </Button>
        </div>

        {/* Recent Memos */}
        <div className="flex-1">
          <h3 className="text-sm font-medium mb-2 text-muted-foreground">최근 메모</h3>
          {isFetching ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : memos.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">메모가 없습니다</p>
          ) : (
            <ScrollArea className="h-[200px]">
              <div className="space-y-2">
                {memos.map((memo) => (
                  <div
                    key={memo.id}
                    className="p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors group"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-sm flex-1 line-clamp-2">{memo.content}</p>
                      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7"
                          onClick={() => handleTogglePin(memo.id, memo.pinned)}
                        >
                          <Pin
                            className={`w-3.5 h-3.5 ${memo.pinned ? 'fill-current text-primary' : ''}`}
                          />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7 text-destructive"
                          onClick={() => handleDelete(memo.id)}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 mt-2">
                      {memo.pinned && (
                        <span className="text-xs px-1.5 py-0.5 rounded bg-primary/10 text-primary">
                          고정됨
                        </span>
                      )}
                      <span className="text-xs text-muted-foreground">
                        {format(new Date(memo.createdAt), 'MMM d, h:mm a')}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
