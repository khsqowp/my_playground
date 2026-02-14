import { useState, useCallback } from "react";

interface Memo {
  id: string;
  content: string;
  categoryTag: string | null;
  pinned: boolean;
  createdAt: string;
}

export function useMemos() {
  const [memos, setMemos] = useState<Memo[]>([]);
  const [loading, setLoading] = useState(false);

  const loadMemos = useCallback(async (search?: string) => {
    setLoading(true);
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    const res = await fetch(`/api/data/memo?${params}`);
    const data = await res.json();
    setMemos(data.memos || []);
    setLoading(false);
  }, []);

  const createMemo = useCallback(async (content: string, categoryTag?: string) => {
    const res = await fetch("/api/data/memo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, categoryTag }),
    });
    if (res.ok) await loadMemos();
    return res.ok;
  }, [loadMemos]);

  const togglePin = useCallback(async (id: string, pinned: boolean) => {
    await fetch("/api/data/memo", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, pinned: !pinned }),
    });
    await loadMemos();
  }, [loadMemos]);

  const deleteMemo = useCallback(async (id: string) => {
    await fetch("/api/data/memo", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    await loadMemos();
  }, [loadMemos]);

  return { memos, loading, loadMemos, createMemo, togglePin, deleteMemo };
}
