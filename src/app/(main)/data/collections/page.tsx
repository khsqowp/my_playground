"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Database, Table as TableIcon, RefreshCw, ChevronLeft, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

export default function DBExplorerPage() {
    const [models, setModels] = useState<string[]>([]);
    const [selectedModel, setSelectedModel] = useState<string | null>(null);
    const [data, setData] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [columns, setColumns] = useState<string[]>([]);

    useEffect(() => {
        fetchModels();
    }, []);

    useEffect(() => {
        if (selectedModel) {
            fetchData(1);
        }
    }, [selectedModel]);

    async function fetchModels() {
        try {
            const res = await fetch("/api/data/collections");
            if (res.ok) {
                const list = await res.json();
                setModels(list);
            }
        } catch (e) {
            console.error("Failed to fetch models", e);
        }
    }

    async function fetchData(p: number) {
        if (!selectedModel) return;
        setLoading(true);
        try {
            const res = await fetch(`/api/data/collections/${selectedModel}?page=${p}&limit=20`);
            if (res.ok) {
                const result = await res.json();
                setData(result.data || []);

                // Calculate columns from first row if available, otherwise empty
                if (result.data && result.data.length > 0) {
                    setColumns(Object.keys(result.data[0]));
                } else {
                    setColumns([]);
                }

                setPage(result.page || 1);
                setTotalPages(result.totalPages || 1);
            } else {
                setData([]);
                setColumns([]);
            }
        } catch (e) {
            console.error("Failed to fetch data", e);
            setData([]);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="flex h-[calc(100vh-4rem)]">
            {/* Sidebar */}
            <div className="w-64 border-r bg-muted/20 flex flex-col">
                <div className="p-4 border-b flex items-center gap-2 font-semibold">
                    <Database className="h-5 w-5" /> 데이터베이스
                </div>
                <ScrollArea className="flex-1">
                    <div className="p-2 space-y-1">
                        {models.map((model) => (
                            <Button
                                key={model}
                                variant={selectedModel === model ? "secondary" : "ghost"}
                                className="w-full justify-start overflow-hidden text-ellipsis whitespace-nowrap"
                                onClick={() => setSelectedModel(model)}
                            >
                                <TableIcon className="mr-2 h-4 w-4 shrink-0" />
                                {model}
                            </Button>
                        ))}
                    </div>
                </ScrollArea>
            </div>

            {/* Main Content */}
            <div className="flex-1 flex flex-col overflow-hidden">
                {selectedModel ? (
                    <>
                        <div className="p-4 border-b flex items-center justify-between bg-background">
                            <h2 className="text-lg font-bold flex items-center gap-2">
                                <TableIcon className="h-5 w-5" /> {selectedModel}
                            </h2>
                            <div className="flex items-center gap-2">
                                <Button variant="outline" size="sm" onClick={() => fetchData(page)} disabled={loading}>
                                    <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
                                </Button>
                                <div className="flex items-center gap-1 border rounded-md p-1">
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-7 w-7"
                                        disabled={page <= 1 || loading}
                                        onClick={() => fetchData(page - 1)}
                                    >
                                        <ChevronLeft className="h-4 w-4" />
                                    </Button>
                                    <span className="text-sm px-2 min-w-[3rem] text-center">
                                        {page} / {totalPages}
                                    </span>
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-7 w-7"
                                        disabled={page >= totalPages || loading}
                                        onClick={() => fetchData(page + 1)}
                                    >
                                        <ChevronRight className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>
                        </div>

                        <div className="flex-1 overflow-auto p-4">
                            {loading ? (
                                <div className="h-full flex items-center justify-center text-muted-foreground">로딩 중...</div>
                            ) : data.length === 0 ? (
                                <div className="h-full flex items-center justify-center text-muted-foreground">데이터가 없습니다</div>
                            ) : (
                                <div className="border rounded-md">
                                    <Table>
                                        <TableHeader>
                                            <TableRow>
                                                {columns.map((col) => (
                                                    <TableHead key={col} className="whitespace-nowrap px-4 py-2 bg-muted/50 font-medium">
                                                        {col}
                                                    </TableHead>
                                                ))}
                                            </TableRow>
                                        </TableHeader>
                                        <TableBody>
                                            {data.map((row, i) => (
                                                <TableRow key={i}>
                                                    {columns.map((col) => (
                                                        <TableCell key={`${i}-${col}`} className="px-4 py-2 max-w-[300px] truncate">
                                                            {/* Handle objects and long text */}
                                                            {typeof row[col] === "object" && row[col] !== null
                                                                ? JSON.stringify(row[col])
                                                                : String(row[col] ?? "")}
                                                        </TableCell>
                                                    ))}
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </div>
                            )}
                        </div>
                    </>
                ) : (
                    <div className="h-full flex items-center justify-center text-muted-foreground">
                        왼쪽에서 테이블을 선택하세요
                    </div>
                )}
            </div>
        </div>
    );
}
