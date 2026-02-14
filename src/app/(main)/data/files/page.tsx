"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Folder, File, FileText, Image as ImageIcon, Download, ChevronRight, CornerLeftUp, FileCode, Film, FileJson } from "lucide-react";
import { cn } from "@/lib/utils";

interface FileItem {
    name: string;
    isDirectory: boolean;
    size: number;
    updatedAt: string;
}

export default function FileExplorerPage() {
    const [currentPath, setCurrentPath] = useState("/");
    const [items, setItems] = useState<FileItem[]>([]);
    const [selectedFile, setSelectedFile] = useState<FileItem | null>(null);
    const [fileContent, setFileContent] = useState<string | null>(null);
    const [fileType, setFileType] = useState<string | null>(null); // 'text', 'image', 'binary', 'error', 'loading'
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        fetchItems(currentPath);
    }, [currentPath]);

    useEffect(() => {
        if (selectedFile && !selectedFile.isDirectory) {
            fetchContent(selectedFile.name);
        } else {
            setFileContent(null);
            setFileType(null);
        }
    }, [selectedFile]);

    async function fetchItems(path: string) {
        setLoading(true);
        setItems([]);
        try {
            const res = await fetch(`/api/data/files?action=list&path=${encodeURIComponent(path)}`);
            if (res.ok) {
                const data = await res.json();
                setItems(data.items || []);
            }
        } catch (e) {
            console.error("Failed to fetch items", e);
        } finally {
            setLoading(false);
        }
    }

    async function fetchContent(filename: string) {
        if (!filename) return;
        setFileType("loading");

        // Construct path carefully to avoid double slashes
        const filePath = currentPath === "/" ? `/${filename}` : `${currentPath}/${filename}`;

        try {
            const res = await fetch(`/api/data/files?action=content&path=${encodeURIComponent(filePath)}`);
            if (res.ok) {
                const data = await res.json();
                if (data.type === "image" || data.type === "text") {
                    setFileContent(data.content);
                    setFileType(data.type);
                } else {
                    setFileContent(null);
                    setFileType("binary");
                }
            } else {
                setFileType("error");
                setFileContent(null);
            }
        } catch (e) {
            console.error(e);
            setFileType("error");
        }
    }

    function handleNavigate(folderName: string) {
        const newPath = currentPath === "/" ? `/${folderName}` : `${currentPath}/${folderName}`;
        setCurrentPath(newPath);
        setSelectedFile(null);
    }

    function handleGoUp() {
        if (currentPath === "/") return;
        const parts = currentPath.split("/").filter(Boolean); // Remove empty strings
        parts.pop();
        const newPath = parts.length === 0 ? "/" : `/${parts.join("/")}`;
        setCurrentPath(newPath);
        setSelectedFile(null);
    }

    function getFileIcon(name: string) {
        const ext = name.split('.').pop()?.toLowerCase();

        if (["jpg", "jpeg", "png", "gif", "webp", "svg"].includes(ext || ""))
            return <ImageIcon className="h-4 w-4 text-blue-500" />;

        if (["mp4", "mkv", "avi", "mov", "webm"].includes(ext || ""))
            return <Film className="h-4 w-4 text-purple-500" />;

        if (["js", "ts", "tsx", "jsx", "css", "html", "py", "java", "c", "cpp"].includes(ext || ""))
            return <FileCode className="h-4 w-4 text-yellow-500" />;

        if (["json", "xml", "yaml", "yml"].includes(ext || ""))
            return <FileJson className="h-4 w-4 text-orange-500" />;

        if (["md", "txt", "log"].includes(ext || ""))
            return <FileText className="h-4 w-4 text-gray-500" />;

        return <File className="h-4 w-4 text-gray-400" />;
    }

    function getDownloadUrl() {
        if (!selectedFile) return "#";
        const filePath = currentPath === "/" ? `/${selectedFile.name}` : `${currentPath}/${selectedFile.name}`;
        return `/api/data/files?action=download&path=${encodeURIComponent(filePath)}`;
    }

    return (
        <div className="flex h-[calc(100vh-4rem)]">
            {/* File List / Tree */}
            <div className="w-80 border-r flex flex-col bg-muted/20">
                <div className="p-4 border-b flex items-center gap-2 bg-background shadow-sm z-10">
                    <Button
                        variant="ghost"
                        size="icon"
                        disabled={currentPath === "/"}
                        onClick={handleGoUp}
                        title="Go Up"
                    >
                        <CornerLeftUp className="h-4 w-4" />
                    </Button>
                    <div className="font-mono text-xs truncate flex-1 bg-muted px-2 py-1 rounded" title={currentPath}>
                        {currentPath}
                    </div>
                </div>

                <ScrollArea className="flex-1">
                    <div className="p-2 space-y-1">
                        {loading && <div className="text-center text-sm py-4 text-muted-foreground animate-pulse">로딩 중...</div>}

                        {!loading && items.map((item) => (
                            <Button
                                key={item.name}
                                variant={selectedFile?.name === item.name ? "secondary" : "ghost"}
                                className={cn(
                                    "w-full justify-start text-sm px-2 h-9",
                                    item.isDirectory && "font-semibold text-foreground"
                                )}
                                onClick={() => {
                                    if (item.isDirectory) handleNavigate(item.name);
                                    else setSelectedFile(item);
                                }}
                            >
                                {item.isDirectory ? (
                                    <Folder className="mr-2 h-4 w-4 text-yellow-500 fill-yellow-500 shrink-0" />
                                ) : (
                                    <span className="mr-2 shrink-0">{getFileIcon(item.name)}</span>
                                )}
                                <span className="truncate">{item.name}</span>
                                {item.isDirectory && <ChevronRight className="ml-auto h-3 w-3 opacity-30" />}
                            </Button>
                        ))}

                        {!loading && items.length === 0 && (
                            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground gap-2">
                                <Folder className="h-8 w-8 opacity-20" />
                                <span className="text-xs">폴더가 비어있습니다</span>
                            </div>
                        )}
                    </div>
                </ScrollArea>
            </div>

            {/* Preview Panel */}
            <div className="flex-1 flex flex-col overflow-hidden bg-background">
                {selectedFile ? (
                    <>
                        <div className="p-4 border-b flex items-center justify-between shadow-sm z-10 bg-background">
                            <div className="flex items-center gap-3 overflow-hidden">
                                {getFileIcon(selectedFile.name)}
                                <div className="flex flex-col overflow-hidden">
                                    <h2 className="font-bold truncate text-sm">{selectedFile.name}</h2>
                                    <span className="text-xs text-muted-foreground">
                                        {(selectedFile.size / 1024).toFixed(1)} KB • {new Date(selectedFile.updatedAt).toLocaleDateString()}
                                    </span>
                                </div>
                            </div>
                            <Button size="sm" variant="outline" asChild>
                                <a href={getDownloadUrl()} download>
                                    <Download className="h-4 w-4 mr-2" /> 다운로드
                                </a>
                            </Button>
                        </div>

                        <div className="flex-1 overflow-auto p-6 bg-muted/10 relative">
                            {fileType === "loading" && (
                                <div className="absolute inset-0 flex items-center justify-center bg-background/50 z-20">
                                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                                </div>
                            )}

                            {fileType === "text" && fileContent && (
                                <div className="bg-white dark:bg-zinc-950 border rounded-md shadow-sm overflow-hidden">
                                    <div className="bg-muted px-4 py-2 text-xs text-muted-foreground border-b flex justify-between">
                                        <span>Text Preview</span>
                                        <span>{fileContent.split('\n').length} lines</span>
                                    </div>
                                    <ScrollArea className="h-[calc(100vh-16rem)]">
                                        <pre className="p-4 text-xs font-mono whitespace-pre-wrap break-all leading-relaxed">
                                            {fileContent}
                                        </pre>
                                    </ScrollArea>
                                </div>
                            )}

                            {fileType === "image" && fileContent && (
                                <div className="flex justify-center items-center h-full bg-checkerboard rounded-lg border shadow-inner p-4">
                                    <img
                                        src={fileContent}
                                        alt={selectedFile.name}
                                        className="max-w-full max-h-full object-contain shadow-lg rounded"
                                    />
                                </div>
                            )}

                            {fileType === "binary" && (
                                <div className="flex flex-col items-center justify-center h-full text-muted-foreground gap-4">
                                    <div className="bg-muted p-6 rounded-full">
                                        <File className="h-12 w-12 opacity-50" />
                                    </div>
                                    <div className="text-center">
                                        <p className="font-medium">미리보기를 지원하지 않는 파일입니다</p>
                                        <p className="text-sm mt-1">다운로드하여 확인하세요</p>
                                    </div>
                                </div>
                            )}

                            {fileType === "error" && (
                                <div className="flex flex-col items-center justify-center h-full text-destructive gap-4">
                                    <div className="bg-destructive/10 p-6 rounded-full">
                                        <File className="h-12 w-12 opacity-50" />
                                    </div>
                                    <p className="font-medium">파일을 읽을 수 없습니다</p>
                                </div>
                            )}
                        </div>
                    </>
                ) : (
                    <div className="flex flex-col items-center justify-center h-full text-muted-foreground gap-6">
                        <div className="bg-muted/50 p-8 rounded-full">
                            <Folder className="h-16 w-16 opacity-20" />
                        </div>
                        <div className="text-center space-y-1">
                            <p className="text-lg font-medium">파일 탐색기</p>
                            <p className="text-sm">왼쪽 목록에서 파일이나 폴더를 선택하세요</p>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
