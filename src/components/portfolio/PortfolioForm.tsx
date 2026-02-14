"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { MarkdownEditor } from "@/components/blog/MarkdownEditor";
import { toast } from "sonner";
import { Loader2, Save, Trash2, Plus, X } from "lucide-react";

interface PortfolioFormProps {
    initialData?: any;
    isEditing?: boolean;
}

export function PortfolioForm({ initialData, isEditing = false }: PortfolioFormProps) {
    const router = useRouter();
    const [loading, setLoading] = useState(false);

    const [formData, setFormData] = useState({
        title: initialData?.title || "",
        description: initialData?.description || "",
        content: initialData?.content || "",
        coverImage: initialData?.coverImage || "",
        techStack: initialData?.techStack || "",
        published: initialData?.published || false,
        visibility: initialData?.visibility || "PRIVATE",
        images: initialData?.images || [], // [{url, caption}]
        links: initialData?.links || [],   // [{title, url, type}]
    });

    const handleChange = (field: string, value: any) => {
        setFormData((prev) => ({ ...prev, [field]: value }));
    };

    const handleImageAdd = () => {
        setFormData((prev) => ({
            ...prev,
            images: [...prev.images, { url: "", caption: "" }],
        }));
    };

    const handleImageChange = (index: number, field: string, value: string) => {
        const newImages = [...formData.images];
        newImages[index][field] = value;
        handleChange("images", newImages);
    };

    const handleImageRemove = (index: number) => {
        const newImages = [...formData.images];
        newImages.splice(index, 1);
        handleChange("images", newImages);
    };

    const handleLinkAdd = () => {
        setFormData((prev) => ({
            ...prev,
            links: [...prev.links, { title: "", url: "", type: "website" }],
        }));
    };

    const handleLinkChange = (index: number, field: string, value: string) => {
        const newLinks = [...formData.links];
        newLinks[index][field] = value;
        handleChange("links", newLinks);
    };

    const handleLinkRemove = (index: number) => {
        const newLinks = [...formData.links];
        newLinks.splice(index, 1);
        handleChange("links", newLinks);
    };

    const handleSubmit = async () => {
        if (!formData.title) {
            toast.error("제목을 입력해주세요");
            return;
        }

        setLoading(true);
        try {
            const url = isEditing ? `/api/portfolio/${initialData.id}` : "/api/portfolio";
            const method = isEditing ? "PUT" : "POST";

            const res = await fetch(url, {
                method,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(formData),
            });

            if (!res.ok) throw new Error();

            const data = await res.json();
            toast.success(isEditing ? "포트폴리오가 수정되었습니다" : "포트폴리오가 생성되었습니다");
            router.push("/manage/portfolio");
            router.refresh();
        } catch {
            toast.error("저장에 실패했습니다");
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async () => {
        if (!confirm("정말 삭제하시겠습니까?")) return;

        try {
            setLoading(true);
            await fetch(`/api/portfolio/${initialData.id}`, { method: "DELETE" });
            toast.success("포트폴리오가 삭제되었습니다");
            router.push("/manage/portfolio");
            router.refresh();
        } catch {
            toast.error("삭제에 실패했습니다");
            setLoading(false);
        }
    };

    return (
        <div className="grid gap-6 md:grid-cols-4">
            <div className="md:col-span-3 space-y-6">
                <div className="space-y-2">
                    <Label>제목</Label>
                    <Input
                        value={formData.title}
                        onChange={(e) => handleChange("title", e.target.value)}
                        placeholder="프로젝트 제목"
                        className="text-lg font-semibold"
                    />
                </div>

                <div className="space-y-2">
                    <Label>설명 (요약)</Label>
                    <Textarea
                        value={formData.description}
                        onChange={(e) => handleChange("description", e.target.value)}
                        placeholder="프로젝트에 대한 간단한 설명"
                        rows={3}
                    />
                </div>

                <div className="space-y-2">
                    <Label>상세 내용</Label>
                    <MarkdownEditor
                        value={formData.content}
                        onChange={(value) => handleChange("content", value)}
                    />
                </div>

                <div className="space-y-4 rounded-lg border p-4">
                    <div className="flex items-center justify-between">
                        <Label className="text-base">갤러리 이미지</Label>
                        <Button type="button" variant="outline" size="sm" onClick={handleImageAdd}>
                            <Plus className="mr-2 h-4 w-4" /> 추가
                        </Button>
                    </div>

                    {formData.images.map((img: any, index: number) => (
                        <div key={index} className="flex gap-2 items-start p-2 border rounded bg-muted/20">
                            <div className="grid gap-2 flex-1">
                                <Input
                                    value={img.url}
                                    onChange={(e) => handleImageChange(index, "url", e.target.value)}
                                    placeholder="이미지 URL"
                                />
                                <Input
                                    value={img.caption}
                                    onChange={(e) => handleImageChange(index, "caption", e.target.value)}
                                    placeholder="이미지 설명 (캡션)"
                                />
                            </div>
                            <Button type="button" variant="ghost" size="icon" onClick={() => handleImageRemove(index)}>
                                <X className="h-4 w-4" />
                            </Button>
                        </div>
                    ))}
                    {formData.images.length === 0 && (
                        <p className="text-sm text-muted-foreground text-center py-2">이미지가 없습니다</p>
                    )}
                </div>
            </div>

            <div className="space-y-6">
                <div className="space-y-4 rounded-lg border p-4">
                    <div className="space-y-2">
                        <Label>공개 설정</Label>
                        <div className="flex items-center justify-between">
                            <span className="text-sm">발행됨</span>
                            <Switch
                                checked={formData.published}
                                onCheckedChange={(checked) => handleChange("published", checked)}
                            />
                        </div>
                    </div>

                    <div className="space-y-2">
                        <Label>공개 범위</Label>
                        <Select
                            value={formData.visibility}
                            onValueChange={(value) => handleChange("visibility", value)}
                        >
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="PRIVATE">비공개</SelectItem>
                                <SelectItem value="PUBLIC">공개</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>

                    <Button onClick={handleSubmit} disabled={loading} className="w-full">
                        {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                        {isEditing ? "수정사항 저장" : "작성하기"}
                    </Button>

                    {isEditing && (
                        <Button variant="destructive" onClick={handleDelete} className="w-full">
                            <Trash2 className="mr-2 h-4 w-4" /> 삭제
                        </Button>
                    )}
                </div>

                <div className="space-y-2">
                    <Label>커버 이미지 URL</Label>
                    <Input
                        value={formData.coverImage}
                        onChange={(e) => handleChange("coverImage", e.target.value)}
                        placeholder="https://..."
                    />
                    {formData.coverImage && (
                        <div className="aspect-video rounded-md overflow-hidden border bg-muted">
                            <img src={formData.coverImage} alt="Cover" className="h-full w-full object-cover" />
                        </div>
                    )}
                </div>

                <div className="space-y-2">
                    <Label>기술 스택 (쉼표로 구분)</Label>
                    <Input
                        value={formData.techStack}
                        onChange={(e) => handleChange("techStack", e.target.value)}
                        placeholder="React, Next.js, Typescript..."
                    />
                </div>

                <div className="space-y-4 rounded-lg border p-4">
                    <div className="flex items-center justify-between">
                        <Label>관련 링크</Label>
                        <Button type="button" variant="outline" size="sm" onClick={handleLinkAdd}>
                            <Plus className="h-4 w-4" />
                        </Button>
                    </div>

                    {formData.links.map((link: any, index: number) => (
                        <div key={index} className="space-y-2 p-2 border rounded bg-muted/20">
                            <div className="flex items-center justify-between">
                                <span className="text-xs font-medium">링크 #{index + 1}</span>
                                <Button type="button" variant="ghost" size="icon" className="h-6 w-6" onClick={() => handleLinkRemove(index)}>
                                    <X className="h-3 w-3" />
                                </Button>
                            </div>
                            <Input
                                value={link.title}
                                onChange={(e) => handleLinkChange(index, "title", e.target.value)}
                                placeholder="제목 (예: GitHub)"
                                className="h-8 text-sm"
                            />
                            <Input
                                value={link.url}
                                onChange={(e) => handleLinkChange(index, "url", e.target.value)}
                                placeholder="URL"
                                className="h-8 text-sm"
                            />
                            <Select
                                value={link.type}
                                onValueChange={(value) => handleLinkChange(index, "type", value)}
                            >
                                <SelectTrigger className="h-8 text-sm"><SelectValue /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="website">웹사이트</SelectItem>
                                    <SelectItem value="github">GitHub</SelectItem>
                                    <SelectItem value="demo">데모</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    ))}
                    {formData.links.length === 0 && (
                        <p className="text-sm text-muted-foreground text-center py-2">링크가 없습니다</p>
                    )}
                </div>
            </div>
        </div>
    );
}
