"use client";

import { useEffect, useState } from "react";
import { PortfolioForm } from "@/components/portfolio/PortfolioForm";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { toast } from "sonner";

export default function PortfolioEditPage() {
    const params = useParams();
    const id = params.id as string;
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch(`/api/portfolio/${id}`)
            .then((res) => {
                if (!res.ok) throw new Error();
                return res.json();
            })
            .then((data) => {
                setData(data);
            })
            .catch(() => {
                toast.error("포트폴리오 정보를 불러오는데 실패했습니다");
            })
            .finally(() => {
                setLoading(false);
            });
    }, [id]);

    if (loading) {
        return <div className="flex h-40 items-center justify-center">Loading...</div>;
    }

    if (!data) {
        return <div className="flex h-40 items-center justify-center">포트폴리오를 찾을 수 없습니다</div>;
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" asChild>
                    <Link href="/manage/portfolio">
                        <ArrowLeft className="h-4 w-4" />
                    </Link>
                </Button>
                <h1 className="text-2xl font-bold">포트폴리오 수정</h1>
            </div>

            <PortfolioForm initialData={data} isEditing={true} />
        </div>
    );
}
