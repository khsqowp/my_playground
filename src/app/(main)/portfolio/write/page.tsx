"use client";

import { PortfolioForm } from "@/components/portfolio/PortfolioForm";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";

export default function PortfolioWritePage() {
    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" asChild>
                    <Link href="/manage/portfolio">
                        <ArrowLeft className="h-4 w-4" />
                    </Link>
                </Button>
                <h1 className="text-2xl font-bold">새 포트폴리오 작성</h1>
            </div>

            <PortfolioForm />
        </div>
    );
}
