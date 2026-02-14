export const dynamic = "force-dynamic";

import Link from "next/link";
import { PortfolioCard } from "@/components/portfolio/PortfolioCard";
import prisma from "@/lib/prisma";

export default async function PublicPortfolioPage() {
    const portfolios = await prisma.portfolio.findMany({
        where: {
            published: true,
            visibility: "PUBLIC",
        },
        orderBy: [
            { sortOrder: "asc" },
            { createdAt: "desc" },
        ],
    });

    return (
        <div className="space-y-8">
            <div className="flex flex-col gap-4">
                <h1 className="text-3xl font-bold tracking-tight">포트폴리오</h1>
                <p className="text-muted-foreground">
                    진행한 프로젝트와 작업물 모음
                </p>
            </div>

            {portfolios.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                    <p className="text-lg font-medium">등록된 포트폴리오가 없습니다</p>
                </div>
            ) : (
                <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                    {portfolios.map((item) => (
                        <PortfolioCard
                            key={item.id}
                            portfolio={{
                                ...item,
                                createdAt: item.createdAt.toISOString(),
                            }}
                            basePath="/portfolio"
                        />
                    ))}
                </div>
            )}
        </div>
    );
}
