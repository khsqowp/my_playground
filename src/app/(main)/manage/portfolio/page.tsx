export const dynamic = "force-dynamic";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Plus } from "lucide-react";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { PortfolioCard } from "@/components/portfolio/PortfolioCard";

export default async function PortfolioPage() {
    const session = await auth();
    if (!session?.user?.id) return null;

    const portfolios = await prisma.portfolio.findMany({
        where: {
            authorId: session.user.id,
        },
        orderBy: {
            createdAt: "desc",
        },
    });

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-2xl font-bold">포트폴리오 관리 ({portfolios.length})</h1>
                <Button asChild>
                    <Link href="/portfolio/write">
                        <Plus className="mr-2 h-4 w-4" />
                        새 포트폴리오
                    </Link>
                </Button>
            </div>

            <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                {portfolios.map((item) => (
                    <PortfolioCard
                        key={item.id}
                        portfolio={{
                            ...item,
                            createdAt: item.createdAt.toISOString(),
                        }}
                        basePath="/portfolio/edit"
                    />
                ))}
            </div>
        </div>
    );
}
