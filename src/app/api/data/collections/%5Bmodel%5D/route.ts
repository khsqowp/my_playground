import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

export async function GET(
    request: NextRequest,
    { params }: { params: Promise<any> }
) {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const modelName = (await params).model;
    // Lowercase the first letter to match prisma client convention (e.g. User -> user, Post -> post)
    // But wait, prisma client properties are usually camelCase. Model names in schema are PascalCase.
    // We need to find the correct property name in prisma client.
    // Usually it is camelCase of model name.

    const prismaClient: any = prisma;
    const modelKey = modelName.charAt(0).toLowerCase() + modelName.slice(1);

    if (!prismaClient[modelKey]) {
        return NextResponse.json({ error: `Model ${modelName} not found` }, { status: 404 });
    }

    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get("page") || "1");
    const limit = parseInt(searchParams.get("limit") || "20");
    const skip = (page - 1) * limit;

    try {
        const [data, total] = await Promise.all([
            prismaClient[modelKey].findMany({
                skip,
                take: limit,
                orderBy: { createdAt: "desc" }, // Assume createdAt exists, if not, might fail. 
                // Better to check metadata or catch error and retry without orderBy
            }),
            prismaClient[modelKey].count(),
        ]);

        return NextResponse.json({
            data,
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit),
        });
    } catch (error) {
        // Retry without orderBy if it failed (e.g. model doesn't have createdAt)
        try {
            const [data, total] = await Promise.all([
                prismaClient[modelKey].findMany({
                    skip,
                    take: limit,
                }),
                prismaClient[modelKey].count(),
            ]);
            return NextResponse.json({
                data,
                total,
                page,
                limit,
                totalPages: Math.ceil(total / limit),
            });
        } catch (retryError) {
            console.error(`Failed to fetch data for model ${modelName}`, retryError);
            return NextResponse.json({ error: "Failed to fetch data" }, { status: 500 });
        }
    }
}
