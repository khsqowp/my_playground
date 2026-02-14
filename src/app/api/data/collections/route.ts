import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import fs from "fs";
import path from "path";

export async function GET() {
    const session = await auth();
    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    // Add admin check if needed: if (session.user.role !== 'ADMIN') ...

    try {
        const schemaPath = path.join(process.cwd(), "prisma", "schema.prisma");
        const schemaContent = fs.readFileSync(schemaPath, "utf-8");

        // Extract model names using regex
        const modelRegex = /model\s+(\w+)\s+{/g;
        const models = [];
        let match;

        while ((match = modelRegex.exec(schemaContent)) !== null) {
            models.push(match[1]);
        }

        return NextResponse.json(models);
    } catch (error) {
        console.error("Failed to parse schema.prisma", error);
        return NextResponse.json({ error: "Failed to load models" }, { status: 500 });
    }
}
