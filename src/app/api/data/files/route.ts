import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import fs from "fs";
import path from "path";
import mime from "mime";
import { z } from "zod";
import { logger } from "@/lib/logger";

// OWASP A03: Injection Prevention via Zod Schema
const QuerySchema = z.object({
    action: z.enum(["list", "content", "download"]).optional(),
    path: z.string()
        .default("/")
        .refine((p) => !p.includes(".."), { message: "Path traversal detected" })
        .refine((p) => !p.includes("\0"), { message: "Null byte detected" })
        .refine((p) => /^[a-zA-Z0-9_\-\./]+$/.test(p), { message: "Invalid characters detected (Sanitization)" }),
});

// OWASP A01: Access Control - Block sensitive files/directories
const BLOCKED_FILES = [".env", ".git", ".next", "node_modules", "package-lock.json", "yarn.lock"];
const BLOCKED_EXTENSIONS = [".exe", ".sh", ".bat", ".cmd"];

function isPathAllowed(relativePath: string) {
    const basename = path.basename(relativePath);

    // Check for blocked files/dirs
    if (BLOCKED_FILES.some(blocked => relativePath.includes(blocked))) {
        return false;
    }

    // Check for blocked extensions
    if (BLOCKED_EXTENSIONS.some(ext => basename.toLowerCase().endsWith(ext))) {
        return false;
    }

    return true;
}

export async function GET(request: NextRequest) {
    const session = await auth();
    if (!session?.user) {
        logger.warn("Unauthorized access attempt to File Explorer", { ip: request.headers.get("x-forwarded-for") });
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const parseResult = QuerySchema.safeParse({
        action: searchParams.get("action") || undefined,
        path: searchParams.get("path") || "/",
    });

    if (!parseResult.success) {
        logger.warn(`Invalid input parameters: ${parseResult.error.message}`, { userId: session.user.id });
        return NextResponse.json({ error: "Invalid input parameters" }, { status: 400 });
    }

    const { action, path: relativePath } = parseResult.data;

    // OWASP A01: Broken Access Control - Enforce strict path validation
    if (!isPathAllowed(relativePath)) {
        logger.warn(`Access to blocked path attempted: ${relativePath}`, { userId: session.user.id });
        return NextResponse.json({ error: "Access denied: Restricted resource" }, { status: 403 });
    }

    const rootDir = process.cwd();
    const absolutePath = path.join(rootDir, relativePath);

    // Ensure path is strictly within rootDir
    if (!absolutePath.startsWith(rootDir)) {
        logger.warn(`Path traversal attempt blocked: ${relativePath}`, { userId: session.user.id });
        return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }

    if (action === "list" || !action) {
        try {
            if (!fs.existsSync(absolutePath)) {
                return NextResponse.json({ error: "Path not found" }, { status: 404 });
            }

            const stats = fs.statSync(absolutePath);
            if (!stats.isDirectory()) {
                return NextResponse.json({ error: "Not a directory" }, { status: 400 });
            }

            const items = fs.readdirSync(absolutePath).map((name) => {
                const itemPath = path.join(absolutePath, name);
                const itemRelativePath = path.join(relativePath, name);

                // Skip blocked items in listing
                if (!isPathAllowed(itemRelativePath)) return null;

                try {
                    const itemStats = fs.statSync(itemPath);
                    return {
                        name,
                        isDirectory: itemStats.isDirectory(),
                        size: itemStats.size,
                        updatedAt: itemStats.mtime,
                    };
                } catch (e) {
                    return null;
                }
            }).filter(Boolean);

            // Sort: Directories first, then files
            items.sort((a: any, b: any) => {
                if (a.isDirectory === b.isDirectory) return a.name.localeCompare(b.name);
                return a.isDirectory ? -1 : 1;
            });

            logger.info(`Directory listed: ${relativePath}`, { userId: session.user.id });
            return NextResponse.json({ items, currentPath: relativePath });
        } catch (e: any) {
            logger.error(`Failed to list directory: ${e.message}`, { userId: session.user.id, path: relativePath });
            return NextResponse.json({ error: "Failed to list directory" }, { status: 500 });
        }
    }

    if (action === "content") {
        try {
            if (!fs.existsSync(absolutePath)) return NextResponse.json({ error: "File not found" }, { status: 404 });

            const stats = fs.statSync(absolutePath);
            if (stats.isDirectory()) return NextResponse.json({ error: "Cannot read directory" }, { status: 400 });

            // Limit preview size to 2MB
            if (stats.size > 2 * 1024 * 1024) {
                return NextResponse.json({ error: "File too large to preview", size: stats.size }, { status: 413 });
            }

            const mimeType = mime.getType(absolutePath) || "";
            const isText = mimeType.startsWith("text/") || mimeType === "application/json" || relativePath.endsWith(".ts") || relativePath.endsWith(".tsx") || relativePath.endsWith(".md");

            if (isText || !mimeType) {
                const content = fs.readFileSync(absolutePath, "utf-8");
                logger.info(`File content viewed: ${relativePath}`, { userId: session.user.id });
                return NextResponse.json({ content, type: "text", mimeType });
            } else if (mimeType.startsWith("image/")) {
                const buffer = fs.readFileSync(absolutePath);
                const base64 = buffer.toString("base64");
                logger.info(`Image viewed: ${relativePath}`, { userId: session.user.id });
                return NextResponse.json({ content: `data:${mimeType};base64,${base64}`, type: "image", mimeType });
            } else {
                return NextResponse.json({ type: "binary", mimeType });
            }
        } catch (e: any) {
            logger.error(`Failed to read file: ${e.message}`, { userId: session.user.id, path: relativePath });
            return NextResponse.json({ error: "Failed to read file" }, { status: 500 });
        }
    }

    if (action === "download") {
        try {
            if (!fs.existsSync(absolutePath)) return NextResponse.json({ error: "File not found" }, { status: 404 });
            if (fs.statSync(absolutePath).isDirectory()) return NextResponse.json({ error: "Cannot download directory" }, { status: 400 });

            const buffer = fs.readFileSync(absolutePath);
            const mimeType = mime.getType(absolutePath) || "application/octet-stream";

            logger.info(`File downloaded: ${relativePath}`, { userId: session.user.id });

            return new NextResponse(buffer, {
                headers: {
                    "Content-Type": mimeType,
                    "Content-Disposition": `attachment; filename="${path.basename(absolutePath)}"`,
                }
            });
        } catch (e: any) {
            logger.error(`Failed to download file: ${e.message}`, { userId: session.user.id, path: relativePath });
            return NextResponse.json({ error: "Download failed" }, { status: 500 });
        }
    }

    return NextResponse.json({ error: "Invalid action" }, { status: 400 });
}
