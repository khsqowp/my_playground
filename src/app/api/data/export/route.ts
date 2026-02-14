import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = request.nextUrl;
  const collectionId = searchParams.get("collectionId");
  const format = searchParams.get("format") || "json";

  if (!collectionId) return NextResponse.json({ error: "collectionId required" }, { status: 400 });

  const records = await prisma.dataRecord.findMany({
    where: { collectionId },
    orderBy: { createdAt: "asc" },
  });

  const data = records.map((r) => r.data as Record<string, unknown>);

  if (format === "csv") {
    if (data.length === 0) {
      return new NextResponse("", { headers: { "Content-Type": "text/csv" } });
    }
    const headers = Object.keys(data[0]);
    const csv = [
      headers.join(","),
      ...data.map((row) => headers.map((h) => `"${String(row[h] ?? "").replace(/"/g, '""')}"`).join(",")),
    ].join("\n");

    return new NextResponse(csv, {
      headers: {
        "Content-Type": "text/csv",
        "Content-Disposition": `attachment; filename="export.csv"`,
      },
    });
  }

  return NextResponse.json(data);
}
