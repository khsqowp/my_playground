import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import type { Prisma } from "@prisma/client";

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const formData = await request.formData();
  const file = formData.get("file") as File | null;
  const collectionId = formData.get("collectionId") as string;

  if (!file || !collectionId) {
    return NextResponse.json({ error: "File and collectionId required" }, { status: 400 });
  }

  try {
    const text = await file.text();
    let records: Record<string, unknown>[];

    if (file.name.endsWith(".json")) {
      records = JSON.parse(text);
      if (!Array.isArray(records)) records = [records];
    } else {
      // CSV parsing
      const lines = text.split("\n").filter((l) => l.trim());
      const headers = lines[0].split(",").map((h) => h.trim().replace(/^"|"$/g, ""));
      records = lines.slice(1).map((line) => {
        const values = line.split(",").map((v) => v.trim().replace(/^"|"$/g, ""));
        const record: Record<string, unknown> = {};
        headers.forEach((h, i) => { record[h] = values[i] || ""; });
        return record;
      });
    }

    const created = await prisma.dataRecord.createMany({
      data: records.map((data) => ({ collectionId, data: data as Prisma.InputJsonValue })),
    });

    return NextResponse.json({ imported: created.count });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Import failed";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
