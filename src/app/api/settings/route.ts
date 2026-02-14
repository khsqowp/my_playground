import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import bcrypt from "bcryptjs";

export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = request.nextUrl;

  // Return categories for selects
  if (searchParams.has("_categories") || searchParams.get("_categories") === "true") {
    const categories = await prisma.category.findMany();
    return NextResponse.json({ categories });
  }

  // Return collections
  if (searchParams.has("_collections")) {
    const collections = await prisma.dataCollection.findMany({
      include: { _count: { select: { records: true } } },
    });
    return NextResponse.json({ collections });
  }

  // Return system settings
  const settings = await prisma.systemSetting.findMany();
  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { id: true, email: true, name: true, role: true },
  });

  return NextResponse.json({ settings, user });
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json();

  // Create collection
  if (body._createCollection) {
    const collection = await prisma.dataCollection.create({
      data: {
        name: body.name,
        description: body.description || null,
        schema: body.schema,
      },
    });
    return NextResponse.json(collection, { status: 201 });
  }

  // Update profile
  if (body._updateProfile) {
    const data: Record<string, string> = {};
    if (body.name) data.name = body.name;
    if (body.email) data.email = body.email;
    if (body.password) data.password = await bcrypt.hash(body.password, 12);

    const user = await prisma.user.update({
      where: { id: session.user.id },
      data,
      select: { id: true, email: true, name: true, role: true },
    });
    return NextResponse.json(user);
  }

  // Update system settings (OWNER only)
  if (body._updateSettings && session.user.role === "OWNER") {
    for (const [key, value] of Object.entries(body.settings as Record<string, string>)) {
      await prisma.systemSetting.upsert({
        where: { key },
        update: { value },
        create: { key, value },
      });
    }
    return NextResponse.json({ success: true });
  }

  return NextResponse.json({ error: "Invalid request" }, { status: 400 });
}
