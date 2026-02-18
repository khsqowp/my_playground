import { NextRequest } from "next/server";
import prisma from "@/lib/prisma";

export function isServiceRequest(request: NextRequest): boolean {
  const key = request.headers.get("x-service-key");
  const configured = process.env.SERVICE_API_KEY;
  if (!configured || !key) return false;
  return key === configured;
}

let cachedOwnerAuthorId: string | null = null;

export async function getServiceAuthorId(): Promise<string | null> {
  if (cachedOwnerAuthorId) return cachedOwnerAuthorId;
  const owner = await prisma.user.findFirst({ where: { role: "OWNER" } });
  if (owner) cachedOwnerAuthorId = owner.id;
  return cachedOwnerAuthorId;
}
