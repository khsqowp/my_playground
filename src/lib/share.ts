import prisma from "@/lib/prisma";

export function generateShareToken(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 32; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

export async function validateShareLink(
  token: string
): Promise<{ valid: boolean; targetType: string; targetId: string } | null> {
  const link = await prisma.shareLink.findUnique({ where: { token } });

  if (!link || !link.active) return null;

  if (link.expiresAt && new Date() > link.expiresAt) {
    await prisma.shareLink.update({
      where: { id: link.id },
      data: { active: false },
    });
    return null;
  }

  if (link.maxAccess && link.accessCount >= link.maxAccess) {
    return null;
  }

  await prisma.shareLink.update({
    where: { id: link.id },
    data: { accessCount: { increment: 1 } },
  });

  return {
    valid: true,
    targetType: link.targetType,
    targetId: link.targetId,
  };
}
