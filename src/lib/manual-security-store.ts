import crypto from "crypto";
import prisma from "@/lib/prisma";

export const SECURITY_COLLECTIONS = {
  sessions: "security_manual_sessions",
  oob: "security_oob_callbacks",
  payloads: "security_payload_lab",
  archiveRules: "security_archive_rules",
  recon: "security_recon_notes",
} as const;

type CollectionName = (typeof SECURITY_COLLECTIONS)[keyof typeof SECURITY_COLLECTIONS];

const COLLECTION_DESCRIPTIONS: Record<CollectionName, string> = {
  [SECURITY_COLLECTIONS.sessions]: "Manual penetration testing sessions and scope records",
  [SECURITY_COLLECTIONS.oob]: "Out-of-band callback evidence for manual testing sessions",
  [SECURITY_COLLECTIONS.payloads]: "Reusable manual testing payloads and notes",
  [SECURITY_COLLECTIONS.archiveRules]: "Security archive classification rules",
  [SECURITY_COLLECTIONS.recon]: "Manual reconnaissance notes and observations",
};

export function nowIso() {
  return new Date().toISOString();
}

export function createToken(prefix: string) {
  return `${prefix}_${crypto.randomBytes(12).toString("hex")}`;
}

export async function ensureSecurityCollection(name: CollectionName) {
  return prisma.dataCollection.upsert({
    where: { name },
    update: {},
    create: {
      name,
      description: COLLECTION_DESCRIPTIONS[name],
      schema: {
        kind: "security-tooling",
        storage: "json",
      },
    },
  });
}

export async function createSecurityRecord<T extends Record<string, unknown>>(
  collectionName: CollectionName,
  data: T
) {
  const collection = await ensureSecurityCollection(collectionName);
  return prisma.dataRecord.create({
    data: {
      collectionId: collection.id,
      data: data as any,
    },
  });
}

export async function listSecurityRecords<T extends Record<string, unknown>>(
  collectionName: CollectionName,
  options: {
    take?: number;
    where?: (record: T, id: string) => boolean;
  } = {}
) {
  const collection = await ensureSecurityCollection(collectionName);
  const rows = await prisma.dataRecord.findMany({
    where: { collectionId: collection.id },
    orderBy: { createdAt: "desc" },
    take: options.where ? undefined : options.take,
  });

  const mapped = rows.map((row) => ({
    id: row.id,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    data: row.data as T,
  }));

  const filtered = options.where
    ? mapped.filter((row) => options.where?.(row.data, row.id))
    : mapped;

  return typeof options.take === "number" ? filtered.slice(0, options.take) : filtered;
}

export async function updateSecurityRecord<T extends Record<string, unknown>>(
  id: string,
  data: T
) {
  return prisma.dataRecord.update({
    where: { id },
    data: { data: data as any },
  });
}
