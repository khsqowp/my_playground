import { RagFileArchive } from "@/components/archive/RagFileArchive";

export default async function ArchiveFilesPage({
  searchParams,
}: {
  searchParams: Promise<{ project?: string }>;
}) {
  const params = await searchParams;

  return (
    <RagFileArchive
      title="파일 아카이브"
      managerHref="/archive/files/manage"
      initialProject={params.project}
    />
  );
}
