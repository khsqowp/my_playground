export interface MemoData {
  id: string;
  content: string;
  categoryTag: string | null;
  pinned: boolean;
  authorId: string;
  createdAt: string;
  updatedAt: string;
}

export interface DataCollectionData {
  id: string;
  name: string;
  description: string | null;
  schema: DataFieldSchema[];
  _count?: { records: number };
  createdAt: string;
  updatedAt: string;
}

export interface DataFieldSchema {
  name: string;
  type: "string" | "number" | "boolean" | "date" | "url" | "text";
  required?: boolean;
}

export interface DataRecordData {
  id: string;
  data: Record<string, unknown>;
  collectionId: string;
  createdAt: string;
  updatedAt: string;
}
