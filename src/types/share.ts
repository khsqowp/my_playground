export interface ShareLinkData {
  id: string;
  token: string;
  targetType: "POST" | "NOTE" | "QUIZSET" | "COLLECTION";
  targetId: string;
  expiresAt: string | null;
  maxAccess: number | null;
  accessCount: number;
  password: string | null;
  active: boolean;
  createdBy: string;
  createdAt: string;
}

export interface ShareLinkCreateInput {
  targetType: "POST" | "NOTE" | "QUIZSET" | "COLLECTION";
  targetId: string;
  expiresAt?: string;
  maxAccess?: number;
  password?: string;
}
