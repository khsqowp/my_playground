export interface WebhookConfigData {
  id: string;
  name: string;
  platform: "DISCORD" | "SLACK" | "CUSTOM";
  url: string;
  secret: string | null;
  enabled: boolean;
  userId: string;
  createdAt: string;
  updatedAt: string;
}

export interface WebhookLogData {
  id: string;
  direction: "INBOUND" | "OUTBOUND";
  payload: unknown;
  status: "SUCCESS" | "FAILED";
  response: string | null;
  webhookId: string;
  createdAt: string;
}

export interface AiConfigData {
  id: string;
  provider: string;
  model: string;
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}
