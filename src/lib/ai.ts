import prisma from "@/lib/prisma";

export async function callOpenAI(
  prompt: string,
  apiKey: string,
  model = "gpt-4"
): Promise<string> {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: prompt }],
      max_tokens: 2000,
    }),
  });

  if (!res.ok) {
    throw new Error(`OpenAI API error: ${res.status}`);
  }

  const data = await res.json();
  return data.choices[0]?.message?.content ?? "";
}

export async function callAnthropic(
  prompt: string,
  apiKey: string,
  model = "claude-sonnet-4-5-20250929"
): Promise<string> {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 2000,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!res.ok) {
    throw new Error(`Anthropic API error: ${res.status}`);
  }

  const data = await res.json();
  return data.content[0]?.text ?? "";
}

export async function getDefaultAiConfig(): Promise<{
  provider: string;
  apiKey: string;
  model: string;
} | null> {
  const config = await prisma.aiConfig.findFirst({
    where: { isDefault: true },
  });
  if (!config) return null;
  return {
    provider: config.provider,
    apiKey: config.apiKey,
    model: config.model,
  };
}

export async function processWithAI(prompt: string): Promise<string> {
  const config = await getDefaultAiConfig();
  if (!config) throw new Error("No AI configuration found");

  if (config.provider === "openai") {
    return callOpenAI(prompt, config.apiKey, config.model);
  } else if (config.provider === "anthropic") {
    return callAnthropic(prompt, config.apiKey, config.model);
  }

  throw new Error(`Unknown AI provider: ${config.provider}`);
}
