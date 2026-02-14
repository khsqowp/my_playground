import { NextRequest, NextResponse } from "next/server";
import { processWithAI } from "@/lib/ai";
import { logger } from "@/lib/logger";

export async function POST(req: NextRequest) {
    try {
        const { text, type } = await req.json();

        if (!text) {
            return NextResponse.json({ error: "Text is required" }, { status: 400 });
        }

        let prompt = "";
        if (type === "tagging") {
            prompt = `Analyze the following text and provide 3-5 relevant tags (keywords) in Korean. Return strictly a JSON object: { "tags": ["tag1", "tag2", ...] }. DO NOT return any other text.
      
      Text: ${text}`;
        } else if (type === "summary") {
            prompt = `Analyze the following text and provide a 1-sentence summary in Korean. Return strictly a JSON object: { "summary": "summary text..." }. DO NOT return any other text.
      
      Text: ${text}`;
        } else {
            prompt = `Analyze the following text. Provide 3-5 relevant tags and a 1-sentence summary in Korean. Return strictly a JSON object: { "tags": ["tag1", "tag2", ...], "summary": "summary text..." }. DO NOT return any other text.
      
      Text: ${text}`;
        }

        logger.info("AI Analysis requested", { type, textLength: text.length });

        const aiResponse = await processWithAI(prompt);

        // Clean up response if it contains markdown code blocks
        const cleanedResponse = aiResponse.replace(/```json/g, "").replace(/```/g, "").trim();

        const result = JSON.parse(cleanedResponse);

        logger.info("AI Analysis success", { result });

        return NextResponse.json(result);
    } catch (error: any) {
        logger.error("AI Analysis failed", { error: error.message });
        return NextResponse.json({ error: "Failed to analyze text" }, { status: 500 });
    }
}
