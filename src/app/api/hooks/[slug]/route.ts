import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import crypto from "crypto";
import { performCodeReview } from "@/lib/code-review";

export async function POST(
    request: NextRequest,
    { params }: { params: Promise<{ slug: string }> }
) {
    const slug = (await params).slug;

    // 1. 웹훅 존재 여부 확인
    const webhook = await prisma.incomingWebhook.findUnique({
        where: { slug },
        include: {
            project: {
                include: {
                    settings: true
                }
            }
        }
    });

    if (!webhook || !webhook.enabled) {
        return NextResponse.json({ error: "Webhook not found or disabled" }, { status: 404 });
    }

    // 2. 페이로드 파싱
    const rawBody = await request.text();
    let payload: any = {};
    try {
        payload = JSON.parse(rawBody);
    } catch {
        payload = { raw: rawBody };
    }

    // 3. GitHub 서명 검증 (Secret이 설정된 경우)
    const signature = request.headers.get("x-hub-signature-256");
    if (signature && webhook.project) {
        const githubSecret = webhook.project.settings.find(
            s => s.key === "SK_ROOKIES_FINAL_PJT_GITHUB_WEBHOOK_SECRET"
        )?.value || process.env.SK_ROOKIES_FINAL_PJT_GITHUB_WEBHOOK_SECRET;

        if (githubSecret) {
            const hmac = crypto.createHmac("sha256", githubSecret);
            const digest = "sha256=" + hmac.update(rawBody).digest("hex");
            
            try {
                if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature))) {
                    console.error("Invalid GitHub signature");
                    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
                }
            } catch (e) {
                return NextResponse.json({ error: "Signature verification failed" }, { status: 401 });
            }
        }
    }

    // 4. 일반 로그 저장 (WebhookLog)
    const log = await prisma.webhookLog.create({
        data: {
            incomingWebhookId: webhook.id,
            direction: "INCOMING",
            status: "SUCCEEDED",
            payload: payload as any,
            response: "200 OK",
        },
    });

    // 5. 프로젝트 활동 로그 저장 (ProjectActivityLog)
    if (webhook.projectId) {
        let action = "WEBHOOK_EVENT";
        let content = "외부 데이터 수신";
        const userAgent = request.headers.get("user-agent") || "";
        let platform = "EXTERNAL";

        // 플랫폼 감지 로직 고도화
        if (request.headers.get("x-github-event")) {
            platform = "GITHUB";
            const event = request.headers.get("x-github-event");
            action = event?.toUpperCase() || "GITHUB_EVENT";
            
            if (event === "push") {
                const branch = payload.ref?.split("/").pop();
                const commitMsg = payload.head_commit?.message || "No message";
                const author = payload.head_commit?.author?.name || "Unknown";
                content = `[${branch}] ${commitMsg} (by ${author})`;
            } else if (event === "ping") {
                content = "GitHub 웹훅 연결 성공 (Ping)";
            } else {
                content = `GitHub 이벤트 발생: ${event}`;
            }
        } else if (userAgent.includes("Slack")) {
            platform = "SLACK";
            content = payload.text || "Slack 메시지 수신";
        } else if (userAgent.includes("Discord")) {
            platform = "DISCORD";
            content = payload.content || "Discord 메시지 수신";
        }

        await prisma.projectActivityLog.create({
            data: {
                projectId: webhook.projectId,
                platform,
                action,
                content,
                rawPayload: payload as any,
                eventTime: new Date(),
            }
        });
    }

    // 코드 리뷰 자동화 (fire-and-forget, webhookLogId 전달로 중복 방지)
    const githubEvent = request.headers.get("x-github-event");
    if (githubEvent && githubEvent !== "ping") {
        const reviewConfig = await prisma.codeReviewConfig.findFirst({
            where: { incomingWebhookId: webhook.id, enabled: true }
        });
        if (reviewConfig) {
            performCodeReview(payload, reviewConfig, log.id).catch(e =>
                console.error("[CODE_REVIEW]", e.message)
            );
        }
    }

    return NextResponse.json({ success: true, logId: log.id });
}
