import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

const publicPaths = ["/login", "/guest", "/api/auth", "/blog", "/portfolio", "/api/public", "/api/hooks"];
const sharePaths = ["/share/"];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow service-key requests (Discord bot, internal services)
  const serviceKey = request.headers.get("x-service-key");
  if (serviceKey && serviceKey === process.env.SERVICE_API_KEY && process.env.SERVICE_API_KEY) {
    return NextResponse.next();
  }

  // Allow public paths
  if (publicPaths.some((path) => pathname.startsWith(path))) {
    return NextResponse.next();
  }

  // Allow share links
  if (sharePaths.some((path) => pathname.startsWith(path))) {
    return NextResponse.next();
  }

  // Allow static files and Next.js internals
  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/api/share") ||
    pathname.includes(".")
  ) {
    return NextResponse.next();
  }

  // Check for auth token using next-auth/jwt
  const token = await getToken({
    req: request,
    secret: process.env.NEXTAUTH_SECRET,
  });

  if (!token) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|uploads).*)"],
};
