import { NextResponse, type NextRequest } from "next/server";

const PROTECTED_PREFIXES = ["/agents", "/enrollment", "/settings"];
const SESSION_COOKIE = "better-auth.session_token";

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const protectedRoute = PROTECTED_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );

  const hasSession = req.cookies
    .getAll()
    .some((cookie) => cookie.name.endsWith(SESSION_COOKIE));

  if (!protectedRoute || hasSession) {
    return NextResponse.next();
  }

  const login = req.nextUrl.clone();
  login.pathname = "/login";
  login.searchParams.set("callbackURL", `${pathname}${req.nextUrl.search}`);
  return NextResponse.redirect(login);
}

export const config = {
  matcher: ["/agents/:path*", "/enrollment/:path*", "/settings/:path*"],
};
