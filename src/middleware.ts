import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

type UserRole = "OWNER" | "PRINCIPAL" | "TEACHER" | "PARENT" | "STUDENT";

// Public paths that don't require authentication
const PUBLIC_PATHS = [
  // '/(blank-layout-pages)/login',
  "/ashara_logo.svg",
  "/neros.png",
  "/barcode.png",
  "/image.png",
  "/neros2.png",
  "/.well-known/appspecific/com.chrome.devtools.json",
  "/login",
  "/api/auth",
  "/_next",
  "/favicon.ico",
  "/pdfsvg.png",
  "/public",
  "/images",
  "/uploads",
  "/error",
  "/unauthorized",
];

// Route-based role requirements - ALL routes must be explicitly defined
const ROUTE_ROLE_REQUIREMENTS: Record<string, UserRole[]> = {
  // Dashboard - accessible by all authenticated users
  "/dashboard": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],

  // Students routes
  "/students": ["OWNER", "PRINCIPAL", "TEACHER"],
  "/students/admission": ["OWNER", "PRINCIPAL"],
  "/students/assignment": ["PRINCIPAL", "TEACHER"],
  "/students/list": ["OWNER", "PRINCIPAL", "TEACHER"],

  // Parents routes
  "/parents": ["OWNER", "PRINCIPAL"],
  "/parents/list": ["OWNER", "PRINCIPAL"],

  // Teachers routes
  "/teachers": ["OWNER", "PRINCIPAL"],
  "/teachers/add": ["OWNER", "PRINCIPAL"],
  "/teachers/list": ["OWNER", "PRINCIPAL", "TEACHER"],
  "/teachers/allocation": ["PRINCIPAL"],
  "/teachers/viewmap": ["OWNER", "PRINCIPAL"],

  // Teachers routes
  "/principals": ["OWNER"],
  "/principals/add": ["OWNER"],
  "/principals/list": ["OWNER"],

  // Materials routes
  "/materials": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
  "/materials/add": ["OWNER", "PRINCIPAL", "TEACHER"],
  "/materials/list": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],

  // Schedules routes
  "/schedules": ["OWNER", "PRINCIPAL", "PARENT", "PARENT", "STUDENT"],
  "/schedules/calendar": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
  "/schedules/timetables": [
    "OWNER",
    "PRINCIPAL",
    "TEACHER",
    "PARENT",
    "STUDENT",
  ],

  // Academics routes
  "/academics": ["OWNER", "PRINCIPAL", "PARENT", "PARENT", "STUDENT"],
  "/academics/assessmnet-setup": [
    "OWNER",
    "PRINCIPAL",
    "TEACHER",
    "PARENT",
    "STUDENT",
  ],
  "/academics/subject-teacher": [
    "OWNER",
    "PRINCIPAL",
    "TEACHER",
    "PARENT",
    "STUDENT",
  ],
  "/academics/reports": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
  "/academics/result-approval": [
    "OWNER",
    "PRINCIPAL",
    "TEACHER",
    "PARENT",
    "STUDENT",
  ],
  "/academics/result-entry": [
    "OWNER",
    "PRINCIPAL",
    "TEACHER",
    "PARENT",
    "STUDENT",
  ],
  "/academics/student-portal": [
    "OWNER",
    "PRINCIPAL",
    "TEACHER",
    "PARENT",
    "STUDENT",
  ],

  // Attendance routes
  "/attendance": ["OWNER", "PRINCIPAL", "TEACHER"],
  "/attendance/student": ["OWNER", "PRINCIPAL", "TEACHER"],
  "/attendance/teacher": ["OWNER", "PRINCIPAL"],

  // Classes routes
  "/classes": ["OWNER", "PRINCIPAL"],

  // Map routes
  "/teachermap": ["OWNER", "PRINCIPAL"],
  "/teachermap/allocation": ["OWNER", "PRINCIPAL"],
  "/teachermap/viewmap": ["OWNER", "PRINCIPAL", "TEACHER"],

  // Common routes accessible by all authenticated users
  "/profile": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
  "/settings": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
  "/home": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
  "/notifications": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
  "/help": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
  "/messages/anouncement": [
    "OWNER",
    "PRINCIPAL",
    "TEACHER",
    "PARENT",
    "STUDENT",
  ],
  "/messages/commbook": ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
};

// Role hierarchy for checking access
const ROLE_HIERARCHY: UserRole[] = [
  "OWNER",
  "PRINCIPAL",
  "TEACHER",
  "PARENT",
  "STUDENT",
];

function getRoleLevel(role: UserRole): number {
  return ROLE_HIERARCHY.indexOf(role);
}

function hasRoleAccess(userRole: UserRole, requiredRoles: UserRole[]): boolean {
  // Only allow access if the user's role is explicitly in the required roles
  // This prevents implicit access based on role hierarchy
  return requiredRoles.includes(userRole);
}

function isRoleHigherOrEqual(
  userRole: UserRole,
  targetRole: UserRole,
): boolean {
  return getRoleLevel(userRole) <= getRoleLevel(targetRole);
}

function getRequiredRolesForPath(pathname: string): UserRole[] | null {
  // Remove trailing slash for consistent matching
  const normalizedPath = pathname.replace(/\/$/, "");

  // Find the most specific route match
  const sortedRoutes = Object.keys(ROUTE_ROLE_REQUIREMENTS).sort(
    (a, b) => b.length - a.length,
  );

  // Debug: Log the matching process
  // console.log('🔍 Route Matching Debug:', {
  //   pathname,
  //   normalizedPath,
  //   sortedRoutes
  // })

  for (const route of sortedRoutes) {
    // Check for exact match
    if (normalizedPath === route) {
      // console.log('✅ Exact match found:', route, '->', ROUTE_ROLE_REQUIREMENTS[route])
      return ROUTE_ROLE_REQUIREMENTS[route];
    }

    // Check for path prefix match (for nested routes)
    if (normalizedPath.startsWith(route + "/")) {
      // console.log('✅ Prefix match found:', route, '->', ROUTE_ROLE_REQUIREMENTS[route])
      return ROUTE_ROLE_REQUIREMENTS[route];
    }
  }

  // If no route is explicitly defined, deny access
  // This ensures all routes are explicitly protected
  // console.log('❌ No route match found for:', normalizedPath)
  return null;
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Check if the path is public
  const isPublic = PUBLIC_PATHS.some((p) => pathname.startsWith(p));
  if (isPublic) {
    return NextResponse.next();
  }

  // Get the authentication token
  const token = await getToken({
    req,
    secret: process.env.NEXTAUTH_SECRET,
    secureCookie: process.env.NODE_ENV === "production",
  });

  // If no token, redirect to login
  if (!token) {
    const loginPath = "/login";
    const url = new URL(loginPath, req.url);

    // Preserve the callback URL for post-login redirect
    if (pathname !== loginPath && pathname !== "/(blank-layout-pages)/login") {
      url.searchParams.set("callbackUrl", pathname);
    }

    return NextResponse.redirect(url);
  }

  // Extract user role from token
  const userRole = (token.role as string)?.toUpperCase() as UserRole;
  if (!userRole) {
    // If no role in token, redirect to login
    const loginPath = "/login";
    const url = new URL(loginPath, req.url);
    return NextResponse.redirect(url);
  }

  // Get required roles for the current path
  const requiredRoles = getRequiredRolesForPath(pathname);

  console.log("🔐 Role Check Debug:", {
    pathname,
    userRole,
    requiredRoles,
    hasAccess: requiredRoles
      ? hasRoleAccess(userRole, requiredRoles)
      : "ROUTE_NOT_DEFINED",
  });

  // If no route configuration exists, deny access
  if (!requiredRoles) {
    console.log("❌ Route not defined:", pathname);
    const unauthorizedPath = "/unauthorized";
    const url = new URL(unauthorizedPath, req.url);

    // Add query parameters for debugging
    url.searchParams.set("error", "ROUTE_NOT_DEFINED");
    url.searchParams.set("path", pathname);
    url.searchParams.set("userRole", userRole);

    return NextResponse.redirect(url);
  }

  // Check if user has required role access
  if (!hasRoleAccess(userRole, requiredRoles)) {
    console.log("❌ Insufficient permissions:", {
      userRole,
      requiredRoles,
      pathname,
    });
    // User doesn't have required role, redirect to unauthorized page
    const unauthorizedPath = "/unauthorized";
    const url = new URL(unauthorizedPath, req.url);

    // Add query parameters for debugging
    url.searchParams.set("requiredRole", requiredRoles.join(","));
    url.searchParams.set("userRole", userRole);
    url.searchParams.set("path", pathname);
    url.searchParams.set("error", "INSUFFICIENT_PERMISSIONS");

    return NextResponse.redirect(url);
  }

  console.log("✅ Access granted:", {
    pathname,
    userRole,
    requiredRoles,
  });

  // Add security headers
  const response = NextResponse.next();
  response.headers.set("X-User-Role", userRole);
  response.headers.set("X-User-ID", token.sub || "");

  if (token.branchId) {
    response.headers.set("X-Branch-ID", token.branchId as string);
  }

  return response;
}

export const config = {
  matcher: [
    // Match all routes except static files, API routes, and Next.js internals
    "/((?!api|_next/static|_next/image|favicon.ico|public|images|uploads).*)",
  ],
};
