"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../hooks/useAuth";
import { UserRole, hasRoleAccess, hasPermission } from "@/types/auth";
import { CircularProgress, Box } from "@mui/material";

type AuthGuardProps = {
  children: React.ReactNode;
  roles?: UserRole[];
  permissions?: (keyof import("@/types/auth").UserPermissions)[];
  requireAllPermissions?: boolean;
  fallback?: React.ReactNode;
  redirectTo?: string;
  unauthorizedRedirect?: string;
};

export default function AuthGuard({
  children,
  roles,
  permissions,
  requireAllPermissions = false,
  fallback,
  redirectTo = "/(blank-layout-pages)/login",
  unauthorizedRedirect = "/(dashboard)",
}: AuthGuardProps) {
  const router = useRouter();
  const { status, isAuthenticated, role } = useAuth();

  useEffect(() => {
    if (status === "loading") return;

    // Check if user is authenticated
    if (!isAuthenticated) {
      router.replace(redirectTo);
      return;
    }

    // Check role-based access
    if (roles && roles.length && role) {
      const userRole = role.toUpperCase() as UserRole;
      if (!hasRoleAccess(userRole, roles)) {
        router.replace(unauthorizedRedirect);
        return;
      }
    }

    // Check permission-based access
    if (permissions && permissions.length && role) {
      const userRole = role.toUpperCase() as UserRole;
      const hasAccess = requireAllPermissions
        ? permissions.every((permission) => hasPermission(userRole, permission))
        : permissions.some((permission) => hasPermission(userRole, permission));

      if (!hasAccess) {
        router.replace(unauthorizedRedirect);
        return;
      }
    }
  }, [
    status,
    isAuthenticated,
    role,
    roles,
    permissions,
    requireAllPermissions,
    router,
    redirectTo,
    unauthorizedRedirect,
  ]);

  // Show loading state
  if (status === "loading") {
    return (
      fallback || (
        <Box
          display="flex"
          justifyContent="center"
          alignItems="center"
          minHeight="200px"
        >
          <CircularProgress />
        </Box>
      )
    );
  }

  return <>{children}</>;
}

// Backward compatibility alias
export { AuthGuard as RequireAuth };
