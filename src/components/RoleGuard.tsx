"use client";

import { ReactNode } from "react";
import { useAuth } from "@/@core/hooks/useAuth";
import { UserRole, hasRoleAccess, hasPermission } from "@/types/auth";

type RoleGuardProps = {
  children: ReactNode;
  roles?: UserRole[];
  permissions?: (keyof import("@/types/auth").UserPermissions)[];
  requireAllPermissions?: boolean;
  fallback?: ReactNode;
  renderIfUnauthorized?: boolean;
};

export default function RoleGuard({
  children,
  roles,
  permissions,
  requireAllPermissions = false,
  fallback = null,
  renderIfUnauthorized = false,
}: RoleGuardProps) {
  const { status, isAuthenticated, role } = useAuth();

  // Show loading state
  if (status === "loading") {
    return null;
  }

  // Check if user is authenticated
  if (!isAuthenticated) {
    return renderIfUnauthorized ? <>{children}</> : <>{fallback}</>;
  }

  const userRole = role?.toUpperCase() as UserRole;

  // Check role-based access
  if (roles && roles.length && userRole) {
    if (!hasRoleAccess(userRole, roles)) {
      return renderIfUnauthorized ? <>{children}</> : <>{fallback}</>;
    }
  }

  // Check permission-based access
  if (permissions && permissions.length && userRole) {
    const hasAccess = requireAllPermissions
      ? permissions.every((permission) => hasPermission(userRole, permission))
      : permissions.some((permission) => hasPermission(userRole, permission));

    if (!hasAccess) {
      return renderIfUnauthorized ? <>{children}</> : <>{fallback}</>;
    }
  }

  return <>{children}</>;
}

// Convenience components for common role checks
export function OwnerGuard({
  children,
  fallback = null,
}: {
  children: ReactNode;
  fallback?: ReactNode;
}) {
  return (
    <RoleGuard roles={["OWNER"]} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}

export function PrincipalGuard({
  children,
  fallback = null,
}: {
  children: ReactNode;
  fallback?: ReactNode;
}) {
  return (
    <RoleGuard roles={["OWNER", "PRINCIPAL"]} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}

export function TeacherGuard({
  children,
  fallback = null,
}: {
  children: ReactNode;
  fallback?: ReactNode;
}) {
  return (
    <RoleGuard roles={["OWNER", "PRINCIPAL", "TEACHER"]} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}

export function ParentGuard({
  children,
  fallback = null,
}: {
  children: ReactNode;
  fallback?: ReactNode;
}) {
  return (
    <RoleGuard roles={["OWNER", "PRINCIPAL", "PARENT"]} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}

export function StudentGuard({
  children,
  fallback = null,
}: {
  children: ReactNode;
  fallback?: ReactNode;
}) {
  return (
    <RoleGuard
      roles={["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"]}
      fallback={fallback}
    >
      {children}
    </RoleGuard>
  );
}
