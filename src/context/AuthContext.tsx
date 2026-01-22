"use client";

import React, {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  ReactNode,
} from "react";
import { useSession } from "next-auth/react";
import {
  signIn as nextAuthSignIn,
  signOut as nextAuthSignOut,
} from "next-auth/react";
import {
  UserRole,
  hasPermission,
  hasRoleAccess,
  getRoleLevel,
  isRoleHigherOrEqual,
} from "@/types/auth";
import { AuthService } from "@/services/auth.service";

// Type definitions
interface AuthUser {
  id: string;
  customId: string;
  name: string;
  role: UserRole;
  branchId?: string;
}

interface AuthSession {
  accessToken?: string;
  user?: AuthUser;
  expires?: string;
}

interface AuthContextType {
  // Authentication state
  isAuthenticated: boolean;
  isLoading: boolean;
  session: AuthSession | null;
  user: AuthUser | null;

  // User role and permissions
  role: UserRole | null;
  roleLevel: number;
  permissions: Record<string, boolean>;

  // Authentication actions
  signIn: (credentials: {
    customId: string;
    password: string;
  }) => Promise<{ success: boolean; error?: string }>;
  signOut: () => Promise<void>;
  refreshSession: () => Promise<void>;

  // Role-based checks
  hasRole: (roles: UserRole[]) => boolean;
  hasPermission: (permission: string) => boolean;
  isRoleHigherOrEqual: (targetRole: UserRole) => boolean;

  // Service access
  authService: typeof AuthService;
}

// Create the context
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Props for the provider
interface AuthProviderProps {
  children: ReactNode;
}

// AuthProvider component
export function AuthProvider({ children }: AuthProviderProps) {
  const { data: session, status, update } = useSession();
  const [authState, setAuthState] = useState<{
    isAuthenticated: boolean;
    isLoading: boolean;
    session: AuthSession | null;
    user: AuthUser | null;
    role: UserRole | null;
    roleLevel: number;
    permissions: Record<string, boolean>;
  }>({
    isAuthenticated: false,
    isLoading: true,
    session: null,
    user: null,
    role: null,
    roleLevel: -1,
    permissions: {},
  });

  // Update auth state when session changes
  useEffect(() => {
    const updateAuthState = async () => {
      if (status === "loading") {
        setAuthState((prev) => ({ ...prev, isLoading: true }));
        return;
      }

      if (status === "authenticated" && session) {
        const user: AuthUser = {
          id: (session as any).id || "",
          customId: (session as any).customId || "",
          name: (session as any).name || "",
          role: ((session as any).role?.toUpperCase() as UserRole) || "STUDENT",
          branchId: (session as any).branchId,
        };

        const role = user.role;
        const roleLevel = getRoleLevel(role);

        // Generate permissions based on role
        const permissions: Record<string, boolean> = {};
        const { ROLE_PERMISSIONS, hasPermission: checkPermission } =
          await import("@/types/auth");
        Object.keys(ROLE_PERMISSIONS[role] || {}).forEach((permission) => {
          permissions[permission] = checkPermission(role, permission as any);
        });

        setAuthState({
          isAuthenticated: true,
          isLoading: false,
          session: session as AuthSession,
          user,
          role,
          roleLevel,
          permissions,
        });
      } else {
        setAuthState({
          isAuthenticated: false,
          isLoading: false,
          session: null,
          user: null,
          role: null,
          roleLevel: -1,
          permissions: {},
        });
      }
    };

    updateAuthState();
  }, [session, status]);

  // Sign in function
  const signIn = useCallback(
    async (credentials: { customId: string; password: string }) => {
      try {
        const result = await nextAuthSignIn("credentials", {
          customId: credentials.customId,
          password: credentials.password,
          redirect: false,
          callbackUrl: "/(dashboard)",
        });

        if (result?.error) {
          return { success: false, error: result.error };
        }

        // Update the session to trigger state refresh
        await update();
        return { success: true };
      } catch (error) {
        return { success: false, error: "An unexpected error occurred" };
      }
    },
    [update],
  );

  // Sign out function
  const signOut = useCallback(async () => {
    await nextAuthSignOut({ redirect: true, callbackUrl: "/login" });
  }, []);

  // Refresh session function
  const refreshSession = useCallback(async () => {
    await update();
  }, [update]);

  // Role-based check functions
  const hasRole = useCallback(
    (roles: UserRole[]) => {
      if (!authState.role) return false;
      return hasRoleAccess(authState.role, roles);
    },
    [authState.role],
  );

  const hasPermission = useCallback(
    (permission: string) => {
      if (!authState.role) return false;
      return authState.permissions[permission] || false;
    },
    [authState.role, authState.permissions],
  );

  const checkRoleHigherOrEqual = useCallback(
    (targetRole: UserRole) => {
      if (!authState.role) return false;
      return isRoleHigherOrEqual(authState.role, targetRole);
    },
    [authState.role],
  );

  // Context value
  const contextValue: AuthContextType = {
    isAuthenticated: authState.isAuthenticated,
    isLoading: authState.isLoading,
    session: authState.session,
    user: authState.user,
    role: authState.role,
    roleLevel: authState.roleLevel,
    permissions: authState.permissions,
    signIn,
    signOut,
    refreshSession,
    hasRole,
    hasPermission,
    isRoleHigherOrEqual: checkRoleHigherOrEqual,
    authService: AuthService,
  };

  return (
    <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
  );
}

// Hook to use the auth context
export function useAuthContext() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuthContext must be used within an AuthProvider");
  }
  return context;
}

// Convenience hooks for specific use cases
export function useIsAuthenticated() {
  const { isAuthenticated, isLoading } = useAuthContext();
  return { isAuthenticated, isLoading };
}

export function useCurrentUser() {
  const { user, isLoading } = useAuthContext();
  return { user, isLoading };
}

export function useCurrentRole() {
  const { role, roleLevel, isLoading } = useAuthContext();
  return { role, roleLevel, isLoading };
}

export function useAuthPermissions() {
  const { permissions, hasPermission, isLoading } = useAuthContext();
  return { permissions, hasPermission, isLoading };
}

// Role-specific convenience hooks
export function useIsOwner() {
  const { hasRole } = useAuthContext();
  return hasRole(["OWNER"]);
}

export function useIsPrincipal() {
  const { hasRole } = useAuthContext();
  return hasRole(["OWNER", "PRINCIPAL"]);
}

export function useIsTeacher() {
  const { hasRole } = useAuthContext();
  return hasRole(["OWNER", "PRINCIPAL", "TEACHER"]);
}

export function useIsParent() {
  const { hasRole } = useAuthContext();
  return hasRole(["OWNER", "PRINCIPAL", "PARENT"]);
}

export function useIsStudent() {
  const { hasRole } = useAuthContext();
  return hasRole(["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"]);
}
