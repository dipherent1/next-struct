import { apiClient, getAuthHeaders } from "@/api/client";
import { useAuth } from "@/@core/hooks/useAuth";
import { UserRole } from "@/types/auth";

// Type definitions for session data
interface SessionData {
  accessToken?: string;
  role?: string;
  branchId?: string;
  user?: {
    id: string;
    customId: string;
    role: string;
    branchId?: string;
  };
}

export interface AuthHeaders {
  Authorization?: string;
  "X-User-Role"?: UserRole;
  "X-Branch-Id"?: string;
}

/**
 * Enhanced authentication service that handles role-based API calls
 * and provides utilities for authentication management
 */
export class AuthService {
  /**
   * Get enhanced authentication headers including role and branch information
   */
  static async getAuthHeaders(): Promise<AuthHeaders> {
    const baseHeaders = await getAuthHeaders();

    // Get additional auth info from session if available
    if (typeof window !== "undefined") {
      const session = await this.getCurrentSession();
      if (session) {
        return {
          ...baseHeaders,
          "X-User-Role": session.role?.toUpperCase() as UserRole,
          "X-Branch-Id": session.branchId || undefined,
        };
      }
    }

    return baseHeaders;
  }

  /**
   * Get current session information
   */
  static async getCurrentSession(): Promise<SessionData | null> {
    if (typeof window === "undefined") {
      // Server-side: use getServerAuth
      const { getServerAuth } = await import("@/auth");
      const session = await getServerAuth();
      return session as SessionData | null;
    } else {
      // Client-side: use getSession
      const { getSession } = await import("next-auth/react");
      const session = await getSession();
      return session as SessionData | null;
    }
  }

  /**
   * Make an authenticated API call with role-based headers
   */
  static async authenticatedRequest<T = any>(config: {
    method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
    url: string;
    data?: any;
    params?: any;
    headers?: Record<string, string>;
  }): Promise<T> {
    const authHeaders = await this.getAuthHeaders();

    const response = await apiClient.request<T>({
      ...config,
      headers: {
        ...authHeaders,
        ...config.headers,
      },
    });

    return response.data;
  }

  /**
   * GET request with authentication
   */
  static async get<T = any>(
    url: string,
    params?: any,
    headers?: Record<string, string>,
  ): Promise<T> {
    return this.authenticatedRequest<T>({
      method: "GET",
      url,
      params,
      headers,
    });
  }

  /**
   * POST request with authentication
   */
  static async post<T = any>(
    url: string,
    data?: any,
    headers?: Record<string, string>,
  ): Promise<T> {
    return this.authenticatedRequest<T>({
      method: "POST",
      url,
      data,
      headers,
    });
  }

  /**
   * PUT request with authentication
   */
  static async put<T = any>(
    url: string,
    data?: any,
    headers?: Record<string, string>,
  ): Promise<T> {
    return this.authenticatedRequest<T>({
      method: "PUT",
      url,
      data,
      headers,
    });
  }

  /**
   * DELETE request with authentication
   */
  static async delete<T = any>(
    url: string,
    headers?: Record<string, string>,
  ): Promise<T> {
    return this.authenticatedRequest<T>({
      method: "DELETE",
      url,
      headers,
    });
  }

  /**
   * PATCH request with authentication
   */
  static async patch<T = any>(
    url: string,
    data?: any,
    headers?: Record<string, string>,
  ): Promise<T> {
    return this.authenticatedRequest<T>({
      method: "PATCH",
      url,
      data,
      headers,
    });
  }

  /**
   * Check if current user has specific role
   */
  static async hasRole(requiredRole: UserRole): Promise<boolean> {
    const session = await this.getCurrentSession();
    if (!session || !session.role) return false;

    const userRole = session.role.toUpperCase() as UserRole;
    return userRole === requiredRole;
  }

  /**
   * Check if current user has any of the specified roles
   */
  static async hasAnyRole(roles: UserRole[]): Promise<boolean> {
    const session = await this.getCurrentSession();
    if (!session || !session.role) return false;

    const userRole = session.role.toUpperCase() as UserRole;
    return roles.includes(userRole);
  }

  /**
   * Check if current user has all of the specified roles
   */
  static async hasAllRoles(roles: UserRole[]): Promise<boolean> {
    const session = await this.getCurrentSession();
    if (!session || !session.role) return false;

    const userRole = session.role.toUpperCase() as UserRole;
    return roles.every((role) => userRole === role);
  }

  /**
   * Get current user role
   */
  static async getUserRole(): Promise<UserRole | null> {
    const session = await this.getCurrentSession();
    return (session?.role?.toUpperCase() as UserRole) || null;
  }

  /**
   * Get current branch ID
   */
  static async getBranchId(): Promise<string | null> {
    const session = await this.getCurrentSession();
    return session?.branchId || null;
  }

  /**
   * Check if user is authenticated
   */
  static async isAuthenticated(): Promise<boolean> {
    const session = await this.getCurrentSession();
    return !!session;
  }

  /**
   * Refresh authentication token if needed
   */
  static async refreshToken(): Promise<boolean> {
    try {
      // This would typically call a refresh token endpoint
      // For now, we'll just check if the session is still valid
      const session = await this.getCurrentSession();
      return !!session;
    } catch (error) {
      console.error("Failed to refresh token:", error);
      return false;
    }
  }

  /**
   * Logout user and clear session
   */
  static async logout(): Promise<void> {
    if (typeof window !== "undefined") {
      const { signOut } = await import("next-auth/react");
      await signOut({ redirect: true, callbackUrl: "/login" });
    }
  }
}

/**
 * Hook for using authentication service in components
 */
export function useAuthService() {
  const { isAuthenticated, role, branchId, signOut } = useAuth();

  const getAuthHeaders = async () => AuthService.getAuthHeaders();
  const authenticatedRequest = <T = any>(
    config: Parameters<typeof AuthService.authenticatedRequest<T>>[0],
  ) => AuthService.authenticatedRequest<T>(config);
  const get = <T = any>(
    url: string,
    params?: any,
    headers?: Record<string, string>,
  ) => AuthService.get<T>(url, params, headers);
  const post = <T = any>(
    url: string,
    data?: any,
    headers?: Record<string, string>,
  ) => AuthService.post<T>(url, data, headers);
  const put = <T = any>(
    url: string,
    data?: any,
    headers?: Record<string, string>,
  ) => AuthService.put<T>(url, data, headers);
  const deleteRequest = <T = any>(
    url: string,
    headers?: Record<string, string>,
  ) => AuthService.delete<T>(url, headers);
  const patch = <T = any>(
    url: string,
    data?: any,
    headers?: Record<string, string>,
  ) => AuthService.patch<T>(url, data, headers);

  const hasRole = async (requiredRole: UserRole) =>
    AuthService.hasRole(requiredRole);
  const hasAnyRole = async (roles: UserRole[]) => AuthService.hasAnyRole(roles);
  const hasAllRoles = async (roles: UserRole[]) =>
    AuthService.hasAllRoles(roles);
  const getUserRole = async () => AuthService.getUserRole();
  const getBranchId = async () => AuthService.getBranchId();
  const refreshToken = async () => AuthService.refreshToken();
  const logout = async () => AuthService.logout();

  return {
    // State
    isAuthenticated,
    role,
    branchId,

    // Methods
    getAuthHeaders,
    authenticatedRequest,
    get,
    post,
    put,
    delete: deleteRequest,
    patch,
    hasRole,
    hasAnyRole,
    hasAllRoles,
    getUserRole,
    getBranchId,
    refreshToken,
    logout: signOut, // Use the hook's signOut for consistency
  };
}

/**
 * Higher-order function to create role-based API services
 */
export function createRoleBasedService<
  T extends Record<string, any>,
>(baseConfig: { baseUrl: string; defaultHeaders?: Record<string, string> }) {
  return {
    /**
     * Create a service method with role-based access control
     */
    createMethod: <K extends keyof T>(
      methodName: K,
      config: {
        method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
        path: string;
        requiredRoles?: UserRole[];
        requiredPermissions?: (keyof import("@/types/auth").UserPermissions)[];
      },
    ) => {
      return async (
        data?: any,
        params?: any,
        options?: { headers?: Record<string, string> },
      ) => {
        // Check role-based access if roles are specified
        if (config.requiredRoles && config.requiredRoles.length > 0) {
          const hasAccess = await AuthService.hasAnyRole(config.requiredRoles);
          if (!hasAccess) {
            throw new Error(
              `Access denied. Required roles: ${config.requiredRoles.join(", ")}`,
            );
          }
        }

        // Check permission-based access if permissions are specified
        if (
          config.requiredPermissions &&
          config.requiredPermissions.length > 0
        ) {
          const userRole = await AuthService.getUserRole();
          if (!userRole) {
            throw new Error("User role not found");
          }

          const { hasPermission } = await import("@/types/auth");
          const hasPermissionAccess = config.requiredPermissions.some(
            (permission) => hasPermission(userRole, permission),
          );

          if (!hasPermissionAccess) {
            throw new Error(
              `Access denied. Required permissions: ${config.requiredPermissions.join(", ")}`,
            );
          }
        }

        // Make the API call
        const url = `${baseConfig.baseUrl}${config.path}`;
        const headers = {
          ...baseConfig.defaultHeaders,
          ...options?.headers,
        };

        return AuthService.authenticatedRequest({
          method: config.method,
          url,
          data,
          params,
          headers,
        });
      };
    },
  };
}
