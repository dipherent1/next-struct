import axios from "axios";
import { getServerAuth } from "@/auth";
import { getSession } from "next-auth/react";
import { AuthService } from "@/services/auth.service";
import { UserRole } from "@/types/auth";

const API_BASE = (
  process.env.NEXT_PUBLIC_API_URL ||
  process.env.API_URL ||
  ""
).replace(/\/$/, "");

// Create base API client
export const apiClient = axios.create({
  baseURL: API_BASE || "/",
  headers: {
    Accept: "application/json",
    "Content-Type": "application/json",
  },
  timeout: 30000,
});

// const readAccessToken = async () => {
//   if (typeof window === 'undefined') {
//     const session = await getServerAuth()
//     return (session as any)?.accessToken || null
//   }
//   const session = await getSession()
//   return (session as any)?.accessToken || null
// }

/**
 * Enhanced function to get complete authentication information
 */
const getAuthInfo = async () => {
  if (typeof window === "undefined") {
    const session = await getServerAuth();
    return {
      accessToken: (session as any)?.accessToken || null,
      role: ((session as any)?.role as UserRole) || null,
      branchId: (session as any)?.branchId || null,
    };
  }
  const session = await getSession();
  return {
    accessToken: (session as any)?.accessToken || null,
    role: ((session as any)?.role as UserRole) || null,
    branchId: (session as any)?.branchId || null,
  };
};

// Request interceptor to add auth token and role-based headers
apiClient.interceptors.request.use(
  async (config) => {
    const authInfo = await getAuthInfo();

    // Add authorization header
    if (authInfo.accessToken) {
      config.headers.Authorization = `Bearer ${authInfo.accessToken}`;
    }

    // Add role-based headers
    if (authInfo.role) {
      config.headers["X-User-Role"] = authInfo.role;
    }

    if (authInfo.branchId) {
      config.headers["X-Branch-Id"] = authInfo.branchId;
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  },
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (res) => res,
  async (err) => {
    if (typeof window !== "undefined") {
      const msg =
        err?.response?.data?.message ||
        err?.message ||
        "An unexpected API error occurred";
      const status = err?.response?.status;

      // Dispatch error event
      window.dispatchEvent(
        new CustomEvent("api-error", {
          detail: {
            message: msg,
            status,
            code: err?.code,
          },
        }),
      );

      // Handle specific error codes
      if (status === 401) {
        // Unauthorized - clear tokens and redirect to login
        localStorage.removeItem("accessToken");
        sessionStorage.removeItem("accessToken");

        // Use AuthService for consistent logout
        await AuthService.logout();
      } else if (status === 403) {
        // Forbidden - role-based access denied
        console.error("Access denied: insufficient permissions");

        // Could redirect to an unauthorized page or show a message
        window.dispatchEvent(
          new CustomEvent("auth-error", {
            detail: {
              message: "You do not have permission to access this resource",
              status: 403,
              type: "permission_denied",
            },
          }),
        );
      }
    }

    return Promise.reject(err);
  },
);

// Multipart/form-data client with auth
export const apiClient2 = axios.create({
  baseURL: API_BASE || "/",
  headers: {
    Accept: "application/json",
    "Content-Type": "multipart/form-data",
  },
  timeout: 30000,
});

// Add auth interceptor to multipart client too
apiClient2.interceptors.request.use(
  async (config) => {
    const authInfo = await getAuthInfo();

    // Add authorization header
    if (authInfo.accessToken) {
      config.headers.Authorization = `Bearer ${authInfo.accessToken}`;
    }

    // Add role-based headers
    if (authInfo.role) {
      config.headers["X-User-Role"] = authInfo.role;
    }

    if (authInfo.branchId) {
      config.headers["X-Branch-Id"] = authInfo.branchId;
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  },
);

// Response interceptor for multipart client
apiClient2.interceptors.response.use(
  (res) => res,
  async (err) => {
    if (typeof window !== "undefined") {
      const msg =
        err?.response?.data?.message ||
        err?.message ||
        "An unexpected API error occurred";
      const status = err?.response?.status;

      // Dispatch error event
      window.dispatchEvent(
        new CustomEvent("api-error", {
          detail: {
            message: msg,
            status,
            code: err?.code,
          },
        }),
      );

      // Handle specific error codes
      if (status === 401) {
        // Unauthorized - clear tokens and redirect to login
        localStorage.removeItem("accessToken");
        sessionStorage.removeItem("accessToken");

        // Use AuthService for consistent logout
        await AuthService.logout();
      } else if (status === 403) {
        // Forbidden - role-based access denied
        console.error("Access denied: insufficient permissions");

        window.dispatchEvent(
          new CustomEvent("auth-error", {
            detail: {
              message: "You do not have permission to access this resource",
              status: 403,
              type: "permission_denied",
            },
          }),
        );
      }
    }

    return Promise.reject(err);
  },
);

// Enhanced utility function for manual token attachment with role-based headers
export const getAuthHeaders = async () => {
  const authInfo = await getAuthInfo();
  const headers: Record<string, string> = {};

  if (authInfo.accessToken) {
    headers.Authorization = `Bearer ${authInfo.accessToken}`;
  }

  if (authInfo.role) {
    headers["X-User-Role"] = authInfo.role;
  }

  if (authInfo.branchId) {
    headers["X-Branch-Id"] = authInfo.branchId;
  }

  return headers;
};

// Optional: Create a public client without auth for specific endpoints
export const publicApiClient = axios.create({
  baseURL: API_BASE || "/",
  headers: {
    Accept: "application/json",
    "Content-Type": "application/json",
  },
  timeout: 30000,
});

/**
 * Create a role-based API client with specific permissions
 */
export function createRoleBasedClient(
  clientConfig: {
    requiredRoles?: UserRole[];
    requiredPermissions?: (keyof import("@/types/auth").UserPermissions)[];
    baseURL?: string;
  } = {},
) {
  const client = axios.create({
    baseURL: clientConfig.baseURL || API_BASE || "/",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    timeout: 30000,
  });

  // Add request interceptor with role-based validation
  client.interceptors.request.use(
    async (axiosConfig) => {
      const authInfo = await getAuthInfo();

      // Check if user is authenticated
      if (!authInfo.accessToken) {
        throw new Error("Authentication required");
      }

      // Check role-based access
      if (clientConfig.requiredRoles && clientConfig.requiredRoles.length > 0) {
        if (
          !authInfo.role ||
          !clientConfig.requiredRoles.includes(authInfo.role)
        ) {
          throw new Error(
            `Access denied. Required roles: ${clientConfig.requiredRoles.join(", ")}`,
          );
        }
      }

      // Check permission-based access
      if (
        clientConfig.requiredPermissions &&
        clientConfig.requiredPermissions.length > 0
      ) {
        if (!authInfo.role) {
          throw new Error("User role not found");
        }

        const { hasPermission } = await import("@/types/auth");
        const hasPermissionAccess = clientConfig.requiredPermissions.some(
          (permission: keyof import("@/types/auth").UserPermissions) =>
            hasPermission(authInfo.role!, permission),
        );

        if (!hasPermissionAccess) {
          throw new Error(
            `Access denied. Required permissions: ${clientConfig.requiredPermissions.join(", ")}`,
          );
        }
      }

      // Add authentication headers
      axiosConfig.headers.Authorization = `Bearer ${authInfo.accessToken}`;
      axiosConfig.headers["X-User-Role"] = authInfo.role;
      if (authInfo.branchId) {
        axiosConfig.headers["X-Branch-Id"] = authInfo.branchId;
      }

      return axiosConfig;
    },
    (error) => {
      return Promise.reject(error);
    },
  );

  // Add response interceptor with enhanced error handling
  client.interceptors.response.use(
    (res) => res,
    async (err) => {
      if (typeof window !== "undefined") {
        const msg =
          err?.response?.data?.message ||
          err?.message ||
          "An unexpected API error occurred";
        const status = err?.response?.status;

        window.dispatchEvent(
          new CustomEvent("api-error", {
            detail: {
              message: msg,
              status,
              code: err?.code,
            },
          }),
        );

        if (status === 401) {
          await AuthService.logout();
        } else if (status === 403) {
          window.dispatchEvent(
            new CustomEvent("auth-error", {
              detail: {
                message: "You do not have permission to access this resource",
                status: 403,
                type: "permission_denied",
              },
            }),
          );
        }
      }

      return Promise.reject(err);
    },
  );

  return client;
}

/**
 * Pre-configured role-based clients for common use cases
 */
export const adminClient = createRoleBasedClient({
  requiredRoles: ["OWNER", "PRINCIPAL"],
});

export const teacherClient = createRoleBasedClient({
  requiredRoles: ["OWNER", "PRINCIPAL", "TEACHER"],
});

export const parentClient = createRoleBasedClient({
  requiredRoles: ["OWNER", "PRINCIPAL", "PARENT"],
});

export const studentClient = createRoleBasedClient({
  requiredRoles: ["OWNER", "PRINCIPAL", "TEACHER", "PARENT", "STUDENT"],
});
