"use client";
import { useEffect, useMemo, useState } from "react";
import {
  signIn as nextAuthSignIn,
  signOut as nextAuthSignOut,
  useSession,
} from "next-auth/react";

type SignInArgs = { customId: string; password: string; redirectTo?: string };

export function useAuth() {
  const { data, status, update } = useSession();
  const [error, setError] = useState<string | null>(null);

  const isAuthenticated = status === "authenticated";
  const accessToken = (data as any)?.accessToken as string | undefined;
  const role = (data as any)?.role as string | undefined;
  const branchId = (data as any)?.branchId as string | undefined;

  const signIn = async ({ customId, password, redirectTo }: SignInArgs) => {
    setError(null);
    const res = await nextAuthSignIn("credentials", {
      customId,
      password,
      redirect: false,
      callbackUrl: redirectTo || "/(dashboard)",
    });
    if (!res || (typeof res === "object" && "error" in res && res.error)) {
      setError(
        typeof res === "object" ? (res.error as string) : "Login failed",
      );
    } else {
      await update();
    }
    return res;
  };

  const signOut = async () => {
    await nextAuthSignOut({ redirect: true, callbackUrl: "/login" });
  };

  return useMemo(
    () => ({
      isAuthenticated,
      status,
      session: data,
      accessToken,
      role,
      branchId,
      error,
      signIn,
      signOut,
    }),
    [isAuthenticated, status, data, accessToken, role, branchId, error],
  );
}
