import { getServerSession } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import type { NextAuthOptions, Session } from "next-auth";
import type { JWT } from "next-auth/jwt";

const API_BASE =
  (process.env.NEXT_PUBLIC_API_URL || process.env.API_URL || "").replace(
    /\/$/,
    "",
  ) || "http://localhost:3000/api";

export const authOptions: NextAuthOptions = {
  secret: process.env.NEXTAUTH_SECRET,
  session: { strategy: "jwt" as const },
  pages: { signIn: "/login" },
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        customId: { label: "ID", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.customId || !credentials?.password) return null;

        const res = await fetch(`${API_BASE}/auth/signin`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({
            customId: credentials.customId,
            password: credentials.password,
          }),
        });

        if (!res.ok) {
          try {
            const errData = await res.json();
            console.error("[NextAuth] Signin failed", {
              apiBase: API_BASE,
              status: res.status,
              message: errData?.message,
            });
          } catch (e) {
            console.error("[NextAuth] Signin failed (no json)", {
              apiBase: API_BASE,
              status: res.status,
            });
          }
          return null;
        }

        const contentType = res.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
          const text = await res.text();
          console.error("[NextAuth] Signin unexpected content-type", {
            apiBase: API_BASE,
            status: res.status,
            contentType,
            snippet: text.slice(0, 120),
          });
          return null;
        }

        let data: any;
        try {
          data = await res.json();
        } catch (e) {
          console.error("[NextAuth] Signin JSON parse error", {
            apiBase: API_BASE,
          });
          return null;
        }

        const accessToken = data?.access_token || data?.accessToken;
        if (!accessToken || !data?.user) return null;

        return {
          id: String(data.user.id),
          name: data.user.name,
          customId: data.user.customId,
          role: data.user.role,
          branchId: data.user.branchId,
          accessToken,
        } as any;
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }: { token: JWT; user?: any }) {
      if (user) {
        token.accessToken = (user as any).accessToken;
        token.role = (user as any).role;
        token.branchId = (user as any).branchId;
        token.id = (user as any).id;
        token.name = (user as any).name;
        token.customId = (user as any).customId;
      }
      return token;
    },
    async session({ session, token }: { session: Session; token: JWT }) {
      (session as any).accessToken = token.accessToken;
      (session as any).role = token.role;
      (session as any).branchId = token.branchId;
      (session as any).id = token.id;
      (session as any).name = token.name;
      (session as any).customId = token.customId;
      return session;
    },
  },
};

export async function getServerAuth() {
  return getServerSession(authOptions as any);
}

export { signIn, signOut, useSession } from "next-auth/react";
