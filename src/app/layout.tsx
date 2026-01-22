// MUI Imports
import InitColorSchemeScript from "@mui/material/InitColorSchemeScript";

// Third-party Imports
import "react-perfect-scrollbar/dist/css/styles.css";

// Type Imports
import type { ChildrenType } from "@core/types";

// Util Imports
import { getSystemMode } from "@core/utils/serverHelpers";

// Style Imports
import "@/app/globals.css";

// Generated Icon CSS Imports
import "@assets/iconify-icons/generated-icons.css";
import TanstackQueryProvider from "@/components/tanstack-provider";
import { AlertProvider } from "@/components/AlertProvider";
import AuthProvider from "@core/components/AuthProvider";
import AuthGuard from "@/@core/components/RequireAuth";
import { AuthProvider as AuthContextProvider } from "@/contexts/AuthContext";

export const metadata = {
  title: "Ashara SMS",
  description: "lorem ipsum",
};

const RootLayout = async (props: ChildrenType) => {
  const { children } = props;

  // Vars

  const systemMode = await getSystemMode();
  const direction = "ltr";

  return (
    <html id="__next" lang="en" dir={direction} suppressHydrationWarning>
      <body className="flex is-full min-bs-full flex-auto flex-col">
        <InitColorSchemeScript attribute="data" defaultMode={systemMode} />
        <AlertProvider>
          <AuthProvider>
            <AuthContextProvider>
              <AuthGuard>
                <TanstackQueryProvider>{children}</TanstackQueryProvider>
              </AuthGuard>
            </AuthContextProvider>
          </AuthProvider>
        </AlertProvider>
      </body>
    </html>
  );
};

export default RootLayout;
