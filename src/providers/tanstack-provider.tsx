"use client";

import React from "react";

import {
  isServer,
  MutationCache,
  QueryCache,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { useAlert } from "./AlertProvider";
import { handleError } from "@/utils/errorHandler";

// function makeQueryClient() {
//   return new QueryClient({
//     defaultOptions: {
//       queries: {
//         staleTime: 60 * 1000
//       }
//     },
//     queryCache: new QueryCache({
//       onError: error => {
//         showAlert(`Something went wrong: ${error.message}`)
//       }
//     })
//   })
// }

// let browserQueryClient: QueryClient | undefined = undefined

// export function getQueryClient() {
//   if (isServer) return makeQueryClient()
//   else {
//     if (!browserQueryClient) browserQueryClient = makeQueryClient()

//     return browserQueryClient
//   }
// }

export default function TanstackQueryProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const { showAlert } = useAlert();
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 60 * 1000,
      },
    },
    queryCache: new QueryCache({
      onError: (error) => {
        showAlert(handleError(error), "error");
      },
    }),
    mutationCache: new MutationCache({
      onError: (error) => {
        showAlert(handleError(error), "error");
      },
    }),
  });

  return (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}
