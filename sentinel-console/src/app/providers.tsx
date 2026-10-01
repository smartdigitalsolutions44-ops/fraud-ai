"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

import { ApiError } from "@/lib/api/client";

export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // the API client already retries transient failures; don't multiply them
            retry: (count, err) => err instanceof ApiError && err.transient && count < 1,
            refetchOnWindowFocus: true,
            staleTime: 2_000,
            // polling responses are structurally shared: unchanged rows keep their identity,
            // so a poll re-renders only what changed
            structuralSharing: true,
          },
          mutations: { retry: false },
        },
      }),
  );
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
