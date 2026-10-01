"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";


export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // the API client already retries transient failures (twice, with delays); retrying
            // again here would multiply requests during an outage, so polls back off instead
            retry: false,
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
