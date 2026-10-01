import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "@/styles/globals.css";

import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

import { Shell } from "@/components/shell/Shell";

import { Providers } from "./providers";

export const metadata: Metadata = {
  title: { default: "SENTINEL // Analyst Console", template: "%s · SENTINEL // Analyst Console" },
  description: "SENTINEL — Fraud Intelligence & Response. Analyst console for the fraud-ai service.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { themeColor: "#0a0c0f", colorScheme: "dark" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en-GB">
      <body>
        <a className="skip-link" href="#main">
          Skip to content
        </a>
        <div className="backdrop" aria-hidden="true" />
        <Providers>
          <Shell>{children}</Shell>
        </Providers>
      </body>
    </html>
  );
}
