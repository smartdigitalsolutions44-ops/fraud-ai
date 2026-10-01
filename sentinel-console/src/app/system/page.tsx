import type { Metadata } from "next";

import { SystemPage } from "@/features/system/SystemPage";

export const metadata: Metadata = { title: "System" };

export default function Page() {
  return <SystemPage />;
}
