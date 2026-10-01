import type { Metadata } from "next";

import { DemoPage } from "@/features/demo/DemoPage";

export const metadata: Metadata = { title: "Demo" };

export default function Page() {
  return <DemoPage />;
}
