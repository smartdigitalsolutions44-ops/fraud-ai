import type { Metadata } from "next";

import { Metrics } from "@/features/metrics/Metrics";

export const metadata: Metadata = { title: "Metrics" };

export default function Page() {
  return <Metrics />;
}
