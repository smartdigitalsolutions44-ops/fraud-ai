import type { Metadata } from "next";

import { LiveFeed } from "@/features/feed/LiveFeed";

export const metadata: Metadata = { title: "Live Feed" };

export default function Page() {
  return <LiveFeed />;
}
