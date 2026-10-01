import type { Metadata } from "next";

import { Investigations } from "@/features/investigations/Investigations";

export const metadata: Metadata = { title: "Investigations" };

export default function Page() {
  return <Investigations />;
}
