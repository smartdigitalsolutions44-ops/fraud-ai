import type { Metadata } from "next";
import { Suspense } from "react";

import { SkeletonRows } from "@/components/States";
import { ReviewQueue } from "@/features/queue/ReviewQueue";

export const metadata: Metadata = { title: "Review Queue" };

export default function Page() {
  return (
    <Suspense fallback={<SkeletonRows rows={8} label="Loading review queue" />}>
      <ReviewQueue />
    </Suspense>
  );
}
