import type { Metadata } from "next";

import { CaseWorkspace } from "@/features/case/CaseWorkspace";

export const metadata: Metadata = { title: "Case" };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function Page({ params }: { params: Promise<{ assessmentId: string }> }) {
  const { assessmentId } = await params;
  return (
    <div className="page">
      {UUID.test(assessmentId) ? (
        <CaseWorkspace assessmentId={assessmentId} />
      ) : (
        <div className="state" data-tone="amber" role="alert">
          <div>
            <div className="state-title">Not found</div>
            <div className="muted">Case links use an assessment ID (a UUID).</div>
          </div>
        </div>
      )}
    </div>
  );
}
