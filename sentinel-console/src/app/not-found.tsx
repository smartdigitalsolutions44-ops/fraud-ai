import Link from "next/link";

export default function NotFound() {
  return (
    <div className="page">
      <div className="state" data-tone="amber" role="alert">
        <div>
          <div className="state-title">Not found</div>
          <div className="muted">
            This page does not exist. <Link href="/" className="text-blue">Back to the overview</Link>.
          </div>
        </div>
      </div>
    </div>
  );
}
