import { demoControl } from "@/lib/server/demoControl";

export const dynamic = "force-dynamic";

export function GET(): Promise<Response> {
  return demoControl("GET", "/status");
}
