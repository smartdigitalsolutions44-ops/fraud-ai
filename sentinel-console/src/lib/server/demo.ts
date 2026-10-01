import "server-only";

import { readFileSync } from "node:fs";
import path from "node:path";

import { serverConfig } from "./config";

export interface CatalogueCase {
  label: string;
  title: string;
  story: string;
  scenario: string;
  expected_decision: string;
  expected_reasons: string[];
  relaxed_match: boolean;
  prelude: Array<Record<string, unknown>>;
  event: Record<string, unknown> & { event_id?: string };
}

export interface Catalogue {
  synthetic: boolean;
  seed: number;
  users: number;
  cases: CatalogueCase[];
  missing_cases: string[];
  note: string;
}

/** The demo catalogue, read on the server only. Refused unless DEMO MODE is on. */
export function readCatalogue(): Catalogue {
  const cfg = serverConfig();
  if (!cfg.demoMode) throw new Error("DEMO_MODE_REQUIRED");
  if (!cfg.demoRoot) throw new Error("SENTINEL_DEMO_ROOT is not configured");
  const file = path.join(cfg.demoRoot, "catalogue.json");
  const data = JSON.parse(readFileSync(file, "utf8")) as Catalogue;
  if (data.synthetic !== true) throw new Error("the catalogue is not marked synthetic");
  return data;
}
