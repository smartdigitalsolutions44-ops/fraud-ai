import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { ReactElement } from "react";
import { vi } from "vitest";

export function fixture<T = unknown>(name: string): T {
  return JSON.parse(readFileSync(path.join(__dirname, "fixtures", `${name}.json`), "utf8")) as T;
}

export type Route = (url: string, init?: RequestInit) => Response | Promise<Response> | undefined;

/** Route fetch calls by URL prefix; anything unrouted is a 404 so tests fail loudly. */
export function mockFetch(routes: Record<string, Route | unknown>) {
  const fn = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const key = Object.keys(routes)
      .sort((a, b) => b.length - a.length)
      .find((k) => url.startsWith(k));
    if (!key) return Response.json({ error: { code: "NOT_FOUND", message: `unrouted ${url}` } }, { status: 404 });
    const route = routes[key];
    if (typeof route === "function") return (await (route as Route)(url, init)) ?? Response.json({}, { status: 500 });
    return Response.json(route);
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

export function renderWithClient(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>) };
}
