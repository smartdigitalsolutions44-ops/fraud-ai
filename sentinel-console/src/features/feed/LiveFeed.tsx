"use client";

import { useState } from "react";

import { Icon } from "@/components/Icon";
import { LiveIndicator } from "@/components/LiveIndicator";
import { Panel } from "@/components/Panel";
import { Empty, ErrorState, SkeletonRows } from "@/components/States";
import { POLL, useFeed } from "@/lib/api/queries";
import { DECISION_ORDER, decisionLabel } from "@/lib/domain";
import { useLiveness } from "@/lib/hooks/useLiveness";

import { FeedTable } from "./FeedTable";

export function LiveFeed() {
  const [decision, setDecision] = useState<string>("");
  const [limit, setLimit] = useState(100);
  const [paused, setPaused] = useState(false);
  const feed = useFeed(limit, decision || undefined, paused);
  const live = useLiveness(feed, POLL.feed);
  const state = paused && feed.data ? "paused" : live.state;
  const items = feed.data?.items ?? [];

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h2>Live feed</h2>
          <p>Every assessment the risk policy made, newest first. Rows show pseudonymous references only; open one to investigate.</p>
        </div>
        <div className="toolbar">
          <LiveIndicator state={state} ageMs={live.ageMs} />
          <button type="button" className="btn btn-sm" onClick={() => setPaused((p) => !p)} aria-pressed={paused}>
            {paused ? "Resume updates" : "Pause updates"}
          </button>
        </div>
      </div>
      {live.state === "stale" && !paused ? (
        <div className="stale-banner" role="status">
          <Icon name="alert" /> The feed could not be refreshed. Rows below are from the last successful update.
        </div>
      ) : null}
      <Panel
        title="Assessments"
        meta={
          <div className="toolbar">
            <label className="sr-only" htmlFor="feed-decision">
              Decision
            </label>
            <select id="feed-decision" className="select" value={decision} onChange={(e) => setDecision(e.target.value)}>
              <option value="">All decisions</option>
              {DECISION_ORDER.map((d) => (
                <option key={d} value={d}>
                  {decisionLabel(d).label}
                </option>
              ))}
            </select>
            <label className="sr-only" htmlFor="feed-limit">
              Rows
            </label>
            <select id="feed-limit" className="select" value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              {[50, 100, 200].map((n) => (
                <option key={n} value={n}>
                  Latest {n}
                </option>
              ))}
            </select>
          </div>
        }
        flush
        note="Risk band is the policy's band of the calibrated model score — a ranking signal, not a probability of fraud. Polling every 5 s while this tab is visible."
      >
        {feed.isPending ? (
          <SkeletonRows rows={10} label="Loading feed" />
        ) : feed.isError && !feed.data ? (
          <div className="panel-body">
            <ErrorState error={feed.error} onRetry={() => void feed.refetch()} />
          </div>
        ) : items.length ? (
          <FeedTable items={items} caption="Live assessments" />
        ) : (
          <Empty>No assessments{decision ? ` with decision ${decisionLabel(decision).label}` : ""} yet.</Empty>
        )}
      </Panel>
    </div>
  );
}
