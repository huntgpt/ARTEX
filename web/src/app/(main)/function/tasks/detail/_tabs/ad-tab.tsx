"use client";

import * as React from "react";

import { AlertTriangleIcon, DatabaseIcon, NetworkIcon, RefreshCwIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { setVisibleInterval } from "@/lib/polling";
import type { ADCollectionRun, ADGraph } from "@/lib/types";

function runTone(state: ADCollectionRun["state"]): "default" | "secondary" | "destructive" | "outline" {
  if (state === "complete") return "default";
  if (state === "failed" || state === "rejected") return "destructive";
  if (state === "partial" || state === "cancelled") return "secondary";
  return "outline";
}

export function ADTab({ taskId }: { taskId: string }) {
  const [graph, setGraph] = React.useState<ADGraph | null>(null);
  const [runs, setRuns] = React.useState<ADCollectionRun[]>([]);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(async () => {
    try {
      const [nextGraph, nextRuns] = await Promise.all([api.taskADGraph(taskId), api.taskADRuns(taskId)]);
      setGraph(nextGraph);
      setRuns(nextRuns);
      setError("");
    } catch (reason) {
      setError(String((reason as Error)?.message ?? reason));
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    void load();
    return setVisibleInterval(() => void load(), 5000);
  }, [load]);

  const counts = React.useMemo(() => {
    const result: Record<string, number> = {};
    for (const entity of graph?.entities ?? []) result[entity.kind] = (result[entity.kind] ?? 0) + 1;
    return result;
  }, [graph]);

  const relationCounts = React.useMemo(() => {
    const result: Record<string, number> = {};
    for (const edge of graph?.edges ?? []) result[edge.relation] = (result[edge.relation] ?? 0) + 1;
    return result;
  }, [graph]);

  return (
    <div className="grid gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-semibold text-lg">Active Directory</h2>
          <p className="text-muted-foreground text-sm">
            BloodHound collection lifecycle, graph evidence, and current blockers.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          <RefreshCwIcon className={loading ? "animate-spin" : ""} /> Refresh
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-md border border-destructive/40 bg-destructive/5 p-3 text-destructive text-sm">
          <AlertTriangleIcon className="size-4" /> {error}
        </div>
      )}

      <div className="grid gap-3 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <DatabaseIcon className="size-4" />
              Entities
            </CardTitle>
          </CardHeader>
          <CardContent className="font-semibold text-2xl tabular-nums">{graph?.entity_count ?? 0}</CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <NetworkIcon className="size-4" />
              Relationships
            </CardTitle>
          </CardHeader>
          <CardContent className="font-semibold text-2xl tabular-nums">{graph?.edge_count ?? 0}</CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Observed kinds</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-1 text-xs">
            {Object.entries(counts).map(([kind, count]) => (
              <Badge key={kind} variant="secondary">
                {kind} {count}
              </Badge>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Collection runs</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3">
          {runs.length === 0 && (
            <p className="text-muted-foreground text-sm">No AD collection run has been recorded for this task.</p>
          )}
          {runs.map((run) => (
            <div key={run.id} className="grid gap-2 rounded-md border p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm">#{run.id}</span>
                  <span className="font-medium text-sm">{run.collector}</span>
                  <Badge variant={runTone(run.state)}>{run.state}</Badge>
                  <Badge variant="outline">{run.mode}</Badge>
                </div>
                <span className="text-muted-foreground text-xs">
                  updated {new Date(run.updated_at).toLocaleString()}
                </span>
              </div>
              <div className="grid gap-1 text-sm sm:grid-cols-5">
                <span>records {run.records}</span>
                <span>entities {run.entities}</span>
                <span>edges {run.edges}</span>
                <span>skipped {run.skipped}</span>
                <span>artifacts {run.artifacts?.length ?? 0}</span>
              </div>
              {(run.blocker_reason || run.error_detail) && (
                <div className="rounded bg-amber-500/10 px-2 py-1 text-amber-700 text-xs dark:text-amber-300">
                  {run.blocker_reason || run.error_detail}
                </div>
              )}
              {run.artifacts?.map((artifact) => (
                <div key={artifact.id} className="flex flex-wrap gap-x-3 text-muted-foreground text-xs">
                  <span>{artifact.kind}</span>
                  <span>{artifact.logical_path}</span>
                  <span className="font-mono">sha256:{artifact.sha256.slice(0, 12)}…</span>
                  <span>{artifact.byte_size} bytes</span>
                  <span>{artifact.state}</span>
                </div>
              ))}
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Attack-path relationship kinds</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-1 text-xs">
          {Object.entries(relationCounts).map(([relation, count]) => (
            <Badge key={relation} variant="outline">
              {relation} {count}
            </Badge>
          ))}
          {Object.keys(relationCounts).length === 0 ? (
            <p className="text-muted-foreground text-sm">No attack-path relationships have been ingested.</p>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Graph observations</CardTitle>
        </CardHeader>
        <CardContent className="grid max-h-96 gap-2 overflow-auto">
          {(graph?.entities ?? []).slice(0, 500).map((entity) => (
            <div key={entity.key} className="grid gap-1 rounded border px-3 py-2 text-xs sm:grid-cols-[8rem_1fr_1fr]">
              <Badge variant="outline" className="w-fit">
                {entity.kind}
              </Badge>
              <span className="font-mono">{entity.key}</span>
              <span>{entity.dns_hostname || entity.domain_sid || "—"}</span>
            </div>
          ))}
          {(graph?.entities.length ?? 0) > 500 && (
            <p className="text-muted-foreground text-xs">Showing the first 500 entities.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
