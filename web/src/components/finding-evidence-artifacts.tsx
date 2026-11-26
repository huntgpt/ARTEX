"use client";

import * as React from "react";

import Image from "next/image";

import { CameraIcon, RefreshCwIcon, ShieldCheckIcon, TerminalIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { intlLocale, t } from "@/i18n";
import { api } from "@/lib/api";
import type { FindingEvidenceArtifact } from "@/lib/types";

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function EvidenceImage({ findingId, artifact }: { findingId: string; artifact: FindingEvidenceArtifact }) {
  const [src, setSrc] = React.useState("");
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    let active = true;
    let objectURL = "";
    setSrc("");
    setError("");
    api
      .findingArtifactBlob(findingId, artifact.id)
      .then((blob) => {
        if (!active) return;
        objectURL = URL.createObjectURL(blob);
        setSrc(objectURL);
      })
      .catch((reason: Error) => {
        if (active) setError(reason.message || t("Evidence image could not be loaded"));
      });
    return () => {
      active = false;
      if (objectURL) URL.revokeObjectURL(objectURL);
    };
  }, [artifact.id, findingId]);

  if (error) {
    return (
      <div className="flex min-h-40 items-center justify-center bg-destructive/5 px-5 text-center text-sm text-destructive">
        {error}
      </div>
    );
  }
  if (!src) {
    return <div className="min-h-40 animate-pulse bg-muted" role="status" aria-label={t("Loading evidence image…")} />;
  }
  return (
    <a
      href={src}
      target="_blank"
      rel="noreferrer"
      className="block bg-black/95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {/* This blob comes from ARTEX's hash-verifying evidence endpoint. */}
      <Image
        src={src}
        alt={artifact.kind === "browser_screenshot" ? t("Actual browser screenshot") : t("Actual command output")}
        width={1400}
        height={900}
        unoptimized
        className="max-h-[34rem] w-full object-contain"
      />
    </a>
  );
}

export function FindingEvidenceArtifacts({ findingId }: { findingId: string }) {
  const [items, setItems] = React.useState<FindingEvidenceArtifact[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  const load = React.useCallback(() => {
    setLoading(true);
    setError("");
    api
      .findingArtifacts(findingId)
      .then((response) => setItems(response.items ?? []))
      .catch((reason: Error) => setError(reason.message || t("Visual evidence could not be loaded")))
      .finally(() => setLoading(false));
  }, [findingId]);

  React.useEffect(() => load(), [load]);

  let content: React.ReactNode;
  if (loading) {
    content = (
      <p className="text-sm text-muted-foreground" role="status">
        {t("Loading verified images…")}
      </p>
    );
  } else if (error) {
    content = <p className="text-sm text-destructive">{error}</p>;
  } else if (items.length === 0) {
    content = (
      <p className="text-sm text-muted-foreground">
        {t("No hash-verified terminal or browser captures are attached to this finding yet.")}
      </p>
    );
  } else {
    content = (
      <div className="divide-y overflow-hidden rounded-xl border">
        {items.map((artifact) => (
          <figure key={artifact.id} className="min-w-0 bg-background">
            <EvidenceImage findingId={findingId} artifact={artifact} />
            <figcaption className="space-y-2 px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                {artifact.kind === "browser_screenshot" ? (
                  <CameraIcon className="size-4 text-muted-foreground" />
                ) : (
                  <TerminalIcon className="size-4 text-muted-foreground" />
                )}
                <span className="text-sm font-medium">{artifact.label}</span>
                <Badge variant="outline">{artifact.tool || t("tool")}</Badge>
                {artifact.truncated && <Badge variant="destructive">{t("Image truncated; raw output retained")}</Badge>}
              </div>
              {artifact.source_url && <p className="break-all text-sm text-muted-foreground">{artifact.source_url}</p>}
              {artifact.command && (
                <pre className="max-h-28 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted px-3 py-2 font-mono text-xs">
                  {artifact.command}
                </pre>
              )}
              <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-muted-foreground">
                <span title={artifact.sha256}>sha256:{artifact.sha256.slice(0, 16)}…</span>
                <span>{formatBytes(artifact.byte_size)}</span>
                <time dateTime={artifact.captured_at}>{new Date(artifact.captured_at).toLocaleString(intlLocale)}</time>
                <span>activity #{artifact.activity_id}</span>
              </div>
            </figcaption>
          </figure>
        ))}
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <ShieldCheckIcon className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
          <CardTitle className="text-sm">{t("Verified visual evidence")}</CardTitle>
          {!loading && <Badge variant="secondary">{items.length}</Badge>}
        </div>
        {error && (
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCwIcon /> {t("Retry")}
          </Button>
        )}
      </CardHeader>
      <CardContent>{content}</CardContent>
    </Card>
  );
}
