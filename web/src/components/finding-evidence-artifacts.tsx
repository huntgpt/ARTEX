"use client";

import * as React from "react";

import Image from "next/image";

import { CameraIcon, ShieldCheckIcon, TerminalIcon } from "lucide-react";

import { Markdown } from "@/components/markdown";
import { Badge } from "@/components/ui/badge";
import { intlLocale, t } from "@/i18n";
import { api } from "@/lib/api";
import type { FindingEvidenceArtifact } from "@/lib/types";

const artifactMarkerPattern = /!\[([^\]\n]*)\]\(artifact:\/\/([a-f0-9]{64})\)/gi;

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function markerFor(artifact: FindingEvidenceArtifact) {
  const caption = (artifact.label || (artifact.kind === "browser_screenshot" ? "Browser evidence" : "Command evidence"))
    .replaceAll("]", "")
    .trim();
  return `![${caption}](artifact://${artifact.id})`;
}

// Reports written before artifact markers existed still render their verified
// captures inline. They are inserted under Evidence rather than collected in a
// detached gallery, and a later Reporter rewrite can move each marker beside the
// exact statement it proves.
export function withInlineEvidenceMarkers(text: string, items: FindingEvidenceArtifact[]) {
  const referenced = new Set(
    Array.from(text.matchAll(new RegExp(artifactMarkerPattern.source, artifactMarkerPattern.flags))).map((match) =>
      match[2].toLowerCase(),
    ),
  );
  const missing = items.filter((artifact) => !referenced.has(artifact.id.toLowerCase()));
  if (missing.length === 0) return text;

  const markers = missing.map(markerFor).join("\n\n");
  const evidenceHeading = /^##\s+Evidence\s*$/im;
  const heading = evidenceHeading.exec(text);
  if (!heading) return `${text.trimEnd()}\n\n## Evidence\n\n${markers}\n`;
  const insertAt = heading.index + heading[0].length;
  return `${text.slice(0, insertAt)}\n\n${markers}${text.slice(insertAt)}`;
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
      <div className="flex min-h-40 items-center justify-center bg-destructive/5 px-5 text-center text-destructive text-sm">
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
      {/* The endpoint re-hashes the original file before returning this blob. */}
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

function EvidenceFigure({
  findingId,
  artifact,
  caption,
}: {
  findingId: string;
  artifact: FindingEvidenceArtifact;
  caption: string;
}) {
  return (
    <figure className="my-5 min-w-0 overflow-hidden rounded-xl border bg-background">
      <EvidenceImage findingId={findingId} artifact={artifact} />
      <figcaption className="space-y-2 px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          {artifact.kind === "browser_screenshot" ? (
            <CameraIcon className="size-4 text-muted-foreground" />
          ) : (
            <TerminalIcon className="size-4 text-muted-foreground" />
          )}
          <span className="font-medium text-sm">{caption.trim() ? caption : artifact.label}</span>
          <Badge variant="outline">{artifact.tool?.trim() ? artifact.tool : t("tool")}</Badge>
          <Badge variant="secondary" className="gap-1">
            <ShieldCheckIcon className="size-3" /> {t("Hash verified")}
          </Badge>
          {artifact.truncated && <Badge variant="destructive">{t("Image truncated; raw output retained")}</Badge>}
        </div>
        {artifact.source_url && <p className="break-all text-muted-foreground text-sm">{artifact.source_url}</p>}
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
  );
}

type ReportPart =
  | { kind: "markdown"; text: string; key: string }
  | { kind: "artifact"; artifactId: string; caption: string; key: string };

function reportParts(text: string): ReportPart[] {
  const parts: ReportPart[] = [];
  const matcher = new RegExp(artifactMarkerPattern.source, artifactMarkerPattern.flags);
  let cursor = 0;
  let index = 0;
  for (const match of text.matchAll(matcher)) {
    const offset = match.index ?? 0;
    if (offset > cursor) parts.push({ kind: "markdown", text: text.slice(cursor, offset), key: `md-${index++}` });
    parts.push({
      kind: "artifact",
      artifactId: match[2].toLowerCase(),
      caption: match[1].trim(),
      key: `artifact-${match[2]}-${index++}`,
    });
    cursor = offset + match[0].length;
  }
  if (cursor < text.length) parts.push({ kind: "markdown", text: text.slice(cursor), key: `md-${index}` });
  return parts;
}

export function FindingReportWithEvidence({ findingId, text }: { findingId: string; text: string }) {
  const [items, setItems] = React.useState<FindingEvidenceArtifact[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    api
      .findingArtifacts(findingId)
      .then((response) => {
        if (active) setItems(response.items ?? []);
      })
      .catch((reason: Error) => {
        if (active) setError(reason.message || t("Visual evidence could not be loaded"));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [findingId]);

  if (loading) {
    return (
      <div className="space-y-3">
        <Markdown text={text} />
        <p className="text-muted-foreground text-xs" role="status">
          {t("Loading verified images…")}
        </p>
      </div>
    );
  }
  if (error) {
    return (
      <div className="space-y-3">
        <Markdown text={text} />
        <p className="text-destructive text-sm">{t("Visual evidence could not be loaded: {error}", { error })}</p>
      </div>
    );
  }

  const artifacts = new Map(items.map((artifact) => [artifact.id.toLowerCase(), artifact]));
  const rendered = withInlineEvidenceMarkers(text, items);
  return (
    <div className="min-w-0 break-words [&_pre]:whitespace-pre-wrap">
      {reportParts(rendered).map((part) => {
        if (part.kind === "markdown") return part.text ? <Markdown key={part.key} text={part.text} /> : null;
        const artifact = artifacts.get(part.artifactId);
        if (!artifact) {
          return (
            <p key={part.key} className="my-3 text-destructive text-sm">
              {t("Referenced evidence image is unavailable or failed integrity validation.")}
            </p>
          );
        }
        return <EvidenceFigure key={part.key} findingId={findingId} artifact={artifact} caption={part.caption} />;
      })}
    </div>
  );
}
