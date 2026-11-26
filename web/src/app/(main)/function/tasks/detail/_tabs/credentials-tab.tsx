"use client";

import * as React from "react";

import { EyeIcon, EyeOffIcon, PlusIcon, TrashIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import { setVisibleInterval } from "@/lib/polling";
import type { DiscoveredSecret, TaskCredential } from "@/lib/types";

// Credentials tab (#3): the task's test accounts — user-declared (program alias
// accounts) and agent-recorded (accounts the workers registered themselves).
// Passwords are masked server-side and never sent to the browser.
export function CredentialsTab({ taskId }: { taskId: string }) {
  const [items, setItems] = React.useState<TaskCredential[] | null>(null);
  const [error, setError] = React.useState("");
  const [domain, setDomain] = React.useState("");
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [note, setNote] = React.useState("");
  const [adding, setAdding] = React.useState(false);
  const [secrets, setSecrets] = React.useState<DiscoveredSecret[] | null>(null);
  const [revealed, setRevealed] = React.useState<Record<number, string>>({});

  const load = React.useCallback(() => {
    Promise.all([api.taskCredentials(taskId), api.taskDiscoveredSecrets(taskId)])
      .then(([credentials, discovered]) => {
        setItems(credentials);
        setSecrets(discovered);
        setError("");
      })
      .catch((e) => setError((e as Error).message));
  }, [taskId]);

  async function reveal(secret: DiscoveredSecret) {
    if (revealed[secret.id] !== undefined) {
      setRevealed((current) => {
        const next = { ...current };
        delete next[secret.id];
        return next;
      });
      return;
    }
    const reason = window.prompt(t("Reason for revealing this secret (recorded in audit log)"));
    if (!reason?.trim()) return;
    try {
      const result = await api.revealTaskDiscoveredSecret(taskId, secret.id, reason.trim());
      setRevealed((current) => ({ ...current, [secret.id]: result.value }));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  React.useEffect(() => {
    load();
    // Agent runs can record credentials mid-task; a light poll keeps the tab current.
    const stopPolling = setVisibleInterval(load, 15000);
    return stopPolling;
  }, [load]);

  async function add() {
    if (!domain.trim() || !username.trim()) return;
    setAdding(true);
    try {
      await api.addTaskCredential(taskId, {
        domain: domain.trim(),
        username: username.trim(),
        password, // empty = "agent generates and records it"
        note: note.trim(),
      });
      setDomain("");
      setUsername("");
      setPassword("");
      setNote("");
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAdding(false);
    }
  }

  async function remove(id: number) {
    try {
      await api.deleteTaskCredential(taskId, id);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{t("Test accounts")}</CardTitle>
          <CardDescription>
            {t(
              "Test accounts for this task. Entries with an empty password mean the agent registers that account and records it. Agent-recorded accounts appear here automatically.",
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {error ? <p className="text-destructive text-sm">{error}</p> : null}
          {items === null ? (
            <Skeleton className="h-24 w-full" />
          ) : items.length === 0 ? (
            <Empty>
              <EmptyHeader>
                <EmptyTitle>{t("No test accounts")}</EmptyTitle>
                <EmptyDescription>
                  {t(
                    "Add one below, or declare them when creating the task — the agent reuses them for authenticated testing.",
                  )}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="flex flex-col divide-y">
              {items.map((c) => (
                <div key={c.id} className="flex flex-wrap items-center gap-2 py-2.5">
                  <code className="font-medium text-sm">{c.domain}</code>
                  <span className="text-muted-foreground text-sm">{c.username}</span>
                  <Badge variant={c.source === "agent" ? "secondary" : "outline"}>
                    {c.source === "agent" ? t("agent-recorded") : t("declared")}
                  </Badge>
                  <div className="ml-auto flex items-center gap-1">
                    <code className="max-w-40 truncate rounded bg-muted px-2 py-0.5 text-sm">
                      {c.password === "" ? t("— agent generates —") : t("stored, hidden")}
                    </code>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-7"
                      aria-label={t("Delete credential")}
                      onClick={() => remove(c.id)}
                    >
                      <TrashIcon />
                    </Button>
                  </div>
                  {c.note ? <p className="w-full text-muted-foreground text-xs">{c.note}</p> : null}
                </div>
              ))}
            </div>
          )}
          <div className="grid gap-2 sm:grid-cols-[1fr_1fr_1fr_auto]">
            <Input
              placeholder={t("domain (e.g. target.example.com)")}
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
            />
            <Input
              placeholder={t("email or username")}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <Input
              placeholder={t("password (empty = agent generates)")}
              type="text"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <Button variant="outline" disabled={adding || !domain.trim() || !username.trim()} onClick={add}>
              <PlusIcon /> {t("Add")}
            </Button>
            <Input
              className="sm:col-span-4"
              placeholder={t("note (optional, e.g. program alias account)")}
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{t("Discovered secrets")}</CardTitle>
          <CardDescription>
            {t("TruffleHog results are encrypted at rest. Values stay 30% masked until an audited reveal action.")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {secrets === null ? (
            <Skeleton className="h-24 w-full" />
          ) : secrets.length === 0 ? (
            <p className="text-muted-foreground text-sm">{t("No discovered secrets")}</p>
          ) : (
            <div className="flex flex-col divide-y">
              {secrets.map((secret) => (
                <div key={secret.id} className="flex flex-wrap items-center gap-2 py-3">
                  <Badge variant={secret.verified ? "default" : "secondary"}>
                    {secret.verified ? t("verified") : t("unverified")}
                  </Badge>
                  <span className="font-medium text-sm">{secret.detector}</span>
                  <code className="max-w-full truncate text-muted-foreground text-xs">
                    {[secret.repository, secret.file_path].filter(Boolean).join("/") ||
                      secret.source_name ||
                      t("unknown location")}
                    {secret.line_number ? `:${secret.line_number}` : ""}
                  </code>
                  <div className="ml-auto flex items-center gap-1">
                    <code className="max-w-72 break-all rounded bg-muted px-2 py-1 text-sm">
                      {revealed[secret.id] ?? secret.masked_value}
                    </code>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-8"
                      aria-label={t("Reveal or hide secret")}
                      onClick={() => reveal(secret)}
                    >
                      {revealed[secret.id] !== undefined ? <EyeOffIcon /> : <EyeIcon />}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
