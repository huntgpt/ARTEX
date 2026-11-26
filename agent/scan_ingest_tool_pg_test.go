package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ingest_scan_output (PG): an nmap file writes its assets through insert_assets
// and its facts through record_fact; a second ingestion of the same file keeps
// the counters, adds no asset row and no fact; a path leaving the working
// directory through a symlink is refused.
func TestIngestScanOutputPG(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("ingest_scan_output", "scan-ingest.example.com", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const assetsWhere = `ip IN ('198.51.100.77','2001:db8::77') OR domain IN ('198.51.100.77','2001:db8::77','example.com') OR domain LIKE '%scan-ingest.example.com' OR url LIKE '%198.51.100.77%' OR url LIKE '%2001:db8::77%'`
	t.Cleanup(func() {
		_ = d.DeleteTask(task.ID)
		_, _ = d.Exec(`DELETE FROM assets WHERE ` + assetsWhere)
	})
	store := d.Exploration(task.ExplorationID)
	tsx := NewToolSet(store, "worker-1")
	tsx.SetTaskID(task.ID)
	tsx.SetAssetStore(d.Assets(), d.Companies())

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scan.xml"), []byte(nmapFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	tool := tsx.ingestScanOutput()
	call := func(path string) (map[string]any, actool.Result) {
		t.Helper()
		in, _ := json.Marshal(map[string]string{"format": "nmap-xml", "path": path})
		res, err := tool.Call(context.Background(), in, &actool.ToolContext{WorkingDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		_ = json.Unmarshal([]byte(res.Flatten()), &out)
		return out, res
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := d.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	facts := func() int {
		all, err := store.ListByKind(db.KindFact, 500)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, f := range all {
			if f.Origin == "worker-1" {
				n++
			}
		}
		return n
	}

	first, res := call("scan.xml")
	if res.IsError || first["facts_written"] != 2.0 || first["assets_written"] != 6.0 || first["fact_errors"] != nil || first["asset_errors"] != nil {
		t.Fatalf("first ingestion: %s", res.Flatten())
	}
	if n := count(`SELECT count(*) FROM assets WHERE type='ip' AND ip IN ('198.51.100.77','2001:db8::77')`); n != 2 {
		t.Fatalf("%d ip assets, want 2", n)
	}
	if n := count(`SELECT count(*) FROM assets WHERE type='service' AND url IN ('http://198.51.100.77:80','https://198.51.100.77:443','https://[2001:db8::77]:8443')`); n != 3 {
		t.Fatalf("%d http service assets, want 3", n)
	}
	if n := count(`SELECT count(*) FROM assets WHERE url LIKE '%evil%' OR domain LIKE '%evil%' OR domain = 'ptr.example.net'`); n != 0 {
		t.Fatalf("%d assets from target text or a PTR name", n)
	}
	assets, nFacts := count(`SELECT count(*) FROM assets WHERE `+assetsWhere), facts()
	if nFacts != 2 {
		t.Fatalf("%d facts, want 2", nFacts)
	}

	// Re-ingestion: same counters, no new asset row, no new fact.
	again, res := call("scan.xml")
	if res.IsError || again["facts_written"] != 0.0 || again["facts_existing"] != 2.0 {
		t.Fatalf("re-ingestion: %s", res.Flatten())
	}
	for _, k := range []string{"hosts", "ports", "urls", "events", "skipped", "assets_written"} {
		if again[k] != first[k] {
			t.Fatalf("re-ingestion: %s = %v, first run %v", k, again[k], first[k])
		}
	}
	if a, f := count(`SELECT count(*) FROM assets WHERE `+assetsWhere), facts(); a != assets || f != nFacts {
		t.Fatalf("re-ingestion: %d assets and %d facts, first run %d and %d", a, f, assets, nFacts)
	}

	// A symlink in the working directory leading outside it is refused.
	outside := filepath.Join(t.TempDir(), "secret.xml")
	if err := os.WriteFile(outside, []byte(nmapFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape.xml")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"escape.xml", outside, "../secret.xml"} {
		if _, res := call(p); !res.IsError {
			t.Fatalf("%s accepted: %s", p, res.Flatten())
		}
	}
}

// ingest_scan_output (PG), JSON formats: nuclei, httpx, Gowitness and ffuf write their
// assets and facts; a second ingestion keeps the counters and adds no asset
// row and no fact.
func TestIngestScanOutputJSONPG(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("ingest_scan_output_json", "scan-ingest.example.com", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const assetsWhere = `ip IN ('198.51.100.77','2001:db8::77') OR domain IN ('198.51.100.77','2001:db8::77','example.com') OR domain LIKE '%scan-ingest.example.com' OR url LIKE '%scan-ingest.example.com%'`
	t.Cleanup(func() {
		_ = d.DeleteTask(task.ID)
		_, _ = d.Exec(`DELETE FROM assets WHERE ` + assetsWhere)
	})
	store := d.Exploration(task.ExplorationID)
	tsx := NewToolSet(store, "worker-1")
	tsx.SetTaskID(task.ID)
	tsx.SetAssetStore(d.Assets(), d.Companies())
	dir := t.TempDir()
	tool := tsx.ingestScanOutput()
	formats := map[string]string{"ct-json": ctFixture, "dns-jsonl": dnsFixture, "nuclei-jsonl": nucleiFixture, "httpx-jsonl": httpxFixture, "gowitness-jsonl": gowitnessFixture, "ffuf-json": ffufFixture}
	wantFacts := map[string]float64{"ct-json": 2, "dns-jsonl": 2, "nuclei-jsonl": 2, "httpx-jsonl": 2, "gowitness-jsonl": 1, "ffuf-json": 2}
	wantAssets := map[string]float64{"ct-json": 2, "dns-jsonl": 3, "nuclei-jsonl": 2, "httpx-jsonl": 2, "gowitness-jsonl": 1, "ffuf-json": 2}
	ingest := func(format string) map[string]any {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, format+".out"), []byte(formats[format]), 0o600); err != nil {
			t.Fatal(err)
		}
		in, _ := json.Marshal(map[string]string{"format": format, "path": format + ".out"})
		res, err := tool.Call(context.Background(), in, &actool.ToolContext{WorkingDir: dir})
		var out map[string]any
		if err != nil || res.IsError || json.Unmarshal([]byte(res.Flatten()), &out) != nil ||
			out["asset_errors"] != nil || out["fact_errors"] != nil {
			t.Fatalf("%s: %v %s", format, err, res.Flatten())
		}
		return out
	}
	state := func() (assets, facts int) {
		t.Helper()
		if err := d.QueryRow(`SELECT count(*) FROM assets WHERE ` + assetsWhere).Scan(&assets); err != nil {
			t.Fatal(err)
		}
		all, err := store.ListByKind(db.KindFact, 500)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range all {
			if f.Origin == "worker-1" {
				facts++
			}
		}
		return assets, facts
	}

	first := map[string]map[string]any{}
	for format := range formats {
		if first[format] = ingest(format); first[format]["facts_written"] != wantFacts[format] || first[format]["assets_written"] != wantAssets[format] {
			t.Fatalf("%s first ingestion: %v", format, first[format])
		}
	}
	assets, facts := state()
	if facts != 11 || assets == 0 {
		t.Fatalf("%d assets and %d facts after the first ingestion, want some assets and 11 facts", assets, facts)
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE url LIKE '%evil%' OR domain LIKE '%evil%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d assets from target text (%v)", n, err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE domain='hermes.scan-ingest.example.com' AND $1 = ANY(task_ids)`, task.ID).Scan(&n); err != nil || n == 0 {
		t.Fatalf("certificate-transparency/DNS asset was not linked to task %d (%v)", task.ID, err)
	}
	for format := range formats {
		out := ingest(format)
		if out["facts_written"] != 0.0 || out["facts_existing"] != wantFacts[format] {
			t.Fatalf("%s re-ingestion: %v", format, out)
		}
		for _, k := range []string{"hosts", "urls", "events", "skipped", "oversized_lines", "assets_written"} {
			if out[k] != first[format][k] {
				t.Fatalf("%s re-ingestion: %s = %v, first run %v", format, k, out[k], first[format][k])
			}
		}
	}
	if a, f := state(); a != assets || f != facts {
		t.Fatalf("re-ingestion: %d assets and %d facts, first run %d and %d", a, f, assets, facts)
	}
}

func TestIngestScanOutputCreatesIdempotentCandidateFollowupsPG(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("scan candidate escalation", "scan-ingest.example.com", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.DeleteTask(task.ID)
		_, _ = d.Exec(`DELETE FROM assets WHERE domain LIKE '%scan-ingest.example.com' OR url LIKE '%scan-ingest.example.com%'`)
	})
	store := d.Exploration(task.ExplorationID)
	tsx := NewToolSet(store, "worker-1")
	tsx.SetTaskID(task.ID)
	tsx.SetAssetStore(d.Assets(), d.Companies())
	dir := t.TempDir()
	tool := tsx.ingestScanOutput()
	ingest := func(name, format, content string) map[string]any {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		in, _ := json.Marshal(map[string]string{"format": format, "path": name})
		res, callErr := tool.Call(context.Background(), in, &actool.ToolContext{WorkingDir: dir})
		var out map[string]any
		if callErr != nil || res.IsError || json.Unmarshal([]byte(res.Flatten()), &out) != nil {
			t.Fatalf("%s: %v %s", format, callErr, res.Flatten())
		}
		return out
	}

	first := ingest("secrets.jsonl", "trufflehog-jsonl", truffleHogFixture)
	if first["followup_intents"] == nil {
		t.Fatalf("TruffleHog did not create a follow-up: %v", first)
	}
	second := ingest("secrets.jsonl", "trufflehog-jsonl", truffleHogFixture)
	if second["followup_intents"] == nil {
		t.Fatalf("repeat TruffleHog ingestion lost follow-up identity: %v", second)
	}
	ctFirst := ingest("ct.json", "ct-json", ctFixture)
	if ctFirst["followup_intents"] == nil {
		t.Fatalf("certificate-transparency ingestion did not create batch coverage work: %v", ctFirst)
	}
	ctSecond := ingest("ct.json", "ct-json", ctFixture)
	if ctSecond["followup_intents"] == nil {
		t.Fatalf("repeat certificate-transparency ingestion lost follow-up identity: %v", ctSecond)
	}
	anomaly := `{"url":"https://scan-ingest.example.com/","status_code":200,"title":"home pg5 ฝาก 1 รับ 50 now"}` + "\n"
	web := ingest("web.jsonl", "httpx-jsonl", anomaly)
	if web["followup_intents"] == nil {
		t.Fatalf("content anomaly did not create a follow-up: %v", web)
	}
	intents, err := store.ListByKind(db.KindIntent, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 5 {
		t.Fatalf("follow-up intents=%d want 5: %+v", len(intents), intents)
	}
	foundJS := false
	foundCT := false
	for _, intent := range intents {
		payload := string(intent.Payload)
		if intent.Origin != "scanner_escalator" || strings.Contains(payload, "ฝาก 1 รับ") {
			t.Fatalf("unsafe or malformed automated follow-up: %+v", intent)
		}
		switch {
		case strings.Contains(payload, "scan:httpx:javascript-api-discovery:"):
			if intent.Priority != 8 {
				t.Fatalf("JavaScript/API follow-up priority=%d want 8", intent.Priority)
			}
			foundJS = true
		case strings.Contains(payload, "scan:ct:dns-http-coverage:"):
			if intent.Priority != 8 || !strings.Contains(payload, "ownership") || !strings.Contains(payload, "task-scope") {
				t.Fatalf("CT batch follow-up is not gated or bounded: %+v", intent)
			}
			foundCT = true
		default:
			if intent.Priority != 10 {
				t.Fatalf("incident/secret follow-up priority=%d want 10: %+v", intent.Priority, intent)
			}
		}
	}
	if !foundJS {
		t.Fatal("HTML application did not create a JavaScript/API discovery follow-up")
	}
	if !foundCT {
		t.Fatal("certificate-transparency ingestion did not create gated batch coverage work")
	}
}

// ingest_scan_output (PG), credentials in URLs: no asset row and no fact keeps
// them, and the same URL with different credentials is one asset row and one
// fact.
func TestIngestScanOutputUserinfoPG(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("ingest_scan_output_userinfo", "scan-ingest.example.com", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const assetsWhere = `ip IN ('198.51.100.77','2001:db8::77') OR domain IN ('198.51.100.77','2001:db8::77','example.com') OR domain LIKE '%scan-ingest.example.com' OR url LIKE '%scan-ingest.example.com%'`
	t.Cleanup(func() {
		_ = d.DeleteTask(task.ID)
		_, _ = d.Exec(`DELETE FROM assets WHERE ` + assetsWhere)
	})
	store := d.Exploration(task.ExplorationID)
	tsx := NewToolSet(store, "worker-1")
	tsx.SetTaskID(task.ID)
	tsx.SetAssetStore(d.Assets(), d.Companies())
	dir := t.TempDir()
	tool := tsx.ingestScanOutput()
	ingest := func(format, content string) map[string]any {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "scan.out"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		in, _ := json.Marshal(map[string]string{"format": format, "path": "scan.out"})
		res, err := tool.Call(context.Background(), in, &actool.ToolContext{WorkingDir: dir})
		var out map[string]any
		if err != nil || res.IsError || json.Unmarshal([]byte(res.Flatten()), &out) != nil ||
			out["asset_errors"] != nil || out["fact_errors"] != nil {
			t.Fatalf("%s: %v %s", format, err, res.Flatten())
		}
		return out
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := d.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	out := ingest("httpx-jsonl", httpxUserinfoDedupFixture)
	if out["events"] != 2.0 || out["urls"] != 1.0 || out["facts_written"] != 1.0 || out["facts_existing"] != 1.0 {
		t.Fatalf("same URL, different credentials: %v", out)
	}
	const appURL = `SELECT count(*) FROM assets WHERE type='service' AND url='https://scan-ingest.example.com/app?id=7'`
	if n := count(appURL); n != 1 {
		t.Fatalf("%d asset rows for the normalised URL, want 1", n)
	}
	ingest("httpx-jsonl", httpxUserinfoFixture)
	ingest("ffuf-json", ffufUserinfoFixture)
	ingest("nuclei-jsonl", nucleiUserinfoFixture)
	if n := count(appURL); n != 1 {
		t.Fatalf("%d asset rows for the normalised URL after httpx and ffuf, want 1", n)
	}
	if n := count(`SELECT count(*) FROM assets a WHERE (` + assetsWhere + `) AND row_to_json(a)::text ~ 's3cr3t|scanuser|alice|bob'`); n != 0 {
		t.Fatalf("%d asset rows keep credentials", n)
	}
	facts, err := store.ListByKind(db.KindFact, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) == 0 {
		t.Fatal("no facts written")
	}
	for _, f := range facts {
		if hasScanCreds(string(f.Payload)) {
			t.Fatalf("fact keeps credentials: %s", f.Payload)
		}
	}
}
