package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func supervisorProfiles(t *testing.T, d *DB) (int64, int64) {
	t.Helper()
	stamp := time.Now().UnixNano()
	first, err := d.SaveProfile(&LLMProfile{Name: fmt.Sprintf("supervisor-codex-%d", stamp), Format: "codex-cli", Model: "codex-test", CLIPath: "/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.SaveProfile(&LLMProfile{Name: fmt.Sprintf("supervisor-claude-%d", stamp), Format: "claude-cli", Model: "claude-test", CLIPath: "/bin/true"})
	if err != nil {
		cleanupProfile(t, d, first)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupProfile(t, d, first)
		cleanupProfile(t, d, second)
	})
	return first, second
}

func TestNormalizeTaskSupervisorConfig(t *testing.T) {
	first, second := int64(10), int64(11)
	dual, err := NormalizeTaskSupervisorConfig(&TaskSupervisorConfig{
		Mode: SupervisorModeDual, PrimaryProfileID: &first, SecondaryProfileID: &second,
	})
	if err != nil || dual.CheckpointPolicy != SupervisorCheckpointStrategic {
		t.Fatalf("normalized dual = %+v, %v", dual, err)
	}
	for _, input := range []*TaskSupervisorConfig{
		{Mode: SupervisorModeDual, PrimaryProfileID: &first},
		{Mode: SupervisorModeDual, PrimaryProfileID: &first, SecondaryProfileID: &first},
		{Mode: SupervisorModeSingle, PrimaryProfileID: &first, SecondaryProfileID: &second},
		{Mode: "many", PrimaryProfileID: &first},
		{Mode: SupervisorModeSingle, PrimaryProfileID: &first, CheckpointPolicy: "sometimes"},
	} {
		if _, err := NormalizeTaskSupervisorConfig(input); !errors.Is(err, ErrSupervisorConfigInvalid) {
			t.Errorf("config %+v error = %v, want ErrSupervisorConfigInvalid", input, err)
		}
	}
}

func TestTaskSupervisorConfigRoundTripAndRevision(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	first, second := supervisorProfiles(t, d)
	cfg := &TaskSupervisorConfig{
		Mode: SupervisorModeDual, PrimaryProfileID: &first, SecondaryProfileID: &second,
		CheckpointPolicy: SupervisorCheckpointEveryRound,
	}
	task, err := d.CreateTaskWithOptions("dual lead", "review independently", TaskCreateOptions{Supervisor: cfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	if task.Supervisor.Mode != SupervisorModeDual || task.Supervisor.PrimaryProfileID == nil || *task.Supervisor.PrimaryProfileID != first {
		t.Fatalf("create config = %+v", task.Supervisor)
	}
	loaded, err := d.GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Supervisor.SecondaryProfileID == nil || *loaded.Supervisor.SecondaryProfileID != second {
		t.Fatalf("hydrated config = %+v", loaded.Supervisor)
	}
	single := &TaskSupervisorConfig{Mode: SupervisorModeSingle, PrimaryProfileID: &second, CheckpointPolicy: SupervisorCheckpointManual}
	updated, err := d.ReplaceTaskSupervisorConfig(task.ID, single)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Mode != SupervisorModeSingle || updated.SecondaryProfileID != nil {
		t.Fatalf("updated config = %+v", updated)
	}
	missing := int64(1 << 61)
	if _, err := d.ReplaceTaskSupervisorConfig(task.ID, &TaskSupervisorConfig{Mode: SupervisorModeSingle, PrimaryProfileID: &missing}); !errors.Is(err, ErrSupervisorProfileAbsent) {
		t.Fatalf("missing profile error = %v", err)
	}
}

func TestTaskSupervisorRejectsDuplicateProviderModelAccount(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	stamp := time.Now().UnixNano()
	makeProfile := func(suffix, configDir string) int64 {
		t.Helper()
		id, err := d.SaveProfile(&LLMProfile{
			Name: fmt.Sprintf("same-claude-%s-%d", suffix, stamp), Format: "claude-cli",
			Model: "claude-same", CLIPath: "/bin/true", CLIConfigDir: configDir,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cleanupProfile(t, d, id) })
		return id
	}
	first := makeProfile("one", "")
	second := makeProfile("two", "")
	task, err := d.CreateTaskWithOptions("duplicate leads", "reject aliases", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	_, err = d.ReplaceTaskSupervisorConfig(task.ID, &TaskSupervisorConfig{
		Mode: SupervisorModeDual, PrimaryProfileID: &first, SecondaryProfileID: &second,
	})
	if !errors.Is(err, ErrSupervisorProfilesNotIndependent) {
		t.Fatalf("duplicate account error = %v, want ErrSupervisorProfilesNotIndependent", err)
	}

	isolated := makeProfile("isolated", fmt.Sprintf("/tmp/artex-claude-%d", stamp))
	cfg, err := d.ReplaceTaskSupervisorConfig(task.ID, &TaskSupervisorConfig{
		Mode: SupervisorModeDual, PrimaryProfileID: &first, SecondaryProfileID: &isolated,
	})
	if err != nil || cfg.Mode != SupervisorModeDual {
		t.Fatalf("isolated profiles rejected: cfg=%+v err=%v", cfg, err)
	}
}

func TestSupervisorSnapshotCanonicalHashAndSecretScrub(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	first, _ := supervisorProfiles(t, d)
	task, err := d.CreateTaskWithOptions("snapshot integrity", "store no plaintext", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	snapshot := map[string]any{
		"task_id": task.ID,
		"goal":    "validate password=P@ssw0rd and Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
		"nested": map[string]any{
			"access_token": "oauth-super-secret",
			"summary":      "repository used sk-ant-abcdefghijklmnopqrst and https://user:pass@example.test/path",
		},
		"pem": "-----BEGIN PRIVATE KEY-----\nsynthetic-private-material\n-----END PRIVATE KEY-----",
	}
	round, err := d.CreateSupervisorRound(task.ID, "manual", snapshot, []SupervisorReviewSeed{
		{LeadRole: "primary", ProfileID: first, Provider: "codex-cli", Model: "codex-test", AccountLabel: "Codex A"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{"P@ssw0rd", "abcdefghijklmnopqrstuvwxyz", "oauth-super-secret", "sk-ant-abcdefghijklmnopqrst", "user:pass", "synthetic-private-material"} {
		if strings.Contains(string(round.Snapshot), plaintext) {
			t.Fatalf("plaintext %q escaped snapshot scrub: %s", plaintext, round.Snapshot)
		}
	}
	if !strings.Contains(string(round.Snapshot), "[REDACTED]") {
		t.Fatalf("snapshot has no redaction marker: %s", round.Snapshot)
	}

	var storedText string
	if err := d.QueryRow(`SELECT snapshot::text FROM supervisor_rounds WHERE id=$1`, round.ID).Scan(&storedText); err != nil {
		t.Fatal(err)
	}
	stored := json.RawMessage(storedText)
	storedHash, err := SupervisorSnapshotHash(stored)
	if err != nil {
		t.Fatal(err)
	}
	if storedHash != round.SnapshotHash {
		t.Fatalf("JSONB round-trip hash = %s, want %s; stored=%s", storedHash, round.SnapshotHash, stored)
	}
	if err := VerifySupervisorSnapshot(stored, round.SnapshotHash); err != nil {
		t.Fatalf("verify stored snapshot: %v", err)
	}
	if err := VerifySupervisorSnapshot(json.RawMessage(`{"task_id":999}`), round.SnapshotHash); err == nil {
		t.Fatal("tampered snapshot unexpectedly verified")
	}
	if _, err := d.SupervisorRoundDetails(task.ID, 10); err != nil {
		t.Fatalf("round details rejected valid JSONB hash: %v", err)
	}
}

func TestSupervisorRoundSameSnapshotReviewsDecisionAndCascade(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	first, second := supervisorProfiles(t, d)
	task, err := d.CreateTaskWithOptions("dual review", "one canonical decision", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := map[string]any{"task_id": task.ID, "facts": []any{"a", "b"}, "frontier_open": 0}
	round, err := d.CreateSupervisorRound(task.ID, "task_start", snapshot, []SupervisorReviewSeed{
		{LeadRole: "primary", ProfileID: first, Provider: "codex-cli", Model: "codex-test", AccountLabel: "Codex A"},
		{LeadRole: "secondary", ProfileID: second, Provider: "claude-cli", Model: "claude-test", AccountLabel: "Claude B"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(round.Snapshot)
	if round.SnapshotHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("snapshot hash = %s, want %x", round.SnapshotHash, sum)
	}
	if err := d.StartSupervisorRound(round.ID); err != nil {
		t.Fatal(err)
	}
	primary := json.RawMessage(`{"assessment":"route A","directions":["one"]}`)
	secondary := json.RawMessage(`{"assessment":"route B","directions":["two"]}`)
	if err := d.CompleteSupervisorReview(round.ID, "primary", primary, "route A", "", 10, 5); err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteSupervisorReview(round.ID, "secondary", secondary, "route B", "", 12, 6); err != nil {
		t.Fatal(err)
	}
	decision := json.RawMessage(`{"selected_directions":["one","two"],"conflicts":[]}`)
	if err := d.SaveSupervisorDecision(round.ID, &first, decision, "both are independent"); err != nil {
		t.Fatal(err)
	}
	details, err := d.SupervisorRoundDetails(task.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(details) != 1 || details[0].State != "completed" || len(details[0].Reviews) != 2 || details[0].Decision == nil {
		t.Fatalf("round details = %+v", details)
	}
	if err := d.DeleteTask(task.ID); err != nil {
		t.Fatal(err)
	}
	var rounds int
	if err := d.QueryRow(`SELECT count(*) FROM supervisor_rounds WHERE task_id=$1`, task.ID).Scan(&rounds); err != nil || rounds != 0 {
		t.Fatalf("cascade rounds = %d, err=%v", rounds, err)
	}
}
