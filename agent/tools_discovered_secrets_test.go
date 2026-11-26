package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestListDiscoveredSecretsSeparatesExposureFromCredentialValidity(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("secret evidence semantics", "example.com", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	if _, err := store.UpsertDiscoveredSecret(task.ID, db.DiscoveredSecretInput{
		Detector: "SQLServer", Repository: "https://github.com/example/repo.git",
		FilePath: "appsettings.json", CommitHash: strings.Repeat("a", 40),
		SecretValue: "P@ssw0rd", Verified: false,
	}); err != nil {
		t.Fatal(err)
	}
	tsx := NewToolSet(store, "worker-test")
	tsx.SetTaskID(task.ID)
	res, err := tsx.listDiscoveredSecrets().Call(context.Background(), nil, nil)
	if err != nil || res.IsError {
		t.Fatalf("list_discovered_secrets: %v %s", err, res.Flatten())
	}
	var out struct {
		Secrets []map[string]any `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil || len(out.Secrets) != 1 {
		t.Fatalf("parse result: %v %s", err, res.Flatten())
	}
	got := out.Secrets[0]
	if got["source_exposure_status"] != "raw_secret_material_encrypted_at_rest" ||
		got["credential_validity_status"] != "not_tested_or_not_verified" || got["verified"] != false {
		t.Fatalf("conflated exposure with credential validity: %#v", got)
	}
	if got["masked_preview"] != "P@ssw***" || strings.Contains(res.Flatten(), "P@ssw0rd") {
		t.Fatalf("masked preview is missing or plaintext leaked: %s", res.Flatten())
	}
}
