package db

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDiscoveredSecretEncryptedListMaskedAndRevealAudited(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	t.Setenv(secretKeyEnv, base64.StdEncoding.EncodeToString(testSecretKey))
	if err := d.InitSecrets(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("discovered secret", "example.com", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	created, err := d.UpsertDiscoveredSecret(task.ID, DiscoveredSecretInput{
		Detector: "Test", Repository: "repo", FilePath: "prod.env", LineNumber: 7,
		Verified: true, SecretValue: "P@ssw0rd", SecretValueV2: "secondary-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	var stored, storedV2 string
	if err := d.QueryRow(`SELECT secret_value,secret_value_v2 FROM discovered_secrets WHERE id=$1`, created.ID).Scan(&stored, &storedV2); err != nil {
		t.Fatal(err)
	}
	if !isEncrypted(stored) || !isEncrypted(storedV2) || strings.Contains(stored+storedV2, "P@ssw0rd") {
		t.Fatalf("secret is not encrypted at rest: %q %q", stored, storedV2)
	}
	listed, err := d.ListDiscoveredSecrets(task.ID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list = %+v, %v", listed, err)
	}
	if listed[0].SecretValue != "" || listed[0].SecretValueV2 != "" || listed[0].ScannerRedacted != "P@ssw***" {
		t.Fatalf("list leaked plaintext or used wrong mask: %+v", listed[0])
	}
	if !listed[0].EncryptedValuePresent || !listed[0].EncryptedValueV2Present {
		t.Fatalf("list did not prove encrypted payload presence: %+v", listed[0])
	}
	revealed, err := d.RevealDiscoveredSecret(task.ID, created.ID, "tester", "validation-use", "authorized validation")
	if err != nil || revealed.SecretValue != "P@ssw0rd" || revealed.SecretValueV2 != "secondary-token" {
		t.Fatalf("reveal = %+v, %v", revealed, err)
	}
	var actor, action, reason string
	if err := d.QueryRow(`SELECT actor,action,reason FROM secret_access_audit WHERE secret_id=$1`, created.ID).Scan(&actor, &action, &reason); err != nil {
		t.Fatal(err)
	}
	if actor != "tester" || action != "validation-use" || reason != "authorized validation" {
		t.Fatalf("audit = %q %q %q", actor, action, reason)
	}
}
