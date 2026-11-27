package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestValidateSecretSourceMaterialUsesCompositeLedgerFingerprint(t *testing.T) {
	repo := t.TempDir()
	gitOutput(t, repo, "init")
	gitOutput(t, repo, "config", "user.email", "artex-test@example.invalid")
	gitOutput(t, repo, "config", "user.name", "ARTEX Test")
	gitOutput(t, repo, "remote", "add", "origin", "https://github.com/example/gaia.git")

	file := "GaiaManagement/PostgresContext.cs"
	password := "PostgresProof42!"
	secondary := "postgresql://gaia:" + password + "@localhost:5432/gaia"
	if err := os.MkdirAll(filepath.Join(repo, "GaiaManagement"), 0o700); err != nil {
		t.Fatal(err)
	}
	source := `services.AddNpgsql("Host=localhost;Port=5432;Username=gaia;Password=` + password + `;Database=gaia");` + "\n"
	if err := os.WriteFile(filepath.Join(repo, filepath.FromSlash(file)), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	gitOutput(t, repo, "add", file)
	gitOutput(t, repo, "commit", "-m", "fixture")
	commit := gitOutput(t, repo, "rev-parse", "HEAD")
	primary := ":"
	fingerprint := sha256.Sum256([]byte(primary + "\x00" + secondary))

	proof, err := validateSecretSourceMaterial(context.Background(), db.DiscoveredSecret{
		ID: 12, Detector: "SQLServer", Repository: "https://github.com/example/gaia",
		FilePath: file, LineNumber: 1, CommitHash: commit,
		SecretValue: primary, SecretValueV2: secondary, SecretSHA256: hex.EncodeToString(fingerprint[:]),
	}, repo)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.OriginMatchesLedger || !proof.FingerprintMatchesLedger || !proof.SourceExposureReproduced {
		t.Fatalf("source proof did not reproduce: %+v", proof)
	}
	if proof.AuthenticationAttempted || proof.PlaintextReturned || proof.CredentialValidity != "not_tested" {
		t.Fatalf("validation exceeded static source reproduction: %+v", proof)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), password) || !strings.Contains(string(raw), "PostgresPro*****") {
		t.Fatalf("proof did not apply final-30-percent masking: %s", raw)
	}
}

func TestRepositoryPathInsideTaskRejectsSibling(t *testing.T) {
	dataDir := t.TempDir()
	inside := filepath.Join(dataDir, "tasks", "7", "repo")
	sibling := filepath.Join(dataDir, "tasks", "8", "repo")
	for _, path := range []string{inside, sibling} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := repositoryPathInsideTask(dataDir, 7, inside); err != nil || got != expected {
		t.Fatalf("inside path=%q err=%v", got, err)
	}
	if _, err := repositoryPathInsideTask(dataDir, 7, sibling); err == nil {
		t.Fatal("sibling task workspace was accepted")
	}
}
