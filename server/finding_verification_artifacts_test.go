package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestFindingVerificationProfileCannotBeModelSelected(t *testing.T) {
	tests := []struct {
		class, name string
		want        findingVerificationClass
	}{
		{"source_exposure", "Credential committed to public repository", verificationSecret},
		{"network", "SMBv1 enabled on domain controller", verificationService},
		{"misconfiguration", "PTT hostname serves gambling content from a historical backend", verificationBrowser},
		{"sql_injection", "Login SQL injection", verificationExploitation},
	}
	for _, tt := range tests {
		f := &db.DBFinding{VulnClass: tt.class, Name: tt.name}
		if got := findingVerificationProfile(f); got != tt.want {
			t.Errorf("profile(%q/%q)=%q, want %q", tt.class, tt.name, got, tt.want)
		}
	}
}

func TestServiceVerificationRequiresIndependentFamiliesForSameTarget(t *testing.T) {
	f := &db.DBFinding{Name: "Legacy TLS on dc01.example.test", Evidence: "Observed at 10.0.0.10:636: TLSv1.0 enabled"}
	nmap := findingArtifactDTO{Kind: "terminal_capture", ToolUseID: "nmap-1", RawOutputSHA256: "a", Command: "nmap -sV -p636 10.0.0.10", activityDetail: "10.0.0.10 TLSv1.0 enabled"}
	nmapAgain := findingArtifactDTO{Kind: "terminal_capture", ToolUseID: "nmap-2", RawOutputSHA256: "b", Command: "nmap --script ssl-enum-ciphers -p636 10.0.0.10", activityDetail: "10.0.0.10 TLSv1.0 enabled"}
	quotes := []string{"TLSv1.0 enabled"}
	if status, _ := assessServiceVerification(f, []findingArtifactDTO{nmap, nmapAgain}, quotes); status == db.VerificationVerified {
		t.Fatal("two captures from the same scanner family were accepted as independent")
	}
	openssl := findingArtifactDTO{Kind: "terminal_capture", ToolUseID: "openssl-1", RawOutputSHA256: "c", Command: "openssl s_client -connect 10.0.0.10:636 -tls1", activityDetail: "connected to 10.0.0.10 with TLSv1"}
	openssl.activityDetail = "connected to 10.0.0.10; TLSv1.0 enabled"
	if status, note := assessServiceVerification(f, []findingArtifactDTO{nmap, openssl}, quotes); status != db.VerificationVerified || note != "" {
		t.Fatalf("independent service evidence=%s note=%q, want verified", status, note)
	}
	openssl.Command = "openssl s_client -connect 10.0.0.99:636 -tls1"
	openssl.activityDetail = "connected to 10.0.0.99"
	if status, _ := assessServiceVerification(f, []findingArtifactDTO{nmap, openssl}, quotes); status == db.VerificationVerified {
		t.Fatal("evidence for a different target was accepted")
	}
	openssl.Command = "openssl s_client -connect 10.0.0.10:636 -tls1"
	openssl.activityDetail = "connected to 10.0.0.10; TLSv1.3 clean"
	if status, _ := assessServiceVerification(f, []findingArtifactDTO{nmap, openssl}, quotes); status == db.VerificationVerified {
		t.Fatal("an unrelated clean handshake on the same target was accepted")
	}
	genericNmap := nmap
	genericNmap.activityDetail = "10.0.0.10 443/tcp open https"
	genericOpenSSL := openssl
	genericOpenSSL.activityDetail = "10.0.0.10 443/tcp open https"
	f.Evidence += "; 443/tcp open https"
	if status, _ := assessServiceVerification(f, []findingArtifactDTO{genericNmap, genericOpenSSL}, []string{"443/tcp open https"}); status == db.VerificationVerified {
		t.Fatal("generic port-open output verified a legacy TLS claim")
	}
}

func TestBrowserVerificationRequiresMatchingHashVerifiedHAR(t *testing.T) {
	dataDir := t.TempDir()
	ref := "tasks/7/browser-trace.json"
	path := filepath.Join(dataDir, "evidence", filepath.FromSlash(ref))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	har := []byte(`{"log":{"entries":[{"request":{"url":"https://route.example.test/login"},"response":{"status":200,"statusText":"OK","headers":[{"name":"server","value":"unexpected-backend"}],"content":{"text":"GAMBLING PORTAL"}}}]}}`)
	if err := os.WriteFile(path, har, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(har)
	trace := browserNetworkTrace{Ref: ref, SHA256: hex.EncodeToString(digest[:]), ByteSize: int64(len(har)), SourceURL: "https://route.example.test/", TraceFormat: "har"}
	detail, _ := json.Marshal(map[string]any{"network_trace": trace})
	artifact := findingArtifactDTO{Kind: "browser_screenshot", Tool: "playwright", SourceURL: trace.SourceURL, activityDetail: string(detail)}
	f := &db.DBFinding{Name: "Hostname serves unexpected web content", Evidence: "Observed route.example.test serving GAMBLING PORTAL from a real browser"}
	s := &Server{m: &Manager{dir: dataDir}}
	quotes := []string{"GAMBLING PORTAL"}
	if status, note := s.assessBrowserVerification(f, []findingArtifactDTO{artifact}, quotes); status != db.VerificationVerified || note != "" {
		t.Fatalf("browser evidence=%s note=%q, want verified", status, note)
	}
	trace.SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	detail, _ = json.Marshal(map[string]any{"network_trace": trace})
	artifact.activityDetail = string(detail)
	if status, _ := s.assessBrowserVerification(f, []findingArtifactDTO{artifact}, quotes); status == db.VerificationVerified {
		t.Fatal("tampered HAR digest was accepted")
	}
	trace.SHA256 = hex.EncodeToString(digest[:])
	detail, _ = json.Marshal(map[string]any{"network_trace": trace})
	artifact.activityDetail = string(detail)
	if status, _ := s.assessBrowserVerification(f, []findingArtifactDTO{artifact}, []string{"ADMIN DASHBOARD"}); status == db.VerificationVerified {
		t.Fatal("an unrelated same-host browser capture was accepted")
	}
	f.Evidence += "; generic response was 200 OK Server"
	if status, _ := s.assessBrowserVerification(f, []findingArtifactDTO{artifact}, []string{"200 OK Server"}); status == db.VerificationVerified {
		t.Fatal("a generic same-host 200 response verified an anomalous-content claim")
	}
}

func TestSecretExposureVerificationRequiresExactSourceHashCapture(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer pg.Close()
	if err := pg.InitSecrets(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTask("secret verification", "verify exact source", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	secret, err := pg.UpsertDiscoveredSecret(task.ID, db.DiscoveredSecretInput{
		Detector: "postgres", SourceType: "git", Repository: "https://github.com/acme/dispenser.git",
		FilePath: "config/database.yml", CommitHash: "0123456789abcdef0123456789abcdef01234567", SecretValue: "secret-value",
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &db.DBFinding{TaskID: &task.ID, Name: "Credential committed to public Dispenser repository",
		Evidence: "https://github.com/acme/dispenser.git config/database.yml commit 0123456789abcdef0123456789abcdef01234567"}
	captureText := "https://github.com/acme/dispenser.git config/database.yml 0123456789abcdef0123456789abcdef01234567 " + secret.SecretSHA256
	artifact := findingArtifactDTO{Kind: "terminal_capture", Command: `test "$(git config --get remote.origin.url)" = "https://github.com/acme/dispenser.git" && git show 0123456789abcdef0123456789abcdef01234567:config/database.yml | sha256sum`, activityDetail: captureText}
	s := &Server{m: &Manager{pg: pg}}
	if status, note := s.assessSecretExposureVerification(f, []findingArtifactDTO{artifact}); status != db.VerificationVerified || note != "" {
		t.Fatalf("secret evidence=%s note=%q, want verified", status, note)
	}
	artifact.activityDetail = "same source but no digest"
	if status, _ := s.assessSecretExposureVerification(f, []findingArtifactDTO{artifact}); status == db.VerificationVerified {
		t.Fatal("source capture without the exact secret digest was accepted")
	}
	artifact.activityDetail = captureText
	artifact.Command = `test "$(git config --get remote.origin.url)" = "https://github.com/acme/dispenser.git" && git show 0123456789abcdef0123456789abcdef01234567:config/database.yml; echo ` + secret.SecretSHA256
	if status, _ := s.assessSecretExposureVerification(f, []findingArtifactDTO{artifact}); status == db.VerificationVerified {
		t.Fatal("model-manufactured digest output was accepted as a source capture")
	}
	artifact.Command = "git config --get remote.origin.url && git show 0123456789abcdef0123456789abcdef01234567:config/database.yml | sha256sum # https://github.com/acme/dispenser.git"
	if status, _ := s.assessSecretExposureVerification(f, []findingArtifactDTO{artifact}); status == db.VerificationVerified {
		t.Fatal("an origin URL printed but not checked was accepted as clone provenance")
	}
	artifact.Command = "curl https://raw.githubusercontent.com/acme/dispenser/0123456789abcdef0123456789abcdef01234567/config/database.yml | sha256sum"
	if status, note := s.assessSecretExposureVerification(f, []findingArtifactDTO{artifact}); status != db.VerificationVerified || note != "" {
		t.Fatalf("commit-pinned repository source evidence=%s note=%q, want verified", status, note)
	}
	artifact.Command = "curl https://evil.example/acme/dispenser/0123456789abcdef0123456789abcdef01234567/config/database.yml | sha256sum"
	artifact.activityDetail = captureText
	if status, _ := s.assessSecretExposureVerification(f, []findingArtifactDTO{artifact}); status == db.VerificationVerified {
		t.Fatal("an unrelated host reusing the repository path was accepted as the source")
	}
}
