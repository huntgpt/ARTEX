package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/redact"
	actool "github.com/Autumn-27/norma/tool"
)

var gitObjectIDRE = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

type secretSourceCandidate struct {
	Role   string `json:"role"`
	Masked string `json:"masked"`
	SHA256 string `json:"sha256"`
	Length int    `json:"length"`
	InFile bool   `json:"in_file"`
	InLine bool   `json:"in_line"`
}

type secretSourceProof struct {
	SecretID                  int64                   `json:"secret_id"`
	Detector                  string                  `json:"detector"`
	Repository                string                  `json:"repository"`
	RepositoryPath            string                  `json:"repository_path"`
	RepositoryOrigin          string                  `json:"repository_origin"`
	OriginMatchesLedger       bool                    `json:"origin_matches_ledger"`
	CommitHash                string                  `json:"commit_hash"`
	FilePath                  string                  `json:"file_path"`
	LineNumber                int                     `json:"line_number"`
	PinnedFileSHA256          string                  `json:"pinned_file_sha256"`
	LedgerFingerprintSHA256   string                  `json:"ledger_fingerprint_sha256"`
	RecomputedFingerprint     string                  `json:"recomputed_fingerprint_sha256"`
	FingerprintMatchesLedger  bool                    `json:"fingerprint_matches_ledger"`
	EncryptedPrimaryPresent   bool                    `json:"encrypted_primary_present"`
	EncryptedSecondaryPresent bool                    `json:"encrypted_secondary_present"`
	Candidates                []secretSourceCandidate `json:"candidates"`
	SourceExposureReproduced  bool                    `json:"source_exposure_reproduced"`
	CredentialValidity        string                  `json:"credential_validity"`
	AuthenticationAttempted   bool                    `json:"authentication_attempted"`
	PlaintextReturned         bool                    `json:"plaintext_returned"`
}

func sha256Text(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalizedGitRemote(value string) string {
	value = strings.TrimSpace(strings.TrimSuffix(value, "/"))
	return strings.TrimSuffix(value, ".git")
}

func secretValidationCandidates(primary, secondary string) []struct{ role, value string } {
	values := []struct{ role, value string }{{"raw", primary}, {"raw_v2", secondary}}
	if parsed, err := url.Parse(secondary); err == nil && parsed.User != nil {
		if username := parsed.User.Username(); username != "" {
			values = append(values, struct{ role, value string }{"url_username", username})
		}
		if password, ok := parsed.User.Password(); ok {
			values = append(values, struct{ role, value string }{"url_password", password})
		}
	}
	for _, field := range strings.FieldsFunc(secondary, func(r rune) bool { return r == ';' || r == '&' || r == '\n' || r == '\r' }) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "password", "pwd", "pass", "passwd":
			values = append(values, struct{ role, value string }{"password_field", strings.TrimSpace(value)})
		case "username", "user", "user id", "uid":
			values = append(values, struct{ role, value string }{"username_field", strings.TrimSpace(value)})
		}
	}
	seen := map[string]bool{}
	out := values[:0]
	for _, item := range values {
		// One-character detector captures and common delimiters are not useful
		// source-binding proof. Four characters is still deliberately permissive:
		// the proof is about committed exposure, not password strength.
		if len([]rune(item.value)) < 4 || seen[item.role+"\x00"+item.value] {
			continue
		}
		seen[item.role+"\x00"+item.value] = true
		out = append(out, item)
	}
	return out
}

func maskedSecretSourceCandidate(role, value string) string {
	if role == "raw_v2" {
		parsed, err := url.Parse(value)
		if err == nil && parsed.User != nil {
			if password, ok := parsed.User.Password(); ok {
				parsed.User = url.UserPassword(parsed.User.Username(), redact.Secret(password))
				return parsed.String()
			}
		}
	}
	return redact.Secret(value)
}

func validateSecretSourceMaterial(ctx context.Context, secret db.DiscoveredSecret, repoPath string) (secretSourceProof, error) {
	proof := secretSourceProof{
		SecretID: secret.ID, Detector: secret.Detector, Repository: secret.Repository,
		RepositoryPath: repoPath, CommitHash: secret.CommitHash, FilePath: secret.FilePath,
		LineNumber: secret.LineNumber, LedgerFingerprintSHA256: secret.SecretSHA256,
		EncryptedPrimaryPresent: secret.SecretValue != "", EncryptedSecondaryPresent: secret.SecretValueV2 != "",
		CredentialValidity: "not_tested", AuthenticationAttempted: false, PlaintextReturned: false,
	}
	if !gitObjectIDRE.MatchString(strings.TrimSpace(secret.CommitHash)) {
		return proof, errors.New("secret ledger commit hash is missing or invalid")
	}
	cleanFile := filepath.ToSlash(filepath.Clean(secret.FilePath))
	if cleanFile == "." || strings.HasPrefix(cleanFile, "../") || strings.HasPrefix(cleanFile, "/") || strings.ContainsRune(cleanFile, '\x00') {
		return proof, errors.New("secret ledger file path is not repository-relative")
	}
	git := func(args ...string) ([]byte, error) {
		commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return exec.CommandContext(commandCtx, "git", append([]string{"-C", repoPath}, args...)...).Output()
	}
	origin, err := git("remote", "get-url", "origin")
	if err != nil {
		return proof, errors.New("read repository origin: " + err.Error())
	}
	proof.RepositoryOrigin = strings.TrimSpace(string(origin))
	proof.OriginMatchesLedger = normalizedGitRemote(proof.RepositoryOrigin) == normalizedGitRemote(secret.Repository)
	pinned, err := git("show", secret.CommitHash+":"+cleanFile)
	if err != nil {
		return proof, errors.New("read pinned repository file: " + err.Error())
	}
	fileSum := sha256.Sum256(pinned)
	proof.PinnedFileSHA256 = hex.EncodeToString(fileSum[:])
	proof.RecomputedFingerprint = sha256Text(secret.SecretValue + "\x00" + secret.SecretValueV2)
	proof.FingerprintMatchesLedger = proof.RecomputedFingerprint == secret.SecretSHA256
	var sourceLine []byte
	if secret.LineNumber > 0 {
		lines := bytes.Split(pinned, []byte("\n"))
		if secret.LineNumber <= len(lines) {
			sourceLine = bytes.TrimSuffix(lines[secret.LineNumber-1], []byte("\r"))
		}
	}
	matched := false
	for _, item := range secretValidationCandidates(secret.SecretValue, secret.SecretValueV2) {
		candidate := secretSourceCandidate{
			Role: item.role, Masked: maskedSecretSourceCandidate(item.role, item.value), SHA256: sha256Text(item.value),
			Length: len([]rune(item.value)), InFile: bytes.Contains(pinned, []byte(item.value)),
			InLine: len(sourceLine) > 0 && bytes.Contains(sourceLine, []byte(item.value)),
		}
		if candidate.InFile && (secret.LineNumber <= 0 || candidate.InLine) && (item.role == "raw" || item.role == "raw_v2" || strings.Contains(item.role, "password")) {
			matched = true
		}
		proof.Candidates = append(proof.Candidates, candidate)
	}
	proof.SourceExposureReproduced = proof.OriginMatchesLedger && proof.FingerprintMatchesLedger && matched
	return proof, nil
}

func repositoryPathInsideTask(dataDir string, taskID int64, requested string) (string, error) {
	root, err := filepath.EvalSymlinks(filepath.Join(dataDir, "tasks", strconv.FormatInt(taskID, 10)))
	if err != nil {
		return "", errors.New("task workspace is unavailable")
	}
	requested, err = filepath.Abs(strings.TrimSpace(requested))
	if err != nil {
		return "", errors.New("invalid repository path")
	}
	resolved, err := filepath.EvalSymlinks(requested)
	if err != nil {
		return "", errors.New("repository path is unavailable")
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("repository path must stay inside the current task workspace")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("repository path is not a directory")
	}
	return resolved, nil
}

func (s *Server) toolValidateRetestDiscoveredSecretSource() actool.CoreTool {
	return wrTool("validate_discovered_secret_source", "Safely reproduce a discovered-secret source exposure from the current finding's task without returning plaintext or attempting authentication. Decrypts the selected vault record only in memory, verifies the ledger's Raw+NUL+RawV2 fingerprint, reads the exact pinned commit/file from a preserved repository inside the task workspace, and returns only hashes, final-30%-masked candidates, source-match booleans, and an audited conclusion.",
		objSchema(map[string]any{
			"secret_id":       map[string]any{"type": "integer", "minimum": 1},
			"repository_path": strParam("absolute path of the preserved local Git repository inside this task's workspace"),
		}, "secret_id", "repository_path"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var input struct {
				SecretID       int64  `json:"secret_id"`
				RepositoryPath string `json:"repository_path"`
			}
			if err := json.Unmarshal(in, &input); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			retest, err := s.m.pg.FindingRetestForConversation(ctx, intercept.ConvIDFromContext(ctx))
			if err != nil || retest == nil {
				return actool.Errorf("the current session is not associated with a retest record"), nil
			}
			finding, err := s.m.pg.GetFinding(retest.FindingID)
			if err != nil || finding == nil || finding.TaskID == nil {
				return actool.Errorf("the retest finding has no task provenance"), nil
			}
			repoPath, err := repositoryPathInsideTask(s.m.dir, *finding.TaskID, input.RepositoryPath)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			secret, err := s.m.pg.RevealDiscoveredSecret(*finding.TaskID, input.SecretID,
				"retester-conversation:"+strconv.FormatInt(intercept.ConvIDFromContext(ctx), 10), "validation-use",
				"bounded source-exposure reproduction for finding "+strconv.FormatInt(finding.ID, 10))
			if err != nil {
				return actool.Errorf("secret record is not part of the current finding task"), nil
			}
			proof, err := validateSecretSourceMaterial(ctx, secret, repoPath)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(proof)
		})
}
