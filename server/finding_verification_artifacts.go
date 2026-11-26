package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

type findingVerificationClass string

const (
	verificationExploitation findingVerificationClass = "exploitation"
	verificationSecret       findingVerificationClass = "secret_exposure"
	verificationService      findingVerificationClass = "service_scan"
	verificationBrowser      findingVerificationClass = "browser_routing"
)

var (
	verificationIPv4RE   = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	verificationDomainRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	verificationCVERe    = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)
	sourceURLRE          = regexp.MustCompile(`https?://[^\s'\"<>]+`)
	outputPrimitiveRE    = regexp.MustCompile(`(?i)(?:^|[;&|()\s])(?:echo|printf|python3?|perl|ruby|node)(?:\s|$)`)
	genericHTTPQuoteRE   = regexp.MustCompile(`(?i)^(?:http/[0-9.]+\s+)?[1-5][0-9]{2}(?:\s+[a-z][a-z ]*)?$`)
)

// findingVerificationProfile is deliberately derived from the vulnerability
// title/class, not selected by the model. A report cannot downgrade itself to
// an easier evidence policy by changing a tool argument.
func findingVerificationProfile(f *db.DBFinding) findingVerificationClass {
	if f == nil {
		return verificationExploitation
	}
	head := strings.ToLower(strings.Join([]string{f.VulnClass, f.Name}, " "))
	if containsAny(head, "secret", "credential", "password", "private key", "api key", "access token") &&
		containsAny(head, "public", "repository", "repo", "commit", "source", "hard-coded", "hardcoded") {
		return verificationSecret
	}
	if containsAny(head, "smb", "tls", "ssl", "cipher", "certificate", "ldaps", "global catalog", "service protocol") {
		return verificationService
	}
	if containsAny(head, "browser", "routing", "misrouting", "hostname serves", "web content", "website content", "gambling content", "historical backend") {
		return verificationBrowser
	}
	return verificationExploitation
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func (s *Server) assessArtifactFindingVerification(f *db.DBFinding, quotes []string) (status, note string) {
	artifacts, err := s.findingArtifacts(f.ID)
	if err != nil {
		return db.VerificationNotAssessed, "artifact evidence read error: " + err.Error()
	}
	switch findingVerificationProfile(f) {
	case verificationSecret:
		return s.assessSecretExposureVerification(f, artifacts)
	case verificationService:
		return assessServiceVerification(f, artifacts, quotes)
	case verificationBrowser:
		return s.assessBrowserVerification(f, artifacts, quotes)
	default:
		return "", ""
	}
}

func (s *Server) assessSecretExposureVerification(f *db.DBFinding, artifacts []findingArtifactDTO) (status, note string) {
	if f.TaskID == nil {
		return db.VerificationNotAssessed, "secret finding has no task provenance"
	}
	secrets, err := s.m.pg.ListDiscoveredSecrets(*f.TaskID)
	if err != nil {
		return db.VerificationNotAssessed, "secret ledger read error: " + err.Error()
	}
	findingText := strings.ToLower(strings.Join([]string{f.Name, f.Summary, f.Evidence, f.Report}, "\n"))
	for _, secret := range secrets {
		if !validSecretSource(secret) || !secretSourceMatchesFinding(secret, findingText) {
			continue
		}
		for _, artifact := range artifacts {
			if artifact.Kind != "terminal_capture" || !exactSourceCaptureCommand(secret, artifact.Command) {
				continue
			}
			captured := strings.ToLower(artifact.Command + "\n" + artifact.activityDetail)
			if sourceTextContains(secret, captured) {
				return db.VerificationVerified, ""
			}
		}
	}
	return db.VerificationUnverified, "secret exposure needs an exact commit/file/secret-hash source capture linked to this finding"
}

func validSecretSource(secret db.DiscoveredSecret) bool {
	return strings.TrimSpace(secret.Repository) != "" && strings.TrimSpace(secret.FilePath) != "" &&
		len(strings.TrimSpace(secret.CommitHash)) >= 7 && len(secret.SecretSHA256) == 64
}

func secretSourceMatchesFinding(secret db.DiscoveredSecret, text string) bool {
	return sourceValueInText(secret.Repository, text, true) &&
		sourceValueInText(secret.FilePath, text, false) &&
		strings.Contains(text, strings.ToLower(strings.TrimSpace(secret.CommitHash)))
}

func sourceTextContains(secret db.DiscoveredSecret, text string) bool {
	return sourceValueInText(secret.Repository, text, true) &&
		sourceValueInText(secret.FilePath, text, false) &&
		strings.Contains(text, strings.ToLower(strings.TrimSpace(secret.CommitHash))) &&
		strings.Contains(text, strings.ToLower(secret.SecretSHA256))
}

func sourceValueInText(value, text string, allowBase bool) bool {
	value = strings.ToLower(strings.Trim(strings.TrimSpace(value), "/"))
	if value == "" {
		return false
	}
	if strings.Contains(text, value) {
		return true
	}
	if !allowBase {
		return false
	}
	base := strings.TrimSuffix(filepath.Base(value), ".git")
	return len(base) >= 3 && strings.Contains(text, base)
}

func exactSourceCaptureCommand(secret db.DiscoveredSecret, command string) bool {
	command = strings.ToLower(strings.TrimSpace(command))
	// A terminal renderer proves which bytes a shell returned, not that a model
	// did not manufacture those bytes. Refuse common output-generation/eval
	// primitives and require the source fetch to hash its extracted value in the
	// same audited command.
	if outputPrimitiveRE.MatchString(command) || strings.Contains(command, "<<") {
		return false
	}
	if !containsAny(command, "sha256sum", "shasum -a 256", "openssl dgst -sha256") {
		return false
	}
	commit := strings.ToLower(strings.TrimSpace(secret.CommitHash))
	file := strings.ToLower(strings.Trim(strings.TrimSpace(secret.FilePath), "/"))
	if commit == "" || file == "" || !strings.Contains(command, commit) || !strings.Contains(command, file) {
		return false
	}
	repoURL, repoHost, repoPath, ok := normalizedRepositorySource(secret.Repository)
	if !ok {
		return false
	}
	switch {
	case strings.Contains(command, "git show"), strings.Contains(command, "git cat-file"), strings.Contains(command, "git archive"):
		return exactGitOriginCheck(command, repoURL)
	case strings.Contains(command, "gh api"):
		return repoHost == "github.com" && strings.Contains(command, "repos/"+repoPath+"/contents/"+file) &&
			(strings.Contains(command, "ref="+commit) || strings.Contains(command, "ref "+commit))
	case strings.Contains(command, "curl "), strings.Contains(command, "wget "):
		return commandContainsPinnedSourceURL(command, repoHost, repoPath, commit, file)
	default:
		return false
	}
}

func exactGitOriginCheck(command, repository string) bool {
	quoted := []string{`"` + repository + `"`, `'` + repository + `'`, repository}
	for _, origin := range []string{"git config --get remote.origin.url", "git remote get-url origin"} {
		substitution := `"$(` + origin + `)"`
		for _, repo := range quoted {
			if strings.Contains(command, "test "+substitution+" = "+repo) ||
				strings.Contains(command, "[ "+substitution+" = "+repo+" ]") ||
				strings.Contains(command, "[[ "+substitution+" = "+repo+" ]]") ||
				strings.Contains(command, origin+" | grep -fx "+repo) ||
				strings.Contains(command, origin+" | grep --fixed-strings --line-regexp "+repo) {
				return true
			}
		}
	}
	return false
}

func normalizedRepositorySource(repository string) (full, host, path string, ok bool) {
	repository = strings.TrimSpace(repository)
	u, err := url.Parse(repository)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", "", "", false
	}
	host = strings.ToLower(u.Hostname())
	path = strings.TrimSuffix(strings.ToLower(strings.Trim(u.Path, "/")), ".git")
	if path == "" {
		return "", "", "", false
	}
	u.RawQuery, u.Fragment = "", ""
	return strings.ToLower(strings.TrimSuffix(u.String(), "/")), host, path, true
}

func commandContainsPinnedSourceURL(command, repoHost, repoPath, commit, file string) bool {
	for _, raw := range sourceURLRE.FindAllString(command, -1) {
		u, err := url.Parse(strings.TrimRight(raw, ".,;)]}"))
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		path := strings.ToLower(strings.Trim(u.Path, "/"))
		query := strings.ToLower(u.RawQuery)
		if repoHost == "github.com" {
			switch host {
			case "raw.githubusercontent.com":
				if strings.Contains(path, repoPath+"/"+commit+"/"+file) {
					return true
				}
			case "github.com":
				if strings.Contains(path, repoPath+"/blob/"+commit+"/"+file) || strings.Contains(path, repoPath+"/raw/"+commit+"/"+file) {
					return true
				}
			case "api.github.com":
				if strings.Contains(path, "repos/"+repoPath+"/contents/"+file) && strings.Contains(query, "ref="+commit) {
					return true
				}
			}
			continue
		}
		if host == repoHost && strings.Contains(path, repoPath) && strings.Contains(path+"?"+query, commit) && strings.Contains(path, file) {
			return true
		}
	}
	return false
}

func assessServiceVerification(f *db.DBFinding, artifacts []findingArtifactDTO, quotes []string) (status, note string) {
	indicators := findingNetworkIndicators(f)
	if len(indicators) == 0 {
		return db.VerificationUnverified, "service finding has no concrete host/IP indicator"
	}
	families := map[string]bool{}
	seenRuns := map[string]bool{}
	claimIndicators := serviceClaimIndicators(f)
	if len(claimIndicators) == 0 {
		return db.VerificationUnverified, "service finding needs a class-derived defect indicator (protocol, cipher, certificate, SMB setting, or CVE)"
	}
	checkedQuotes := findingAnchoredQuotes(f, quotes, false)
	if len(checkedQuotes) == 0 {
		return db.VerificationUnverified, "service finding needs an exact finding-anchored defect quote from signed command output"
	}
	for _, artifact := range artifacts {
		if artifact.Kind != "terminal_capture" || artifact.ToolUseID == "" || artifact.RawOutputSHA256 == "" {
			continue
		}
		family := serviceCommandFamily(artifact.Command)
		if family == "" || !artifactDetailContainsAny(artifact, indicators) ||
			!artifactDetailContainsAny(artifact, claimIndicators) || !quoteInArtifactDetail(artifact, checkedQuotes) {
			continue
		}
		runKey := artifact.ToolUseID + "\x00" + artifact.RawOutputSHA256
		if seenRuns[runKey] {
			continue
		}
		seenRuns[runKey] = true
		families[family] = true
	}
	if len(families) < 2 {
		return db.VerificationUnverified, "service finding needs two independent signed scan/handshake captures for the same host"
	}
	return db.VerificationVerified, ""
}

func serviceClaimIndicators(f *db.DBFinding) []string {
	text := strings.ToLower(normalizeEvidenceText(strings.Join([]string{f.VulnClass, f.Name, f.Summary, f.Evidence}, "\n")))
	var out []string
	add := func(values ...string) {
		for _, value := range values {
			value = strings.ToLower(normalizeEvidenceText(value))
			if value != "" && !containsString(out, value) {
				out = append(out, value)
			}
		}
	}
	for _, cve := range verificationCVERe.FindAllString(text, -1) {
		add(cve)
	}
	if containsAny(text, "smbv1", "smb v1", "smb1", "smb 1.0") {
		add("smbv1", "smb v1", "smb1", "smb 1.0", "nt lm 0.12")
	}
	if strings.Contains(text, "smb") && containsAny(text, "signing disabled", "signing not required", "message signing") {
		add("signing disabled", "signing:disabled", "signing not required", "signing required: false", "signing:false")
	}
	if strings.Contains(text, "tls") || strings.Contains(text, "ssl") {
		for _, version := range []string{"sslv2", "ssl v2", "sslv3", "ssl v3", "tlsv1.0", "tls 1.0", "tlsv1.1", "tls 1.1"} {
			if strings.Contains(text, version) || containsAny(text, "legacy tls", "obsolete tls", "deprecated tls") {
				add(version)
			}
		}
		for _, cipher := range []string{"rc4", "3des", "des-cbc", "null cipher", "export cipher", "anonymous cipher"} {
			if strings.Contains(text, cipher) {
				add(cipher)
			}
		}
	}
	if containsAny(text, "certificate mismatch", "hostname mismatch", "name mismatch", "certificate does not match") {
		add("hostname mismatch", "name mismatch", "does not match", "verify error:num=62")
	}
	if containsAny(text, "expired certificate", "certificate expired", "expired tls") {
		add("certificate has expired", "certificate expired", "verify error:num=10")
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func serviceCommandFamily(command string) string {
	c := strings.ToLower(" " + command + " ")
	for _, item := range []struct{ needle, family string }{
		{" nmap ", "nmap"}, {" testssl", "testssl"}, {" sslscan", "sslscan"},
		{" openssl ", "openssl"}, {" smbclient ", "smbclient"}, {" rpcclient ", "rpcclient"},
		{" netexec ", "netexec"}, {" crackmapexec ", "crackmapexec"}, {" ldapsearch ", "ldapsearch"},
	} {
		if strings.Contains(c, item.needle) {
			return item.family
		}
	}
	return ""
}

func findingNetworkIndicators(f *db.DBFinding) []string {
	text := strings.Join([]string{f.Name, f.Summary, f.Evidence}, "\n")
	seen := map[string]bool{}
	var out []string
	for _, raw := range append(verificationIPv4RE.FindAllString(text, -1), verificationDomainRE.FindAllString(text, -1)...) {
		indicator := strings.ToLower(strings.TrimSpace(raw))
		if ip := net.ParseIP(indicator); ip == nil && strings.Count(indicator, ".") == 0 {
			continue
		}
		if !seen[indicator] {
			seen[indicator] = true
			out = append(out, indicator)
		}
	}
	return out
}

func artifactDetailContainsAny(artifact findingArtifactDTO, indicators []string) bool {
	text := strings.ToLower(normalizeEvidenceText(artifact.activityDetail))
	for _, indicator := range indicators {
		if strings.Contains(text, strings.ToLower(normalizeEvidenceText(indicator))) {
			return true
		}
	}
	return false
}

func findingAnchoredQuotes(f *db.DBFinding, quotes []string, browser bool) []string {
	findingText := normalizeEvidenceText(strings.Join([]string{f.Name, f.Summary, f.Evidence, f.Report}, "\n"))
	var out []string
	for _, quote := range usableArtifactQuotes(quotes) {
		if !strings.Contains(findingText, quote) || (browser && genericBrowserQuote(f, quote)) {
			continue
		}
		out = append(out, quote)
	}
	return out
}

func genericBrowserQuote(f *db.DBFinding, quote string) bool {
	q := strings.TrimSpace(strings.ToLower(quote))
	claim := strings.ToLower(strings.Join([]string{f.VulnClass, f.Name, f.Summary}, " "))
	if genericHTTPQuoteRE.MatchString(q) {
		return !containsAny(claim, "status", "response code", "redirect")
	}
	if strings.HasPrefix(q, "server:") {
		return !containsAny(claim, "backend", "fingerprint", "server") || containsAny(q, "server: nginx", "server: apache")
	}
	if strings.HasPrefix(q, "content-type:") {
		return !containsAny(claim, "content type", "content-type", "mime")
	}
	if containsAny(q, "content-length:", "cache-control:", "connection:", "date:", "etag:", "last-modified:") {
		return true
	}
	return q == "text/html" || q == "application/json" || q == "nginx" || q == "apache"
}

func usableArtifactQuotes(quotes []string) []string {
	var out []string
	for _, quote := range quotes {
		q := normalizeEvidenceText(quote)
		if len([]rune(q)) >= verificationMinQuoteRunes {
			out = append(out, q)
		}
	}
	return out
}

func quoteInArtifactDetail(artifact findingArtifactDTO, quotes []string) bool {
	detail := normalizeEvidenceText(artifact.activityDetail)
	for _, quote := range quotes {
		if strings.Contains(detail, quote) {
			return true
		}
	}
	return false
}

type browserNetworkTrace struct {
	Ref         string `json:"ref"`
	SHA256      string `json:"sha256"`
	ByteSize    int64  `json:"byte_size"`
	SourceURL   string `json:"source_url"`
	TraceFormat string `json:"trace_format"`
}

func (s *Server) assessBrowserVerification(f *db.DBFinding, artifacts []findingArtifactDTO, quotes []string) (status, note string) {
	text := strings.ToLower(strings.Join([]string{f.Name, f.Summary, f.Evidence, f.Report}, "\n"))
	checkedQuotes := findingAnchoredQuotes(f, quotes, true)
	if len(checkedQuotes) == 0 {
		return db.VerificationUnverified, "browser/routing finding needs a non-generic anomalous response quote anchored in the finding and signed HAR"
	}
	for _, artifact := range artifacts {
		if artifact.Kind != "browser_screenshot" || artifact.Tool != "playwright" || artifact.SourceURL == "" {
			continue
		}
		u, err := url.Parse(artifact.SourceURL)
		if err != nil || u.Hostname() == "" || !strings.Contains(text, strings.ToLower(u.Hostname())) {
			continue
		}
		trace, ok := browserTraceFromActivity(artifact.activityDetail)
		if !ok || trace.TraceFormat != "har" || trace.SourceURL != artifact.SourceURL {
			continue
		}
		if s.validBrowserHAR(trace, u.Hostname(), checkedQuotes) {
			return db.VerificationVerified, ""
		}
	}
	return db.VerificationUnverified, "browser/routing finding needs a signed Playwright screenshot and matching HAR provenance"
}

func browserTraceFromActivity(detail string) (browserNetworkTrace, bool) {
	var envelope struct {
		NetworkTrace browserNetworkTrace `json:"network_trace"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(detail)), &envelope); err != nil {
		return browserNetworkTrace{}, false
	}
	t := envelope.NetworkTrace
	return t, t.Ref != "" && len(t.SHA256) == 64 && t.ByteSize > 0 && t.SourceURL != ""
}

func (s *Server) validBrowserHAR(trace browserNetworkTrace, hostname string, quotes []string) bool {
	artifact := agent.EvidenceArtifact{Ref: trace.Ref, SHA256: trace.SHA256, ByteSize: trace.ByteSize}
	root := filepath.Join(s.m.dir, "evidence")
	if !evidenceArtifactFileValid(root, artifact) {
		return false
	}
	path, err := confinedEvidencePath(root, trace.Ref)
	if err != nil {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
				Response struct {
					Status     int    `json:"status"`
					StatusText string `json:"statusText"`
					Headers    []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
					Content struct {
						Text     string `json:"text"`
						Encoding string `json:"encoding"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(raw, &har); err != nil {
		return false
	}
	for _, entry := range har.Log.Entries {
		u, err := url.Parse(entry.Request.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), hostname) {
			continue
		}
		var evidence strings.Builder
		fmt.Fprintf(&evidence, "%d %s\n", entry.Response.Status, entry.Response.StatusText)
		for _, header := range entry.Response.Headers {
			evidence.WriteString(header.Name)
			evidence.WriteString(": ")
			evidence.WriteString(header.Value)
			evidence.WriteByte('\n')
		}
		body := []byte(entry.Response.Content.Text)
		if strings.EqualFold(entry.Response.Content.Encoding, "base64") {
			decoded, err := base64.StdEncoding.DecodeString(entry.Response.Content.Text)
			if err != nil {
				continue
			}
			body = decoded
		}
		evidence.Write(body)
		normalized := normalizeEvidenceText(evidence.String())
		for _, quote := range quotes {
			if strings.Contains(normalized, quote) {
				return true
			}
		}
	}
	return false
}

func artifactVerificationSuccessMessage(profile findingVerificationClass, poe int) string {
	if profile == verificationExploitation {
		return fmt.Sprintf(" (POE L%d)", poe)
	}
	return " (" + string(profile) + " evidence policy)"
}
