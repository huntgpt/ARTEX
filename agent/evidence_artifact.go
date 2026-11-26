package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// EvidenceArtifact is a verified image produced from a real tool execution or
// imported from a real browser capture. Ref is deliberately relative to the
// ARTEX evidence root: activity metadata must never disclose a server path.
type EvidenceArtifact struct {
	Ref             string    `json:"ref"`
	Kind            string    `json:"kind"` // terminal_capture or browser_screenshot
	Label           string    `json:"label"`
	MIMEType        string    `json:"mime_type"`
	SHA256          string    `json:"sha256"`
	ByteSize        int64     `json:"byte_size"`
	CapturedAt      time.Time `json:"captured_at"`
	Tool            string    `json:"tool,omitempty"`
	Command         string    `json:"command,omitempty"`
	SourceURL       string    `json:"source_url,omitempty"`
	OriginalName    string    `json:"original_name,omitempty"`
	RawOutputSHA256 string    `json:"raw_output_sha256,omitempty"`
	Truncated       bool      `json:"truncated,omitempty"`
	Sensitive       bool      `json:"sensitive,omitempty"`
}

type evidenceCaptureConfig struct {
	Dir       string
	RefPrefix string
}

func taskEvidenceConfig(base string, taskID int64) evidenceCaptureConfig {
	prefix := filepath.ToSlash(filepath.Join("tasks", fmt.Sprintf("%d", taskID)))
	return evidenceCaptureConfig{
		Dir:       filepath.Join(base, "evidence", filepath.FromSlash(prefix)),
		RefPrefix: prefix,
	}
}

var ansiEscape = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))`)

func shellEvidenceTool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bash", "shell", "exec", "execute", "exec_command", "run_command":
		return true
	default:
		return false
	}
}

func commandFromToolInput(raw string) string {
	var in map[string]any
	if json.Unmarshal([]byte(raw), &in) == nil {
		for _, key := range []string{"command", "cmd", "script"} {
			if value, ok := in[key].(string); ok && strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return strings.TrimSpace(raw)
}

// terminalEvidence renders the exact command and tool-result text into a PNG.
// This is not synthetic evidence: the bytes come from the same tool_result that
// is persisted in Activity.Detail, and RawOutputSHA256 makes that relationship
// independently checkable. Long output is visibly marked as truncated in the
// image while the full raw result remains in the audit activity/spill file.
func terminalEvidence(cfg evidenceCaptureConfig, toolUseID, toolName, toolInput, output string, at time.Time) ([]EvidenceArtifact, error) {
	if cfg.Dir == "" || !shellEvidenceTool(toolName) {
		return nil, nil
	}
	command := commandFromToolInput(toolInput)
	if command == "" && strings.TrimSpace(output) == "" {
		return nil, nil
	}
	clean := strings.ReplaceAll(ansiEscape.ReplaceAllString(output, ""), "\r\n", "\n")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	rawHash := sha256.Sum256([]byte(output))
	lines, truncated := terminalLines(command, clean, 156, 520)
	if truncated {
		lines = append(lines, "", "[ARTEX terminal capture truncated for image safety; full output remains in the audited tool result]")
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	nameSeed := toolUseID + "\x00" + command + "\x00" + hex.EncodeToString(rawHash[:])
	nameHash := sha256.Sum256([]byte(nameSeed))
	name := fmt.Sprintf("terminal-%s.png", hex.EncodeToString(nameHash[:8]))
	path := filepath.Join(cfg.Dir, name)
	if err := renderTerminalPNG(path, lines, at, hex.EncodeToString(rawHash[:])); err != nil {
		return nil, err
	}
	artifactHash, size, err := hashRegularFile(path)
	if err != nil {
		return nil, err
	}
	return []EvidenceArtifact{{
		Ref:             filepath.ToSlash(filepath.Join(cfg.RefPrefix, name)),
		Kind:            "terminal_capture",
		Label:           "Actual command output",
		MIMEType:        "image/png",
		SHA256:          artifactHash,
		ByteSize:        size,
		CapturedAt:      at.UTC(),
		Tool:            toolName,
		Command:         command,
		RawOutputSHA256: hex.EncodeToString(rawHash[:]),
		Truncated:       truncated,
		Sensitive:       true,
	}}, nil
}

func terminalLines(command, output string, width, maxLines int) ([]string, bool) {
	lines := []string{"$ " + command, ""}
	for _, line := range strings.Split(output, "\n") {
		for len([]rune(line)) > width {
			r := []rune(line)
			lines = append(lines, string(r[:width]))
			line = string(r[width:])
		}
		lines = append(lines, line)
		if len(lines) >= maxLines {
			return lines[:maxLines], true
		}
	}
	return lines, false
}

func renderTerminalPNG(path string, lines []string, at time.Time, rawHash string) error {
	const (
		canvasWidth = 1400
		padding     = 28
		lineHeight  = 17
		headerH     = 68
	)
	height := headerH + padding + len(lines)*lineHeight + padding
	if height < 220 {
		height = 220
	}
	img := image.NewRGBA(image.Rect(0, 0, canvasWidth, height))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: color.RGBA{R: 13, G: 17, B: 23, A: 255}}, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(0, 0, canvasWidth, headerH), &image.Uniform{C: color.RGBA{R: 24, G: 31, B: 42, A: 255}}, image.Point{}, draw.Src)
	face := basicfont.Face7x13
	drawer := &font.Drawer{Dst: img, Face: face}
	drawer.Src = image.NewUniform(color.RGBA{R: 236, G: 242, B: 248, A: 255})
	drawer.Dot = fixed.P(padding, 27)
	drawer.DrawString("ARTEX · VERIFIED TERMINAL CAPTURE")
	drawer.Src = image.NewUniform(color.RGBA{R: 148, G: 163, B: 184, A: 255})
	drawer.Dot = fixed.P(padding, 50)
	drawer.DrawString(at.UTC().Format(time.RFC3339) + "  raw-output sha256:" + rawHash[:16] + "…")
	drawer.Src = image.NewUniform(color.RGBA{R: 219, G: 231, B: 241, A: 255})
	y := headerH + padding
	for _, line := range lines {
		// basicfont is intentionally deterministic and dependency-free at runtime.
		// Replace invalid UTF-8 only; printable non-ASCII remains in the audit text.
		if !utf8.ValidString(line) {
			line = strings.ToValidUTF8(line, "�")
		}
		drawer.Dot = fixed.P(padding, y)
		drawer.DrawString(line)
		y += lineHeight
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func hashRegularFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return "", 0, fmt.Errorf("evidence artifact is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), st.Size(), nil
}

func evidenceMetadata(existing json.RawMessage, artifacts []EvidenceArtifact) json.RawMessage {
	if len(artifacts) == 0 {
		return existing
	}
	meta := map[string]any{}
	if len(existing) > 0 {
		_ = json.Unmarshal(existing, &meta)
	}
	var current []EvidenceArtifact
	if raw, ok := meta["evidence_artifacts"]; ok {
		b, _ := json.Marshal(raw)
		_ = json.Unmarshal(b, &current)
	}
	meta["evidence_artifacts"] = append(current, artifacts...)
	out, _ := json.Marshal(meta)
	return out
}

// artifactsFromToolResult accepts artifacts only from ARTEX's code-owned
// scanner-ingest tool. Target-controlled command output, custom tools, and an
// LLM response may contain JSON that looks like an artifact envelope; treating
// that text as evidence would let an arbitrary/mock image acquire a verified
// badge. Terminal captures never come through this path: ARTEX creates them
// itself from the audited tool_result below.
func artifactsFromToolResult(sourceTool, output string) []EvidenceArtifact {
	if !strings.EqualFold(strings.TrimSpace(sourceTool), "ingest_scan_output") {
		return nil
	}
	var envelope struct {
		Artifacts []EvidenceArtifact `json:"artifacts"`
	}
	if json.Unmarshal([]byte(output), &envelope) != nil {
		return nil
	}
	var out []EvidenceArtifact
	for _, artifact := range envelope.Artifacts {
		if !validImportedBrowserArtifact(artifact) {
			continue
		}
		out = append(out, artifact)
	}
	return out
}

func validImportedBrowserArtifact(artifact EvidenceArtifact) bool {
	if artifact.Kind != "browser_screenshot" || artifact.Tool != "gowitness" ||
		artifact.Ref == "" || filepath.IsAbs(artifact.Ref) || artifact.ByteSize <= 0 ||
		artifact.CapturedAt.IsZero() || artifact.OriginalName == "" ||
		artifact.OriginalName != filepath.Base(artifact.OriginalName) ||
		len(artifact.SHA256) != 64 || strings.ToLower(artifact.SHA256) != artifact.SHA256 {
		return false
	}
	if _, err := hex.DecodeString(artifact.SHA256); err != nil {
		return false
	}
	switch artifact.MIMEType {
	case "image/png", "image/jpeg", "image/webp":
	default:
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(artifact.Ref))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return false
	}
	u, err := url.Parse(artifact.SourceURL)
	return err == nil && u.User == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}
