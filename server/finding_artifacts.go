package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

type findingArtifactDTO struct {
	ID              string    `json:"id"`
	ActivityID      int64     `json:"activity_id"`
	NodeID          int64     `json:"node_id,omitempty"`
	ToolUseID       string    `json:"tool_use_id"`
	Verified        bool      `json:"verified"`
	Provenance      string    `json:"provenance"`
	Kind            string    `json:"kind"`
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
	ref             string
	activityDetail  string
}

func (s *Server) findingArtifacts(id int64) ([]findingArtifactDTO, error) {
	finding, err := s.m.pg.GetFinding(id)
	if err != nil || finding == nil {
		return nil, err
	}
	if finding.TaskID == nil || finding.NodeID == nil {
		return []findingArtifactDTO{}, nil
	}
	task := s.m.ResolveTask(i64s(*finding.TaskID))
	if task == nil {
		return []findingArtifactDTO{}, nil
	}
	nodes, err := task.Store.FindingEvidenceNodes(*finding.NodeID)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(nodes))
	for _, node := range nodes {
		ids = append(ids, node.ID)
	}
	activities, err := task.Store.EvidenceActivities(ids)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []findingArtifactDTO{}
	evidenceRoot := filepath.Join(s.m.dir, "evidence")
	for _, activity := range activities {
		var metadata struct {
			Artifacts []agent.EvidenceArtifact `json:"evidence_artifacts"`
		}
		if json.Unmarshal(activity.Metadata, &metadata) != nil {
			metadata.Artifacts = nil
		}
		// Compatibility path for audited scanner/browser-ingest results recorded
		// before captureRunSession understood Norma's nonce-bound output frame.
		// The parser remains restricted to code-owned ingest tools and the file,
		// SHA and exact-result declaration are validated below.
		if len(metadata.Artifacts) == 0 {
			metadata.Artifacts = agent.EvidenceArtifactsFromToolResult(activity.Tool, activity.Detail)
		}
		for _, artifact := range metadata.Artifacts {
			if !validEvidenceArtifact(activity, artifact) ||
				!evidenceArtifactFileValid(evidenceRoot, artifact) || seen[artifact.SHA256] {
				continue
			}
			seen[artifact.SHA256] = true
			nodeID := int64(0)
			if activity.NodeID != nil {
				nodeID = *activity.NodeID
			}
			out = append(out, findingArtifactDTO{
				ID: artifact.SHA256, ActivityID: activity.ID, NodeID: nodeID,
				ToolUseID: activity.ToolUseID, Verified: true, Provenance: "audited_tool_result",
				Kind: artifact.Kind, Label: artifact.Label, MIMEType: artifact.MIMEType,
				SHA256: artifact.SHA256, ByteSize: artifact.ByteSize, CapturedAt: artifact.CapturedAt,
				Tool: artifact.Tool, Command: artifact.Command, SourceURL: artifact.SourceURL,
				OriginalName: artifact.OriginalName, RawOutputSHA256: artifact.RawOutputSHA256,
				Truncated: artifact.Truncated, Sensitive: artifact.Sensitive, ref: artifact.Ref,
				activityDetail: activity.Detail,
			})
		}
	}
	return out, nil
}

func validEvidenceArtifact(activity db.Activity, artifact agent.EvidenceArtifact) bool {
	if activity.Kind != "tool_result" || strings.TrimSpace(activity.ToolUseID) == "" ||
		artifact.CapturedAt.IsZero() || artifact.ByteSize <= 0 || artifact.ByteSize > 50<<20 ||
		len(artifact.SHA256) != 64 || strings.ToLower(artifact.SHA256) != artifact.SHA256 ||
		len(artifact.Ref) == 0 || filepath.IsAbs(artifact.Ref) {
		return false
	}
	if _, err := hex.DecodeString(artifact.SHA256); err != nil {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(artifact.Ref))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) ||
		!strings.HasPrefix(filepath.ToSlash(clean), "tasks/") {
		return false
	}
	switch artifact.Kind {
	case "terminal_capture":
		if activity.IsError || artifact.MIMEType != "image/png" || !shellEvidenceActivityTool(activity.Tool) ||
			!strings.EqualFold(strings.TrimSpace(artifact.Tool), strings.TrimSpace(activity.Tool)) ||
			strings.TrimSpace(artifact.Command) == "" || len(artifact.RawOutputSHA256) != 64 ||
			strings.TrimSpace(artifact.SourceURL) != "" {
			return false
		}
		if _, err := hex.DecodeString(artifact.RawOutputSHA256); err != nil {
			return false
		}
		raw := sha256.Sum256([]byte(activity.Detail))
		return hex.EncodeToString(raw[:]) == artifact.RawOutputSHA256
	case "browser_screenshot":
		// A failed importer call may contain diagnostic text shaped by a file or
		// target response. Only a successful audited import can attest that the
		// server confined, decoded, hashed, and persisted the original image.
		if activity.IsError {
			return false
		}
		expectedTool := ""
		switch activity.Tool {
		case "ingest_scan_output":
			expectedTool = "gowitness"
		case "ingest_browser_evidence", "ingest_retest_browser_evidence":
			expectedTool = "playwright"
		}
		if expectedTool == "" || artifact.Tool != expectedTool ||
			artifact.RawOutputSHA256 != "" || artifact.Command != "" ||
			artifact.OriginalName == "" || artifact.OriginalName != filepath.Base(artifact.OriginalName) {
			return false
		}
		switch artifact.MIMEType {
		case "image/png", "image/jpeg":
		case "image/webp":
			if expectedTool != "gowitness" {
				return false
			}
		default:
			return false
		}
		u, err := url.Parse(artifact.SourceURL)
		if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return false
		}
		return artifactDeclaredInToolResult(activity.Tool, activity.Detail, artifact)
	default:
		return false
	}
}

func shellEvidenceActivityTool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bash", "shell", "exec", "execute", "exec_command", "run_command":
		return true
	default:
		return false
	}
}

func artifactDeclaredInToolResult(sourceTool, detail string, artifact agent.EvidenceArtifact) bool {
	for _, declared := range agent.EvidenceArtifactsFromToolResult(sourceTool, detail) {
		if declared == artifact {
			return true
		}
	}
	return false
}

func evidenceArtifactFileValid(root string, artifact agent.EvidenceArtifact) bool {
	path, err := confinedEvidencePath(root, artifact.Ref)
	if err != nil {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != artifact.ByteSize || st.Size() > 50<<20 {
		return false
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == artifact.SHA256
}

func (s *Server) listFindingArtifacts(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, http.StatusBadRequest, "bad finding id")
		return
	}
	if finding, err := s.m.pg.GetFinding(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	} else if finding == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	artifacts, err := s.findingArtifacts(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"items": artifacts})
}

func (s *Server) getFindingArtifact(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	digest := strings.ToLower(strings.TrimSpace(r.PathValue("artifact")))
	if id <= 0 || len(digest) != 64 {
		writeErr(w, 400, "bad evidence artifact")
		return
	}
	artifacts, err := s.findingArtifacts(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var selected *findingArtifactDTO
	for i := range artifacts {
		if artifacts[i].SHA256 == digest {
			selected = &artifacts[i]
			break
		}
	}
	if selected == nil {
		writeErr(w, 404, "evidence artifact not found")
		return
	}
	root := filepath.Join(s.m.dir, "evidence")
	path, err := confinedEvidencePath(root, selected.ref)
	if err != nil {
		writeErr(w, 404, "evidence artifact unavailable")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, 404, "evidence artifact unavailable")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != selected.ByteSize || st.Size() > 50<<20 {
		writeErr(w, 409, "evidence artifact failed integrity validation")
		return
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil || hex.EncodeToString(h.Sum(nil)) != selected.SHA256 {
		writeErr(w, 409, "evidence artifact failed integrity validation")
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		writeErr(w, 500, "evidence artifact unavailable")
		return
	}
	w.Header().Set("Content-Type", selected.MIMEType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": selected.OriginalName}))
	http.ServeContent(w, r, selected.OriginalName, selected.CapturedAt, f)
}

func confinedEvidencePath(root, ref string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(rootAbs, filepath.FromSlash(ref))
	rel, err := filepath.Rel(rootAbs, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact escapes evidence root")
	}
	cur := rootAbs
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("artifact path contains a symlink")
		}
	}
	return path, nil
}
