package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/redact"
)

func discoveredSecretDTO(secret db.DiscoveredSecret) map[string]any {
	masked := secret.ScannerRedacted
	if secret.SecretValue != "" {
		masked = redact.Secret(secret.SecretValue)
	}
	return map[string]any{
		"id": secret.ID, "task_id": secret.TaskID, "detector": secret.Detector,
		"source_type": secret.SourceType, "source_name": secret.SourceName,
		"repository": secret.Repository, "file_path": secret.FilePath,
		"line_number": secret.LineNumber, "commit_hash": secret.CommitHash,
		"verified": secret.Verified, "masked_value": masked,
		"secret_sha256": secret.SecretSHA256, "metadata": secret.Metadata,
		"created_at": secret.CreatedAt, "updated_at": secret.UpdatedAt,
	}
}

func (s *Server) listTaskDiscoveredSecrets(w http.ResponseWriter, r *http.Request) {
	taskID, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	items, err := s.m.PG().ListDiscoveredSecrets(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, discoveredSecretDTO(item))
	}
	writeJSON(w, 200, out)
}

func (s *Server) revealTaskDiscoveredSecret(w http.ResponseWriter, r *http.Request) {
	taskID, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	secretID, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil || secretID <= 0 {
		writeErr(w, 400, "invalid secret id")
		return
	}
	var request struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(request.Reason) == "" {
		writeErr(w, 400, "reason is required")
		return
	}
	secret, err := s.m.PG().RevealDiscoveredSecret(taskID, secretID, "operator-ui", request.Action, request.Reason)
	if err != nil {
		writeErr(w, 404, "secret not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"id": secret.ID, "value": secret.SecretValue, "value_v2": secret.SecretValueV2,
	})
}
