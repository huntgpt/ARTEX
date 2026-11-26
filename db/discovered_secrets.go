package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Autumn-27/artex/redact"
)

type DiscoveredSecretInput struct {
	Detector        string
	SourceType      string
	SourceName      string
	Repository      string
	FilePath        string
	LineNumber      int
	CommitHash      string
	Verified        bool
	SecretValue     string
	SecretValueV2   string
	ScannerRedacted string
	Metadata        json.RawMessage
}

type DiscoveredSecret struct {
	ID              int64           `json:"id"`
	TaskID          int64           `json:"task_id"`
	Detector        string          `json:"detector"`
	SourceType      string          `json:"source_type"`
	SourceName      string          `json:"source_name"`
	Repository      string          `json:"repository"`
	FilePath        string          `json:"file_path"`
	LineNumber      int             `json:"line_number"`
	CommitHash      string          `json:"commit_hash"`
	Verified        bool            `json:"verified"`
	SecretValue     string          `json:"-"`
	SecretValueV2   string          `json:"-"`
	SecretSHA256    string          `json:"secret_sha256"`
	ScannerRedacted string          `json:"scanner_redacted"`
	Metadata        json.RawMessage `json:"metadata,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func (d *DB) UpsertDiscoveredSecret(taskID int64, in DiscoveredSecretInput) (DiscoveredSecret, error) {
	in.Detector = strings.TrimSpace(in.Detector)
	if taskID <= 0 || in.Detector == "" || in.SecretValue == "" {
		return DiscoveredSecret{}, errors.New("discovered secret requires task, detector and value")
	}
	if in.LineNumber < 0 {
		in.LineNumber = 0
	}
	sum := sha256.Sum256([]byte(in.SecretValue + "\x00" + in.SecretValueV2))
	digest := hex.EncodeToString(sum[:])
	sealed, err := sealSecret(colDiscoveredSecret, in.SecretValue)
	if err != nil {
		return DiscoveredSecret{}, err
	}
	sealedV2, err := sealSecret(colDiscoveredSecretV2, in.SecretValueV2)
	if err != nil {
		return DiscoveredSecret{}, err
	}
	metadata := in.Metadata
	if len(metadata) == 0 || !json.Valid(metadata) {
		metadata = json.RawMessage(`{}`)
	}
	var out DiscoveredSecret
	err = d.QueryRow(`
INSERT INTO discovered_secrets(task_id,detector,source_type,source_name,repository,file_path,line_number,commit_hash,verified,secret_value,secret_value_v2,secret_sha256,scanner_redacted,metadata)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT(task_id,detector,secret_sha256,repository,file_path,line_number,commit_hash) DO UPDATE SET
 verified=discovered_secrets.verified OR EXCLUDED.verified, scanner_redacted=EXCLUDED.scanner_redacted,
 metadata=EXCLUDED.metadata, updated_at=now()
RETURNING id,task_id,detector,source_type,source_name,repository,file_path,line_number,commit_hash,verified,secret_sha256,scanner_redacted,metadata,created_at,updated_at`,
		taskID, in.Detector, utf8Clean(in.SourceType), utf8Clean(in.SourceName), utf8Clean(in.Repository),
		utf8Clean(in.FilePath), in.LineNumber, utf8Clean(in.CommitHash), in.Verified, sealed, sealedV2,
		digest, redact.Secret(in.SecretValue), string(jsonbClean(metadata))).Scan(
		&out.ID, &out.TaskID, &out.Detector, &out.SourceType, &out.SourceName, &out.Repository,
		&out.FilePath, &out.LineNumber, &out.CommitHash, &out.Verified, &out.SecretSHA256,
		&out.ScannerRedacted, &out.Metadata, &out.CreatedAt, &out.UpdatedAt)
	return out, err
}

// ReportSecretValues decrypts values only for an in-memory replacement pass in
// the report renderer. Callers must never serialize the returned slice.
func (d *DB) ReportSecretValues(taskID int64) ([]string, error) {
	rows, err := d.Query(`SELECT secret_value,secret_value_v2 FROM discovered_secrets WHERE task_id=$1`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var sealed, sealedV2 string
		if err := rows.Scan(&sealed, &sealedV2); err != nil {
			return nil, err
		}
		value, err := openSecret(colDiscoveredSecret, sealed)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		if sealedV2 != "" {
			value, err = openSecret(colDiscoveredSecretV2, sealedV2)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
	}
	return values, rows.Err()
}

func (d *DB) ReportSecretValuesForTasks(taskIDs []int64) ([]string, error) {
	seen := map[int64]bool{}
	var values []string
	for _, taskID := range taskIDs {
		if taskID <= 0 || seen[taskID] {
			continue
		}
		seen[taskID] = true
		items, err := d.ReportSecretValues(taskID)
		if err != nil {
			return nil, err
		}
		values = append(values, items...)
	}
	return values, nil
}

func (d *DB) ListDiscoveredSecrets(taskID int64) ([]DiscoveredSecret, error) {
	rows, err := d.Query(`SELECT id,task_id,detector,source_type,source_name,repository,file_path,line_number,commit_hash,verified,secret_sha256,scanner_redacted,metadata,created_at,updated_at FROM discovered_secrets WHERE task_id=$1 ORDER BY verified DESC,id DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DiscoveredSecret
	for rows.Next() {
		var s DiscoveredSecret
		if err := rows.Scan(&s.ID, &s.TaskID, &s.Detector, &s.SourceType, &s.SourceName, &s.Repository, &s.FilePath, &s.LineNumber, &s.CommitHash, &s.Verified, &s.SecretSHA256, &s.ScannerRedacted, &s.Metadata, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) RevealDiscoveredSecret(taskID, secretID int64, actor, action, reason string) (DiscoveredSecret, error) {
	if action != "copy" && action != "validation-use" {
		action = "reveal"
	}
	var out DiscoveredSecret
	var sealed, sealedV2 string
	err := d.QueryRow(`SELECT id,task_id,detector,source_type,source_name,repository,file_path,line_number,commit_hash,verified,secret_value,secret_value_v2,secret_sha256,scanner_redacted,metadata,created_at,updated_at FROM discovered_secrets WHERE task_id=$1 AND id=$2`, taskID, secretID).Scan(
		&out.ID, &out.TaskID, &out.Detector, &out.SourceType, &out.SourceName, &out.Repository, &out.FilePath, &out.LineNumber, &out.CommitHash, &out.Verified, &sealed, &sealedV2, &out.SecretSHA256, &out.ScannerRedacted, &out.Metadata, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	if out.SecretValue, err = openSecret(colDiscoveredSecret, sealed); err != nil {
		return out, err
	}
	if sealedV2 != "" {
		out.SecretValueV2, err = openSecret(colDiscoveredSecretV2, sealedV2)
		if err != nil {
			return out, err
		}
	}
	_, err = d.Exec(`INSERT INTO secret_access_audit(task_id,secret_id,actor,action,reason) VALUES($1,$2,$3,$4,$5)`, taskID, secretID, utf8Clean(actor), action, utf8Clean(reason))
	return out, err
}

func (s *ExplorationStore) UpsertDiscoveredSecret(taskID int64, in DiscoveredSecretInput) (DiscoveredSecret, error) {
	return s.db.UpsertDiscoveredSecret(taskID, in)
}
