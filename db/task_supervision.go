package db

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	SupervisorModeOff    = "off"
	SupervisorModeSingle = "single"
	SupervisorModeDual   = "dual"

	SupervisorCheckpointStrategic  = "strategic"
	SupervisorCheckpointEveryRound = "every_round"
	SupervisorCheckpointManual     = "manual"
)

var (
	ErrSupervisorConfigInvalid          = errors.New("invalid task supervisor config")
	ErrSupervisorProfileAbsent          = errors.New("task supervisor profile not found")
	ErrSupervisorProfilesNotIndependent = errors.New("task supervisor profiles are not independent")
)

// TaskSupervisorConfig binds stable project-lead identities to one task. It is
// intentionally separate from the worker failover/rotation chain.
type TaskSupervisorConfig struct {
	Mode               string `json:"mode"`
	PrimaryProfileID   *int64 `json:"primary_profile_id,omitempty"`
	SecondaryProfileID *int64 `json:"secondary_profile_id,omitempty"`
	CheckpointPolicy   string `json:"checkpoint_policy"`
	Revision           int64  `json:"revision"`
}

func DefaultTaskSupervisorConfig() TaskSupervisorConfig {
	return TaskSupervisorConfig{
		Mode:             SupervisorModeOff,
		CheckpointPolicy: SupervisorCheckpointStrategic,
		Revision:         1,
	}
}

// NormalizeTaskSupervisorConfig validates the lead topology before any row is
// written. Dual leads must be different profiles so two labels cannot disguise
// one model/account as independent review.
func NormalizeTaskSupervisorConfig(in *TaskSupervisorConfig) (TaskSupervisorConfig, error) {
	cfg := DefaultTaskSupervisorConfig()
	if in == nil {
		return cfg, nil
	}
	cfg = *in
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	cfg.CheckpointPolicy = strings.ToLower(strings.TrimSpace(cfg.CheckpointPolicy))
	if cfg.Mode == "" {
		cfg.Mode = SupervisorModeOff
	}
	if cfg.CheckpointPolicy == "" {
		cfg.CheckpointPolicy = SupervisorCheckpointStrategic
	}
	if cfg.Revision <= 0 {
		cfg.Revision = 1
	}
	validID := func(id *int64) bool { return id != nil && *id > 0 }
	switch cfg.Mode {
	case SupervisorModeOff:
		cfg.PrimaryProfileID = nil
		cfg.SecondaryProfileID = nil
	case SupervisorModeSingle:
		if !validID(cfg.PrimaryProfileID) || cfg.SecondaryProfileID != nil {
			return TaskSupervisorConfig{}, fmt.Errorf("%w: single mode requires exactly one primary profile", ErrSupervisorConfigInvalid)
		}
	case SupervisorModeDual:
		if !validID(cfg.PrimaryProfileID) || !validID(cfg.SecondaryProfileID) {
			return TaskSupervisorConfig{}, fmt.Errorf("%w: dual mode requires primary and secondary profiles", ErrSupervisorConfigInvalid)
		}
		if *cfg.PrimaryProfileID == *cfg.SecondaryProfileID {
			return TaskSupervisorConfig{}, fmt.Errorf("%w: dual leads must use different profiles", ErrSupervisorConfigInvalid)
		}
	default:
		return TaskSupervisorConfig{}, fmt.Errorf("%w: unknown mode %q", ErrSupervisorConfigInvalid, cfg.Mode)
	}
	switch cfg.CheckpointPolicy {
	case SupervisorCheckpointStrategic, SupervisorCheckpointEveryRound, SupervisorCheckpointManual:
	default:
		return TaskSupervisorConfig{}, fmt.Errorf("%w: unknown checkpoint policy %q", ErrSupervisorConfigInvalid, cfg.CheckpointPolicy)
	}
	return cfg, nil
}

func ensureSupervisorProfiles(tx *sql.Tx, cfg TaskSupervisorConfig) error {
	for _, profileID := range []*int64{cfg.PrimaryProfileID, cfg.SecondaryProfileID} {
		if profileID == nil {
			continue
		}
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM llm_profiles WHERE id=$1)`, *profileID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: profile #%d", ErrSupervisorProfileAbsent, *profileID)
		}
	}
	if cfg.Mode == SupervisorModeDual {
		primary, err := supervisorProfileFingerprint(tx, *cfg.PrimaryProfileID)
		if err != nil {
			return err
		}
		secondary, err := supervisorProfileFingerprint(tx, *cfg.SecondaryProfileID)
		if err != nil {
			return err
		}
		if primary == secondary {
			return fmt.Errorf("%w: profiles #%d and #%d resolve to the same provider/model/account fingerprint", ErrSupervisorProfilesNotIndependent, *cfg.PrimaryProfileID, *cfg.SecondaryProfileID)
		}
	}
	return nil
}

// supervisorProfileFingerprint is deliberately based on provider, model and
// the effective account locator, not the display name. Two differently named
// profiles that both use a CLI's global login are still the same reviewer. A
// per-profile CLI config/token file, or a different API-key hint/base URL,
// identifies a different account without loading or comparing plaintext keys.
func supervisorProfileFingerprint(tx *sql.Tx, id int64) (string, error) {
	var format, model, baseURL, keyHint, configDir, tokenFile string
	err := tx.QueryRow(`
SELECT lower(trim(format)),lower(trim(model)),lower(trim(COALESCE(base_url,''))),
       lower(trim(COALESCE(api_key_hint,''))),lower(trim(COALESCE(cli_config_dir,''))),
       lower(trim(COALESCE(cli_auth_token_file,'')))
FROM llm_profiles WHERE id=$1`, id).Scan(&format, &model, &baseURL, &keyHint, &configDir, &tokenFile)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("%w: profile #%d", ErrSupervisorProfileAbsent, id)
	}
	if err != nil {
		return "", err
	}
	account := ""
	switch format {
	case "claude-cli", "codex-cli":
		account = configDir + "\x00" + tokenFile
	default:
		account = baseURL + "\x00" + keyHint
	}
	return format + "\x00" + model + "\x00" + account, nil
}

func insertTaskSupervisorConfig(tx *sql.Tx, taskID int64, input *TaskSupervisorConfig) (TaskSupervisorConfig, error) {
	cfg, err := NormalizeTaskSupervisorConfig(input)
	if err != nil {
		return TaskSupervisorConfig{}, err
	}
	if cfg.Mode == SupervisorModeOff {
		return cfg, nil
	}
	if err := ensureSupervisorProfiles(tx, cfg); err != nil {
		return TaskSupervisorConfig{}, err
	}
	_, err = tx.Exec(`
INSERT INTO task_supervisor_config(task_id,mode,primary_profile_id,secondary_profile_id,checkpoint_policy,revision)
VALUES ($1,$2,$3,$4,$5,$6)`, taskID, cfg.Mode, cfg.PrimaryProfileID, cfg.SecondaryProfileID, cfg.CheckpointPolicy, cfg.Revision)
	return cfg, err
}

func scanSupervisorConfig(row interface{ Scan(...any) error }) (TaskSupervisorConfig, error) {
	cfg := DefaultTaskSupervisorConfig()
	var primary, secondary sql.NullInt64
	if err := row.Scan(&cfg.Mode, &primary, &secondary, &cfg.CheckpointPolicy, &cfg.Revision); err != nil {
		return TaskSupervisorConfig{}, err
	}
	if primary.Valid {
		id := primary.Int64
		cfg.PrimaryProfileID = &id
	}
	if secondary.Valid {
		id := secondary.Int64
		cfg.SecondaryProfileID = &id
	}
	return cfg, nil
}

func (d *DB) TaskSupervisorConfig(taskID int64) (TaskSupervisorConfig, error) {
	cfg, err := scanSupervisorConfig(d.QueryRow(`
SELECT mode,primary_profile_id,secondary_profile_id,checkpoint_policy,revision
FROM task_supervisor_config WHERE task_id=$1`, taskID))
	if err == sql.ErrNoRows {
		return DefaultTaskSupervisorConfig(), nil
	}
	return cfg, err
}

// ReplaceTaskSupervisorConfig atomically swaps the lead bindings. Old rounds
// retain the provider/model/account snapshots they actually used.
func (d *DB) ReplaceTaskSupervisorConfig(taskID int64, input *TaskSupervisorConfig) (TaskSupervisorConfig, error) {
	cfg, err := NormalizeTaskSupervisorConfig(input)
	if err != nil {
		return TaskSupervisorConfig{}, err
	}
	tx, err := d.Begin()
	if err != nil {
		return TaskSupervisorConfig{}, err
	}
	defer tx.Rollback()
	var taskExists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL)`, taskID).Scan(&taskExists); err != nil {
		return TaskSupervisorConfig{}, err
	}
	if !taskExists {
		return TaskSupervisorConfig{}, sql.ErrNoRows
	}
	if err := ensureSupervisorProfiles(tx, cfg); err != nil {
		return TaskSupervisorConfig{}, err
	}
	if err := tx.QueryRow(`
INSERT INTO task_supervisor_config(task_id,mode,primary_profile_id,secondary_profile_id,checkpoint_policy,revision)
VALUES ($1,$2,$3,$4,$5,1)
ON CONFLICT(task_id) DO UPDATE SET
 mode=EXCLUDED.mode,
 primary_profile_id=EXCLUDED.primary_profile_id,
 secondary_profile_id=EXCLUDED.secondary_profile_id,
 checkpoint_policy=EXCLUDED.checkpoint_policy,
 revision=task_supervisor_config.revision+1
RETURNING revision`, taskID, cfg.Mode, cfg.PrimaryProfileID, cfg.SecondaryProfileID, cfg.CheckpointPolicy).Scan(&cfg.Revision); err != nil {
		return TaskSupervisorConfig{}, err
	}
	return cfg, tx.Commit()
}

type SupervisorRound struct {
	ID                 int64           `json:"id"`
	TaskID             int64           `json:"task_id"`
	TriggerKind        string          `json:"trigger_kind"`
	State              string          `json:"state"`
	SnapshotHash       string          `json:"snapshot_hash"`
	LegacySnapshotHash string          `json:"legacy_snapshot_hash,omitempty"`
	Snapshot           json.RawMessage `json:"snapshot"`
	StartedAt          *time.Time      `json:"started_at,omitempty"`
	CompletedAt        *time.Time      `json:"completed_at,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

type SupervisorReviewSeed struct {
	LeadRole     string
	ProfileID    int64
	Provider     string
	Model        string
	AccountLabel string
}

type SupervisorReview struct {
	ID           int64           `json:"id"`
	RoundID      int64           `json:"round_id"`
	LeadRole     string          `json:"lead_role"`
	ProfileID    *int64          `json:"profile_id,omitempty"`
	Provider     string          `json:"provider"`
	Model        string          `json:"model"`
	AccountLabel string          `json:"account_label"`
	State        string          `json:"state"`
	Proposal     json.RawMessage `json:"proposal,omitempty"`
	Summary      string          `json:"summary"`
	Error        string          `json:"error,omitempty"`
	InputTokens  int             `json:"input_tokens"`
	OutputTokens int             `json:"output_tokens"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type SupervisorDecision struct {
	ID               int64           `json:"id"`
	RoundID          int64           `json:"round_id"`
	ArbiterProfileID *int64          `json:"arbiter_profile_id,omitempty"`
	Decision         json.RawMessage `json:"decision"`
	Rationale        string          `json:"rationale"`
	CreatedAt        time.Time       `json:"created_at"`
}

type SupervisorRoundDetail struct {
	SupervisorRound
	Reviews  []SupervisorReview  `json:"reviews"`
	Decision *SupervisorDecision `json:"decision,omitempty"`
}

func jsonObject(raw []byte, label string) (json.RawMessage, error) {
	var object map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, fmt.Errorf("%s must be a JSON object", label)
	}
	return append(json.RawMessage(nil), raw...), nil
}

var supervisorSensitiveKey = regexp.MustCompile(`(?i)(?:^|[_-])(?:api[_-]?key|authorization|cookie|credential|password|passwd|private[_-]?key|pwd|raw|refresh[_-]?token|secret|session[_-]?token|access[_-]?token)(?:$|[_-])`)

var supervisorSecretText = []*regexp.Regexp{
	regexp.MustCompile(`(?is)-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}`),
	regexp.MustCompile(`\b(?:sk-ant-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b`),
	regexp.MustCompile(`\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	regexp.MustCompile(`(?i)\b(?:api[_-]?key|authorization|cookie|credential|password|passwd|pwd|refresh[_-]?token|secret|session[_-]?token|access[_-]?token)\b\s*[:=]\s*(?:["']?)[^\s,;"']{4,}`),
	regexp.MustCompile(`(?i)://([^:/\s]+):([^@/\s]+)@`),
}

func scrubSupervisorText(text string) string {
	for index, pattern := range supervisorSecretText {
		if index == len(supervisorSecretText)-1 {
			text = pattern.ReplaceAllString(text, "://[REDACTED]@")
			continue
		}
		text = pattern.ReplaceAllString(text, "[REDACTED]")
	}
	return text
}

// scrubSupervisorSnapshot recursively removes secret-bearing fields and common
// credential forms from free text before the snapshot is persisted or sent to
// either lead. This is a defence in depth boundary: the normal graph tools
// should not put plaintext secrets in summaries, but supervisor storage must
// remain safe even if an upstream fact or human hint does.
func scrubSupervisorSnapshot(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if supervisorSensitiveKey.MatchString(strings.ToLower(strings.TrimSpace(key))) {
				out[key] = "[REDACTED]"
				continue
			}
			out[key] = scrubSupervisorSnapshot(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = scrubSupervisorSnapshot(item)
		}
		return out
	case string:
		return scrubSupervisorText(typed)
	default:
		return typed
	}
}

func decodeSupervisorSnapshot(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if len(raw) == 0 || decoder.Decode(&object) != nil || object == nil {
		return nil, errors.New("supervisor snapshot must be a JSON object")
	}
	return object, nil
}

// SupervisorSnapshotHash canonicalizes JSON object key order and whitespace
// before hashing. PostgreSQL JSONB is therefore free to normalize the stored
// representation without invalidating the audit hash.
func SupervisorSnapshotHash(snapshot json.RawMessage) (string, error) {
	object, err := decodeSupervisorSnapshot(snapshot)
	if err != nil {
		return "", err
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return "", fmt.Errorf("canonicalize supervisor snapshot: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func VerifySupervisorSnapshot(snapshot json.RawMessage, expectedHash string) error {
	actual, err := SupervisorSnapshotHash(snapshot)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(expectedHash), actual) {
		return fmt.Errorf("supervisor snapshot audit hash mismatch: got %s, want %s", actual, expectedHash)
	}
	return nil
}

func canonicalSupervisorSnapshot(snapshot any) (json.RawMessage, string, error) {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, "", fmt.Errorf("encode supervisor snapshot: %w", err)
	}
	object, err := decodeSupervisorSnapshot(raw)
	if err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(scrubSupervisorSnapshot(object))
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize supervisor snapshot: %w", err)
	}
	hash, err := SupervisorSnapshotHash(canonical)
	if err != nil {
		return nil, "", err
	}
	return canonical, hash, nil
}

// CreateSupervisorRound writes the immutable snapshot and both pending review
// rows in one transaction, before either provider is called.
func (d *DB) CreateSupervisorRound(taskID int64, triggerKind string, snapshot any, seeds []SupervisorReviewSeed) (*SupervisorRound, error) {
	triggerKind = strings.TrimSpace(triggerKind)
	if triggerKind == "" {
		return nil, errors.New("supervisor trigger kind is required")
	}
	if len(seeds) < 1 || len(seeds) > 2 {
		return nil, fmt.Errorf("supervisor round requires one or two lead reviews")
	}
	raw, hash, err := canonicalSupervisorSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	round := &SupervisorRound{TaskID: taskID, TriggerKind: triggerKind, State: "pending", SnapshotHash: hash, Snapshot: raw}
	if err := tx.QueryRow(`
INSERT INTO supervisor_rounds(task_id,trigger_kind,snapshot_hash,snapshot)
VALUES ($1,$2,$3,$4)
RETURNING id,created_at,updated_at`, taskID, triggerKind, hash, raw).Scan(&round.ID, &round.CreatedAt, &round.UpdatedAt); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, seed := range seeds {
		if (seed.LeadRole != "primary" && seed.LeadRole != "secondary") || seen[seed.LeadRole] || seed.ProfileID <= 0 {
			return nil, fmt.Errorf("invalid or duplicate supervisor lead %q", seed.LeadRole)
		}
		seen[seed.LeadRole] = true
		if _, err := tx.Exec(`
INSERT INTO supervisor_reviews(round_id,lead_role,profile_id,provider,model,account_label)
VALUES ($1,$2,$3,$4,$5,$6)`, round.ID, seed.LeadRole, seed.ProfileID, seed.Provider, seed.Model, seed.AccountLabel); err != nil {
			return nil, err
		}
	}
	return round, tx.Commit()
}

func (d *DB) StartSupervisorRound(roundID int64) error {
	res, err := d.Exec(`UPDATE supervisor_rounds SET state='running',started_at=COALESCE(started_at,now()) WHERE id=$1 AND state='pending'`, roundID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("supervisor round %d is not pending", roundID)
	}
	_, err = d.Exec(`UPDATE supervisor_reviews SET state='running',started_at=COALESCE(started_at,now()) WHERE round_id=$1 AND state='pending'`, roundID)
	return err
}

func (d *DB) CompleteSupervisorReview(roundID int64, role string, proposal json.RawMessage, summary, reviewError string, inputTokens, outputTokens int) error {
	state := "completed"
	var payload any
	if strings.TrimSpace(reviewError) != "" {
		state = "failed"
		payload = nil
	} else {
		object, err := jsonObject(proposal, "supervisor proposal")
		if err != nil {
			return err
		}
		payload = object
	}
	res, err := d.Exec(`
UPDATE supervisor_reviews SET state=$3,proposal=$4,summary=$5,error=$6,input_tokens=$7,output_tokens=$8,completed_at=now()
WHERE round_id=$1 AND lead_role=$2 AND state IN ('pending','running')`, roundID, role, state, payload, strings.TrimSpace(summary), strings.TrimSpace(reviewError), max(inputTokens, 0), max(outputTokens, 0))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("supervisor review %d/%s is not writable", roundID, role)
	}
	return nil
}

func (d *DB) MarkSupervisorRoundMerging(roundID int64) error {
	res, err := d.Exec(`UPDATE supervisor_rounds SET state='merging' WHERE id=$1 AND state='running'`, roundID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("supervisor round %d is not running", roundID)
	}
	return nil
}

func (d *DB) FailSupervisorRound(roundID int64, cause string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE supervisor_reviews SET state='failed',error=$2,completed_at=now() WHERE round_id=$1 AND state IN ('pending','running')`, roundID, strings.TrimSpace(cause)); err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE supervisor_rounds SET state='failed',completed_at=now() WHERE id=$1 AND state IN ('pending','running','merging')`, roundID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("supervisor round %d is not active", roundID)
	}
	return tx.Commit()
}

// FailOpenSupervisorRounds recovers crash-interrupted checkpoints. A planner
// loop is serialized per task, so any open round observed before creating the
// next one belongs to a previous process/run and cannot still be producing data.
func (d *DB) FailOpenSupervisorRounds(taskID int64, cause string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
UPDATE supervisor_reviews review
SET state='failed',error=$2,completed_at=now()
FROM supervisor_rounds round
WHERE review.round_id=round.id AND round.task_id=$1
  AND round.state IN ('pending','running','merging')
  AND review.state IN ('pending','running')`, taskID, strings.TrimSpace(cause)); err != nil {
		return err
	}
	if _, err := tx.Exec(`
UPDATE supervisor_rounds SET state='failed',completed_at=now()
WHERE task_id=$1 AND state IN ('pending','running','merging')`, taskID); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) SaveSupervisorDecision(roundID int64, arbiterProfileID *int64, decision json.RawMessage, rationale string) error {
	object, err := jsonObject(decision, "supervisor decision")
	if err != nil {
		return err
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
INSERT INTO supervisor_decisions(round_id,arbiter_profile_id,decision,rationale)
VALUES($1,$2,$3,$4)
ON CONFLICT(round_id) DO UPDATE SET arbiter_profile_id=EXCLUDED.arbiter_profile_id,decision=EXCLUDED.decision,rationale=EXCLUDED.rationale`, roundID, arbiterProfileID, object, strings.TrimSpace(rationale)); err != nil {
		return err
	}
	var failed int
	if err := tx.QueryRow(`SELECT count(*) FROM supervisor_reviews WHERE round_id=$1 AND state='failed'`, roundID).Scan(&failed); err != nil {
		return err
	}
	state := "completed"
	if failed > 0 {
		state = "partial"
	}
	if _, err := tx.Exec(`UPDATE supervisor_rounds SET state=$2,completed_at=now() WHERE id=$1 AND state IN ('running','merging','pending')`, roundID, state); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) MarkSupervisorRoundPartial(roundID int64) error {
	res, err := d.Exec(`UPDATE supervisor_rounds SET state='partial',completed_at=COALESCE(completed_at,now()) WHERE id=$1 AND state IN ('completed','partial')`, roundID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("supervisor round %d cannot become partial", roundID)
	}
	return nil
}

func (d *DB) SupervisorRoundDetails(taskID int64, limit int) ([]SupervisorRoundDetail, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := d.Query(`
SELECT id,task_id,trigger_kind,state,snapshot_hash,COALESCE(legacy_snapshot_hash,''),snapshot,started_at,completed_at,created_at,updated_at
FROM supervisor_rounds WHERE task_id=$1 ORDER BY id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SupervisorRoundDetail, 0)
	byRound := map[int64]int{}
	for rows.Next() {
		var detail SupervisorRoundDetail
		if err := rows.Scan(&detail.ID, &detail.TaskID, &detail.TriggerKind, &detail.State, &detail.SnapshotHash, &detail.LegacySnapshotHash, &detail.Snapshot, &detail.StartedAt, &detail.CompletedAt, &detail.CreatedAt, &detail.UpdatedAt); err != nil {
			return nil, err
		}
		if err := VerifySupervisorSnapshot(detail.Snapshot, detail.SnapshotHash); err != nil {
			return nil, fmt.Errorf("supervisor round %d: %w", detail.ID, err)
		}
		detail.Reviews = []SupervisorReview{}
		byRound[detail.ID] = len(out)
		out = append(out, detail)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	ids := make([]int64, 0, len(out))
	for _, detail := range out {
		ids = append(ids, detail.ID)
	}
	reviewRows, err := d.Query(`
SELECT id,round_id,lead_role,profile_id,provider,model,account_label,state,proposal,summary,error,input_tokens,output_tokens,started_at,completed_at,created_at,updated_at
FROM supervisor_reviews WHERE round_id=ANY($1::bigint[]) ORDER BY round_id DESC,lead_role`, ids)
	if err != nil {
		return nil, err
	}
	for reviewRows.Next() {
		var review SupervisorReview
		var proposal []byte
		if err := reviewRows.Scan(&review.ID, &review.RoundID, &review.LeadRole, &review.ProfileID, &review.Provider, &review.Model, &review.AccountLabel, &review.State, &proposal, &review.Summary, &review.Error, &review.InputTokens, &review.OutputTokens, &review.StartedAt, &review.CompletedAt, &review.CreatedAt, &review.UpdatedAt); err != nil {
			reviewRows.Close()
			return nil, err
		}
		if len(proposal) > 0 {
			review.Proposal = append(json.RawMessage(nil), proposal...)
		}
		if index, ok := byRound[review.RoundID]; ok {
			out[index].Reviews = append(out[index].Reviews, review)
		}
	}
	if err := reviewRows.Close(); err != nil {
		return nil, err
	}
	decisionRows, err := d.Query(`SELECT id,round_id,arbiter_profile_id,decision,rationale,created_at FROM supervisor_decisions WHERE round_id=ANY($1::bigint[])`, ids)
	if err != nil {
		return nil, err
	}
	for decisionRows.Next() {
		var decision SupervisorDecision
		if err := decisionRows.Scan(&decision.ID, &decision.RoundID, &decision.ArbiterProfileID, &decision.Decision, &decision.Rationale, &decision.CreatedAt); err != nil {
			decisionRows.Close()
			return nil, err
		}
		if index, ok := byRound[decision.RoundID]; ok {
			out[index].Decision = &decision
		}
	}
	if err := decisionRows.Close(); err != nil {
		return nil, err
	}
	return out, nil
}
