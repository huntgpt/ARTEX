package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type RedTeamPhaseDefinition struct {
	Phase        string   `json:"phase"`
	Label        string   `json:"label"`
	Execution    string   `json:"execution"`
	Tools        []string `json:"tools"`
	Dependencies []string `json:"dependencies"`
}

type RedTeamPhaseRun struct {
	RedTeamPhaseDefinition
	State         string     `json:"state"`
	Owner         string     `json:"owner,omitempty"`
	Tool          string     `json:"tool,omitempty"`
	CurrentResult string     `json:"current_result,omitempty"`
	BlockerReason string     `json:"blocker_reason,omitempty"`
	BlockerKind   string     `json:"blocker_kind,omitempty"`
	BlockerSource string     `json:"blocker_source,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// GoalCompletionRequirements selects the deterministic task-state checks that
// must pass before a broad, end-of-engagement goal may be proved. Ordinary
// narrow goals leave every field false and are unaffected.
type GoalCompletionRequirements struct {
	WorkflowComplete bool
	FindingsVerified bool
	RetestsComplete  bool
	ReportAvailable  bool
}

// GoalCompletionIssues returns precise, stable reasons why a broad red-team
// deliverable cannot close yet. It deliberately does not call
// EnsureRedTeamWorkflow: proof is fail-closed when a goal claims an
// engagement-wide deliverable but its required phase ledger was never created.
func (s *ExplorationStore) GoalCompletionIssues(ctx context.Context, req GoalCompletionRequirements) ([]string, error) {
	if s == nil || (!req.WorkflowComplete && !req.FindingsVerified && !req.RetestsComplete && !req.ReportAvailable) {
		return nil, nil
	}
	var phaseRows int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM red_team_phase_runs WHERE exploration_id=$1`, s.expID).Scan(&phaseRows); err != nil {
		return nil, err
	}
	if phaseRows == 0 {
		return []string{"required red-team phase ledger is missing"}, nil
	}

	issues := []string{}
	if req.WorkflowComplete {
		rows, err := s.db.QueryContext(ctx, `SELECT phase,state FROM red_team_phase_runs
WHERE exploration_id=$1 AND state NOT IN ('complete','skipped') ORDER BY phase`, s.expID)
		if err != nil {
			return nil, err
		}
		var waiting []string
		for rows.Next() {
			var phase, state string
			if err := rows.Scan(&phase, &state); err != nil {
				rows.Close()
				return nil, err
			}
			waiting = append(waiting, phase+"="+state)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		if len(waiting) > 0 {
			issues = append(issues, "red-team phases are unfinished: "+strings.Join(waiting, ", "))
		}
	}

	var taskID int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM tasks WHERE exploration_id=$1 AND deleted_at IS NULL ORDER BY id DESC LIMIT 1`, s.expID).Scan(&taskID)
	if errors.Is(err, sql.ErrNoRows) {
		return append(issues, "task record for the red-team exploration is missing"), nil
	}
	if err != nil {
		return nil, err
	}

	// False positives, duplicates and ignored rows do not hold a deliverable
	// open. Every other finding is part of the assessment output until triage
	// explicitly removes it.
	const actionable = `COALESCE(f.status,'pending') NOT IN ('false_positive','duplicate','ignored')`
	if req.FindingsVerified {
		var pending, unverified int
		q := `SELECT
			count(*) FILTER (WHERE COALESCE(f.status,'pending') IN ('pending','in_progress')),
			count(*) FILTER (WHERE COALESCE(f.verification_status,'unverified') <> 'verified')
		FROM findings f WHERE f.task_id=$1 AND ` + actionable
		if err := s.db.QueryRowContext(ctx, q, taskID).Scan(&pending, &unverified); err != nil {
			return nil, err
		}
		if pending > 0 {
			issues = append(issues, fmt.Sprintf("%d actionable findings still await triage", pending))
		}
		if unverified > 0 {
			issues = append(issues, fmt.Sprintf("%d actionable findings are not verified", unverified))
		}
	}

	if req.RetestsComplete {
		var findings, missing int
		q := `SELECT count(*), count(*) FILTER (WHERE NOT EXISTS (
			SELECT 1 FROM finding_retests r WHERE r.finding_id=f.id AND r.status='completed'
		)) FROM findings f WHERE f.task_id=$1 AND ` + actionable
		if err := s.db.QueryRowContext(ctx, q, taskID).Scan(&findings, &missing); err != nil {
			return nil, err
		}
		if findings == 0 {
			issues = append(issues, "no actionable findings exist for completed retest evidence")
		} else if missing > 0 {
			issues = append(issues, fmt.Sprintf("%d of %d actionable findings have no completed retest", missing, findings))
		}
	}

	if req.ReportAvailable {
		var phaseState, phaseResult string
		err := s.db.QueryRowContext(ctx, `SELECT state,current_result FROM red_team_phase_runs
			WHERE exploration_id=$1 AND phase='report'`, s.expID).Scan(&phaseState, &phaseResult)
		if errors.Is(err, sql.ErrNoRows) {
			issues = append(issues, "report phase is missing")
		} else if err != nil {
			return nil, err
		} else {
			if phaseState != "complete" {
				issues = append(issues, "report phase is "+phaseState+", not complete")
			}
			if strings.TrimSpace(phaseResult) == "" {
				issues = append(issues, "report phase has no recorded report artifact")
			}
		}
		var missing int
		q := `SELECT count(*) FROM findings f WHERE f.task_id=$1 AND ` + actionable + `
			AND (btrim(COALESCE(f.report,''))='' OR f.report_evidence_version < f.evidence_version)`
		if err := s.db.QueryRowContext(ctx, q, taskID).Scan(&missing); err != nil {
			return nil, err
		}
		if missing > 0 {
			issues = append(issues, fmt.Sprintf("%d actionable findings have no current report artifact", missing))
		}
	}
	return issues, nil
}

var RedTeamWorkflow = []RedTeamPhaseDefinition{
	{Phase: "passive_discovery", Label: "Passive discovery", Execution: "artex_automated", Tools: []string{"web_search", "whois", "certificate-transparency"}},
	{Phase: "ownership", Label: "Ownership verification", Execution: "artex_operator_gate", Tools: []string{"rdap", "whois", "dns"}, Dependencies: []string{"passive_discovery"}},
	{Phase: "subdomain_dns", Label: "Subdomain and DNS", Execution: "artex_automated", Tools: []string{"subfinder", "dnsx", "puredns"}, Dependencies: []string{"ownership"}},
	{Phase: "port_service", Label: "Port and service discovery", Execution: "artex_automated", Tools: []string{"naabu", "nmap"}, Dependencies: []string{"subdomain_dns"}},
	{Phase: "http_tls", Label: "HTTP and TLS inventory", Execution: "artex_automated", Tools: []string{"httpx", "tlsx"}, Dependencies: []string{"port_service"}},
	{Phase: "screenshots", Label: "Screenshots", Execution: "artex_automated", Tools: []string{"gowitness"}, Dependencies: []string{"http_tls"}},
	{Phase: "public_source", Label: "GitHub and public-source discovery", Execution: "artex_automated", Tools: []string{"trufflehog", "github-search"}, Dependencies: []string{"ownership"}},
	{Phase: "javascript_api_url", Label: "JavaScript, API and URL discovery", Execution: "artex_automated", Tools: []string{"katana", "gau", "waybackurls", "openapi"}, Dependencies: []string{"http_tls"}},
	{Phase: "path_validation", Label: "Path validation", Execution: "artex_automated", Tools: []string{"opendoor", "ffuf"}, Dependencies: []string{"javascript_api_url"}},
	{Phase: "active_validation", Label: "Active vulnerability validation", Execution: "artex_agent", Tools: []string{"nuclei", "interactsh", "http-replay"}, Dependencies: []string{"path_validation"}},
	{Phase: "ai_analysis", Label: "AI analysis and replanning", Execution: "artex_agent", Tools: []string{"claude-cli", "codex-cli"}, Dependencies: []string{"screenshots", "public_source", "active_validation"}},
	{Phase: "findings", Label: "Findings and evidence", Execution: "artex_agent", Tools: []string{"finding-register", "evidence-store"}, Dependencies: []string{"ai_analysis"}},
	{Phase: "initial_access", Label: "Initial access", Execution: "artex_operator_assisted", Tools: []string{"credential-validation", "exploit-validation"}, Dependencies: []string{"findings"}},
	{Phase: "internal_discovery", Label: "Internal discovery", Execution: "artex_operator_assisted", Tools: []string{"nmap", "ldap", "smb"}, Dependencies: []string{"initial_access"}},
	{Phase: "ad_collection", Label: "AD collection", Execution: "artex_operator_assisted", Tools: []string{"sharphound", "bloodhound-python", "adexplorer"}, Dependencies: []string{"internal_discovery"}},
	{Phase: "ad_core_analysis", Label: "Core AD and Kerberos paths", Execution: "artex_agent", Tools: []string{"bloodhound", "certipy", "netexec", "impacket"}, Dependencies: []string{"ad_collection"}},
	{Phase: "adcs_assessment", Label: "ADCS and enterprise PKI", Execution: "artex_agent", Tools: []string{"certipy", "certify", "bloodhound-adcs"}, Dependencies: []string{"ad_collection"}},
	{Phase: "sccm_mecm_assessment", Label: "SCCM / MECM", Execution: "artex_agent", Tools: []string{"configmanbearpig", "sccmhunter", "sharpsccm"}, Dependencies: []string{"ad_collection"}},
	{Phase: "mssql_assessment", Label: "MSSQL trust and execution paths", Execution: "artex_agent", Tools: []string{"configmanbearpig", "impacket-mssqlclient", "netexec-mssql"}, Dependencies: []string{"ad_collection"}},
	{Phase: "exchange_assessment", Label: "Exchange and hybrid identity", Execution: "artex_agent", Tools: []string{"ldap", "http-replay", "bloodhound-opengraph"}, Dependencies: []string{"ad_collection"}},
	{Phase: "relay_coercion_assessment", Label: "NTLM relay and coercion", Execution: "artex_agent", Tools: []string{"coercer", "responder", "impacket-ntlmrelayx"}, Dependencies: []string{"ad_collection"}},
	{Phase: "acl_gpo_assessment", Label: "ACL and GPO abuse paths", Execution: "artex_agent", Tools: []string{"bloodhound", "bloodyad", "powerview"}, Dependencies: []string{"ad_collection"}},
	{Phase: "delegation_assessment", Label: "Delegation and Kerberos abuse", Execution: "artex_agent", Tools: []string{"bloodhound", "impacket", "rubeus"}, Dependencies: []string{"ad_collection"}},
	{Phase: "shadow_credentials_assessment", Label: "Shadow credentials and key trust", Execution: "artex_agent", Tools: []string{"pywhisker", "whisker", "certipy"}, Dependencies: []string{"ad_collection"}},
	{Phase: "credential_paths_assessment", Label: "LAPS, gMSA, DPAPI and credential paths", Execution: "artex_agent", Tools: []string{"bloodhound", "netexec", "impacket"}, Dependencies: []string{"ad_collection"}},
	{Phase: "ad_analysis", Label: "Converged AD attack-path analysis", Execution: "artex_agent", Tools: []string{"bloodhound", "ad-graph", "claude-cli", "codex-cli"}, Dependencies: []string{"ad_core_analysis", "adcs_assessment", "sccm_mecm_assessment", "mssql_assessment", "exchange_assessment", "relay_coercion_assessment", "acl_gpo_assessment", "delegation_assessment", "shadow_credentials_assessment", "credential_paths_assessment"}},
	{Phase: "ad_access", Label: "AD access validation", Execution: "artex_operator_assisted", Tools: []string{"kerberos", "ldap", "smb"}, Dependencies: []string{"ad_analysis"}},
	{Phase: "retest", Label: "Retest", Execution: "artex_agent", Tools: []string{"http-replay", "finding-retest"}, Dependencies: []string{"findings", "ad_access"}},
	{Phase: "report", Label: "Final report", Execution: "artex_automated", Tools: []string{"report-renderer"}, Dependencies: []string{"retest"}},
}

var redTeamPhaseByName = func() map[string]RedTeamPhaseDefinition {
	out := make(map[string]RedTeamPhaseDefinition, len(RedTeamWorkflow))
	for _, phase := range RedTeamWorkflow {
		out[phase.Phase] = phase
	}
	return out
}()

var validRedTeamPhaseStates = map[string]bool{
	"pending": true, "ready": true, "running": true, "blocked": true,
	"complete": true, "skipped": true, "failed": true,
}

var validRedTeamBlockerKinds = map[string]bool{"dependency": true, "evidence": true, "operational": true}
var validPendingBlockerKinds = map[string]bool{"dependency": true, "evidence": true}

func validateRedTeamBlockerSource(ctx context.Context, tx *sql.Tx, explorationID int64, definition RedTeamPhaseDefinition, blockerKind, blockerSource string, dependencyStates map[string]string) error {
	prefix, value, ok := strings.Cut(blockerSource, ":")
	if !ok || strings.TrimSpace(value) == "" {
		return errors.New("blocker_source must be a typed durable reference")
	}
	value = strings.TrimSpace(value)
	switch blockerKind {
	case "dependency":
		if prefix != "phase" {
			return errors.New("dependency blocker_source must be phase:<dependency>")
		}
		isDependency := false
		for _, dependency := range definition.Dependencies {
			if value == dependency {
				isDependency = true
				break
			}
		}
		if !isDependency {
			return fmt.Errorf("phase %s is not a dependency of %s", value, definition.Phase)
		}
		state := dependencyStates[value]
		if state == "complete" || state == "skipped" {
			return fmt.Errorf("dependency blocker_source phase:%s is already %s", value, state)
		}
	case "evidence":
		if prefix != KindFact && prefix != KindIntent {
			return errors.New("evidence blocker_source must be fact:<id> or intent:<id>")
		}
		nodeID, err := strconv.ParseInt(value, 10, 64)
		if err != nil || nodeID <= 0 {
			return errors.New("evidence blocker_source contains an invalid node id")
		}
		var kind string
		err = tx.QueryRowContext(ctx, `SELECT kind FROM exploration_nodes WHERE exploration_id=$1 AND id=$2`, explorationID, nodeID).Scan(&kind)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("evidence blocker_source does not exist in this exploration")
		}
		if err != nil {
			return err
		}
		if kind != prefix {
			return fmt.Errorf("evidence blocker_source expected %s but node is %s", prefix, kind)
		}
	}
	return nil
}

func (d *DB) EnsureRedTeamWorkflow(ctx context.Context, explorationID int64) error {
	if explorationID <= 0 {
		return errors.New("red-team workflow requires an exploration")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, phase := range RedTeamWorkflow {
		if _, err := tx.ExecContext(ctx, `INSERT INTO red_team_phase_runs(exploration_id,phase) VALUES($1,$2) ON CONFLICT DO NOTHING`, explorationID, phase.Phase); err != nil {
			return err
		}
	}
	if err := refreshRedTeamReady(ctx, tx, explorationID); err != nil {
		return err
	}
	return tx.Commit()
}

func refreshRedTeamReady(ctx context.Context, tx *sql.Tx, explorationID int64) error {
	type phaseState struct {
		state       string
		blockerKind string
	}
	states := map[string]phaseState{}
	rows, err := tx.QueryContext(ctx, `SELECT phase,state,blocker_kind FROM red_team_phase_runs WHERE exploration_id=$1`, explorationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var phase string
		var item phaseState
		if err := rows.Scan(&phase, &item.state, &item.blockerKind); err != nil {
			rows.Close()
			return err
		}
		states[phase] = item
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, definition := range RedTeamWorkflow {
		current := states[definition.Phase]
		if current.state != "pending" && !(current.state == "blocked" && current.blockerKind == "dependency") {
			continue
		}
		ready := true
		for _, dependency := range definition.Dependencies {
			state := states[dependency].state
			if state != "complete" && state != "skipped" {
				ready = false
				break
			}
		}
		if ready {
			if _, err := tx.ExecContext(ctx, `UPDATE red_team_phase_runs
SET state='ready', blocker_reason='', blocker_kind='', blocker_source='', finished_at=NULL, updated_at=now()
WHERE exploration_id=$1 AND phase=$2
  AND (state='pending' OR (state='blocked' AND blocker_kind='dependency'))`, explorationID, definition.Phase); err != nil {
				return err
			}
			states[definition.Phase] = phaseState{state: "ready"}
		}
	}
	return nil
}

func (d *DB) RedTeamWorkflowRuns(ctx context.Context, explorationID int64) ([]RedTeamPhaseRun, error) {
	if err := d.EnsureRedTeamWorkflow(ctx, explorationID); err != nil {
		return nil, err
	}
	rows, err := d.QueryContext(ctx, `SELECT phase,state,owner,tool,current_result,blocker_reason,blocker_kind,blocker_source,started_at,finished_at,updated_at FROM red_team_phase_runs WHERE exploration_id=$1`, explorationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byPhase := map[string]RedTeamPhaseRun{}
	for rows.Next() {
		var run RedTeamPhaseRun
		if err := rows.Scan(&run.Phase, &run.State, &run.Owner, &run.Tool, &run.CurrentResult, &run.BlockerReason, &run.BlockerKind, &run.BlockerSource, &run.StartedAt, &run.FinishedAt, &run.UpdatedAt); err != nil {
			return nil, err
		}
		run.RedTeamPhaseDefinition = redTeamPhaseByName[run.Phase]
		byPhase[run.Phase] = run
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]RedTeamPhaseRun, 0, len(RedTeamWorkflow))
	for _, definition := range RedTeamWorkflow {
		if run, ok := byPhase[definition.Phase]; ok {
			// JSON arrays must stay arrays even when a phase has no dependencies.
			// A nil slice marshals as null and used to crash the Progress UI.
			if run.Tools == nil {
				run.Tools = []string{}
			}
			if run.Dependencies == nil {
				run.Dependencies = []string{}
			}
			out = append(out, run)
		}
	}
	return out, nil
}

func (d *DB) TransitionRedTeamPhase(ctx context.Context, explorationID int64, phase, state, owner, tool, result, blocker, blockerKind, blockerSource string) ([]RedTeamPhaseRun, error) {
	phase, state = strings.TrimSpace(phase), strings.TrimSpace(state)
	blocker, blockerKind, blockerSource = strings.TrimSpace(blocker), strings.TrimSpace(blockerKind), strings.TrimSpace(blockerSource)
	definition, exists := redTeamPhaseByName[phase]
	if !exists || !validRedTeamPhaseStates[state] {
		return nil, fmt.Errorf("invalid red-team phase transition %q -> %q", phase, state)
	}
	if err := d.EnsureRedTeamWorkflow(ctx, explorationID); err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM red_team_phase_runs WHERE exploration_id=$1 AND phase=$2 FOR UPDATE`, explorationID, phase).Scan(&current); err != nil {
		return nil, err
	}
	dependenciesReady := true
	var waitingDependencies []string
	dependencyStates := map[string]string{}
	if state == "ready" || state == "running" || state == "complete" || (state == "blocked" && blockerKind == "dependency") {
		for _, dependency := range definition.Dependencies {
			var dependencyState string
			if err := tx.QueryRowContext(ctx, `SELECT state FROM red_team_phase_runs WHERE exploration_id=$1 AND phase=$2`, explorationID, dependency).Scan(&dependencyState); err != nil {
				return nil, err
			}
			dependencyStates[dependency] = dependencyState
			if dependencyState != "complete" && dependencyState != "skipped" {
				dependenciesReady = false
				waitingDependencies = append(waitingDependencies, dependency+" ("+dependencyState+")")
			}
		}
	}
	if (state == "ready" || state == "running" || state == "complete") && !dependenciesReady {
		return nil, fmt.Errorf("phase %s waits for %s", phase, strings.Join(waitingDependencies, ", "))
	}
	allowed := current == "ready" || current == "running" || current == "blocked" || current == "failed" || (current == "pending" && state == "blocked")
	if !allowed || (current == "ready" && state == "complete") || (state == "pending" && current != "blocked" && current != "failed") {
		return nil, fmt.Errorf("phase %s cannot transition from %s to %s", phase, current, state)
	}
	if state == "blocked" && blocker == "" {
		return nil, errors.New("blocked red-team phase requires blocker_reason")
	}
	if state == "blocked" && blockerKind == "" {
		blockerKind = "operational"
	}
	if state == "blocked" && !validRedTeamBlockerKinds[blockerKind] {
		return nil, errors.New("blocked red-team phase requires blocker_kind dependency, evidence, or operational")
	}
	if state == "blocked" && (blockerKind == "dependency" || blockerKind == "evidence") && blockerSource == "" {
		return nil, errors.New("dependency/evidence blocker requires blocker_source provenance")
	}
	if state == "blocked" && (blockerKind == "dependency" || blockerKind == "evidence") {
		if err := validateRedTeamBlockerSource(ctx, tx, explorationID, definition, blockerKind, blockerSource, dependencyStates); err != nil {
			return nil, err
		}
	}
	if state == "blocked" && blockerKind == "dependency" && dependenciesReady {
		return nil, fmt.Errorf("phase %s has no unfinished dependency to block on", phase)
	}
	if current == "pending" && state == "blocked" {
		if !validPendingBlockerKinds[blockerKind] {
			return nil, errors.New("blocking a pending red-team phase requires blocker_kind dependency or evidence")
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE red_team_phase_runs SET state=$3,owner=$4,tool=$5,current_result=$6,
blocker_reason=CASE WHEN $3 IN ('blocked','failed') THEN $7 ELSE '' END,
blocker_kind=CASE WHEN $3 IN ('blocked','failed') THEN $8 ELSE '' END,
blocker_source=CASE WHEN $3 IN ('blocked','failed') THEN $9 ELSE '' END,
started_at=CASE WHEN $3='running' AND started_at IS NULL THEN now() ELSE started_at END,
finished_at=CASE WHEN $3 IN ('complete','skipped') THEN now() WHEN $3 IN ('pending','ready','running') THEN NULL ELSE finished_at END,
updated_at=now() WHERE exploration_id=$1 AND phase=$2`, explorationID, phase, state, utf8Clean(owner), utf8Clean(tool), utf8Clean(result), utf8Clean(blocker), utf8Clean(blockerKind), utf8Clean(blockerSource))
	if err != nil {
		return nil, err
	}
	if err := refreshRedTeamReady(ctx, tx, explorationID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.RedTeamWorkflowRuns(ctx, explorationID)
}
