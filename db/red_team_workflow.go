package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
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
	states := map[string]string{}
	rows, err := tx.QueryContext(ctx, `SELECT phase,state FROM red_team_phase_runs WHERE exploration_id=$1`, explorationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var phase, state string
		if err := rows.Scan(&phase, &state); err != nil {
			rows.Close()
			return err
		}
		states[phase] = state
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, definition := range RedTeamWorkflow {
		if states[definition.Phase] != "pending" {
			continue
		}
		ready := true
		for _, dependency := range definition.Dependencies {
			state := states[dependency]
			if state != "complete" && state != "skipped" {
				ready = false
				break
			}
		}
		if ready {
			if _, err := tx.ExecContext(ctx, `UPDATE red_team_phase_runs SET state='ready',updated_at=now() WHERE exploration_id=$1 AND phase=$2 AND state='pending'`, explorationID, definition.Phase); err != nil {
				return err
			}
			states[definition.Phase] = "ready"
		}
	}
	return nil
}

func (d *DB) RedTeamWorkflowRuns(ctx context.Context, explorationID int64) ([]RedTeamPhaseRun, error) {
	if err := d.EnsureRedTeamWorkflow(ctx, explorationID); err != nil {
		return nil, err
	}
	rows, err := d.QueryContext(ctx, `SELECT phase,state,owner,tool,current_result,blocker_reason,started_at,finished_at,updated_at FROM red_team_phase_runs WHERE exploration_id=$1`, explorationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byPhase := map[string]RedTeamPhaseRun{}
	for rows.Next() {
		var run RedTeamPhaseRun
		if err := rows.Scan(&run.Phase, &run.State, &run.Owner, &run.Tool, &run.CurrentResult, &run.BlockerReason, &run.StartedAt, &run.FinishedAt, &run.UpdatedAt); err != nil {
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
			out = append(out, run)
		}
	}
	return out, nil
}

func (d *DB) TransitionRedTeamPhase(ctx context.Context, explorationID int64, phase, state, owner, tool, result, blocker string) ([]RedTeamPhaseRun, error) {
	phase, state = strings.TrimSpace(phase), strings.TrimSpace(state)
	definition, exists := redTeamPhaseByName[phase]
	if !exists || !validRedTeamPhaseStates[state] || state == "pending" {
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
	if state == "running" || state == "complete" {
		for _, dependency := range definition.Dependencies {
			var dependencyState string
			if err := tx.QueryRowContext(ctx, `SELECT state FROM red_team_phase_runs WHERE exploration_id=$1 AND phase=$2`, explorationID, dependency).Scan(&dependencyState); err != nil {
				return nil, err
			}
			if dependencyState != "complete" && dependencyState != "skipped" {
				return nil, fmt.Errorf("phase %s waits for %s (%s)", phase, dependency, dependencyState)
			}
		}
	}
	allowed := current == "ready" || current == "running" || current == "blocked" || current == "failed"
	if !allowed || (current == "ready" && state == "complete") {
		return nil, fmt.Errorf("phase %s cannot transition from %s to %s", phase, current, state)
	}
	if state == "blocked" && strings.TrimSpace(blocker) == "" {
		return nil, errors.New("blocked red-team phase requires blocker_reason")
	}
	_, err = tx.ExecContext(ctx, `UPDATE red_team_phase_runs SET state=$3,owner=$4,tool=$5,current_result=$6,
blocker_reason=CASE WHEN $3 IN ('blocked','failed') THEN $7 ELSE '' END,
started_at=CASE WHEN $3='running' AND started_at IS NULL THEN now() ELSE started_at END,
finished_at=CASE WHEN $3 IN ('complete','skipped') THEN now() WHEN $3 IN ('ready','running') THEN NULL ELSE finished_at END,
updated_at=now() WHERE exploration_id=$1 AND phase=$2`, explorationID, phase, state, utf8Clean(owner), utf8Clean(tool), utf8Clean(result), utf8Clean(blocker))
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
