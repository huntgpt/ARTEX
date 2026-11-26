package server

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type supervisorProbeProvider struct {
	mu       sync.Mutex
	text     string
	err      error
	usage    llm.Usage
	entered  chan<- string
	release  <-chan struct{}
	requests []llm.CompletionRequest
}

func (p *supervisorProbeProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.mu.Lock()
	p.requests = append(p.requests, req)
	p.mu.Unlock()
	if p.entered != nil {
		select {
		case p.entered <- req.Messages[0].Text():
		case <-ctx.Done():
			return llm.Message{}, "", llm.Usage{}, ctx.Err()
		}
	}
	if p.release != nil {
		select {
		case <-p.release:
		case <-ctx.Done():
			return llm.Message{}, "", llm.Usage{}, ctx.Err()
		}
	}
	if p.err != nil {
		return llm.Message{}, "", p.usage, p.err
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.text)}}, "end_turn", p.usage, nil
}

func (p *supervisorProbeProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		_, _, _, err := p.Complete(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
		}
	}
}

func (p *supervisorProbeProvider) captured() []llm.CompletionRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]llm.CompletionRequest(nil), p.requests...)
}

func createSupervisorRuntimeFixture(t *testing.T, primary, secondary, arbiter llm.Provider) (*Server, *Task, int64, int64, int64) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	profile := func(name, format, model string) int64 {
		t.Helper()
		id, err := m.pg.SaveProfile(&db.LLMProfile{
			Name: name + "-" + time.Now().Format("150405.000000000"), Format: format,
			Model: model, APIKey: "test-key", PoolExclude: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	primaryID := profile("supervisor-primary", "codex-cli", "codex-test")
	secondaryID := profile("supervisor-secondary", "claude-cli", "claude-test")
	arbiterID := profile("supervisor-arbiter", "openai", "arbiter-test")
	cfg := db.TaskSupervisorConfig{
		Mode: db.SupervisorModeDual, PrimaryProfileID: &primaryID, SecondaryProfileID: &secondaryID,
		CheckpointPolicy: db.SupervisorCheckpointEveryRound, Revision: 1,
	}
	task, err := m.CreateTaskWithOptions("dual lead runtime test", "produce an audited plan", db.TaskCreateOptions{
		LLMProfileIDs: []int64{arbiterID}, Supervisor: &cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
		_ = m.pg.DeleteProfile(primaryID)
		_ = m.pg.DeleteProfile(secondaryID)
		_ = m.pg.DeleteProfile(arbiterID)
	})
	s := &Server{m: m, provByProfile: map[int64]*provEntry{}}
	s.provByProfile[primaryID] = &provEntry{prov: primary, cfg: agent.Config{Model: "codex-test", MaxTokens: 4000}}
	s.provByProfile[secondaryID] = &provEntry{prov: secondary, cfg: agent.Config{Model: "claude-test", MaxTokens: 4000}}
	s.provByProfile[arbiterID] = &provEntry{prov: arbiter, cfg: agent.Config{Model: "arbiter-test", MaxTokens: 4000}}
	return s, task, primaryID, secondaryID, arbiterID
}

func TestDualSupervisorRunsLeadsConcurrentlyOnIdenticalSnapshot(t *testing.T) {
	entered := make(chan string, 2)
	release := make(chan struct{})
	primary := &supervisorProbeProvider{
		text:  `{"assessment":"primary","recommended_directions":[],"evidence_gaps":[],"conflicts_or_challenges":[],"stop_or_continue":"continue","blocking_conditions":[]}`,
		usage: llm.Usage{InputTokens: 31, OutputTokens: 7}, entered: entered, release: release,
	}
	secondary := &supervisorProbeProvider{
		text:  `{"assessment":"secondary","recommended_directions":[],"evidence_gaps":[],"conflicts_or_challenges":[],"stop_or_continue":"continue","blocking_conditions":[]}`,
		usage: llm.Usage{InputTokens: 29, OutputTokens: 8}, entered: entered, release: release,
	}
	arbiter := &supervisorProbeProvider{text: `{"consensus_summary":"continue with evidence-backed work","selected_directions":[],"rejected_directions":[],"conflicts":[],"idle_slot_reasons":[],"planner_constraints":[]}`}
	s, task, _, _, _ := createSupervisorRuntimeFixture(t, primary, secondary, arbiter)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type outcome struct {
		advice agent.SupervisorAdvice
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		advice, err := s.runSupervisorCheckpoint(ctx, task, nil, "manual")
		done <- outcome{advice: advice, err: err}
	}()

	first := <-entered
	second := <-entered // proves both lead calls started before either was released
	if first != second {
		t.Fatalf("leads received different snapshots\nprimary=%s\nsecondary=%s", first, second)
	}
	close(release)
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.advice.State != "completed" || result.advice.RoundID <= 0 || len(result.advice.Primary) == 0 || len(result.advice.Secondary) == 0 {
		t.Fatalf("unexpected advice: %+v", result.advice)
	}
	rounds, err := s.m.pg.SupervisorRoundDetails(mustTaskID(t, task.ID), 1)
	if err != nil || len(rounds) != 1 {
		t.Fatalf("rounds=%+v err=%v", rounds, err)
	}
	if rounds[0].SnapshotHash != result.advice.SnapshotHash || len(rounds[0].Reviews) != 2 || rounds[0].Decision == nil {
		t.Fatalf("persisted round is incomplete: %+v", rounds[0])
	}
	for _, review := range rounds[0].Reviews {
		if review.State != "completed" || review.AccountLabel == "" || review.Provider == "" || review.Model == "" {
			t.Fatalf("review identity/state not persisted: %+v", review)
		}
	}
	if len(arbiter.captured()) != 1 {
		t.Fatalf("arbiter calls=%d want 1", len(arbiter.captured()))
	}
}

func TestSupervisorSnapshotCarriesCurrentPlatformWorkerAndApprovalState(t *testing.T) {
	primary := &supervisorProbeProvider{text: `{"assessment":"read current runtime state","recommended_directions":[],"evidence_gaps":[],"conflicts_or_challenges":[],"stop_or_continue":"continue","blocking_conditions":[]}`}
	secondary := &supervisorProbeProvider{text: `{"assessment":"independent runtime check","recommended_directions":[],"evidence_gaps":[],"conflicts_or_challenges":[],"stop_or_continue":"continue","blocking_conditions":[]}`}
	arbiter := &supervisorProbeProvider{text: `{"consensus_summary":"use current enabled capabilities","selected_directions":[],"rejected_directions":[],"conflicts":[],"idle_slot_reasons":[],"planner_constraints":[]}`}
	s, task, _, _, _ := createSupervisorRuntimeFixture(t, primary, secondary, arbiter)

	oldCapture := s.m.TrafficEnabled()
	oldBinding := s.m.PG().GetBool(settingAgentTrafficBinding, false)
	if err := s.m.SetTrafficEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := s.m.PG().SetBool(settingAgentTrafficBinding, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = s.m.SetTrafficEnabled(oldCapture)
		_ = s.m.PG().SetBool(settingAgentTrafficBinding, oldBinding)
	})

	openIntent, err := task.Store.AddIntent(map[string]any{"summary": "ready current work"}, 6, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	runningIntent, err := task.Store.AddIntent(map[string]any{"summary": "live current work"}, 8, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if token, err := task.Store.ClaimIntentToken(runningIntent, "work#snapshot"); err != nil || token == "" {
		t.Fatalf("claim token=%q err=%v", token, err)
	}

	pendingApproval, err := s.m.PG().CreateInterceptPending(0, 0, task.ID, "worker", "Bash", []byte(`{"password":"approval-secret-never-prompted"}`), "reason contains another-secret-never-prompted")
	if err != nil {
		t.Fatal(err)
	}
	deniedApproval, err := s.m.PG().CreateInterceptPending(0, 0, task.ID, "worker", "WebFetch", []byte(`{"authorization":"Bearer hidden-token-never-prompted"}`), "denied secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.m.PG().DecideInterceptPending(deniedApproval, "denied"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.m.PG().Exec(`DELETE FROM intercept_pending WHERE id IN ($1,$2)`, pendingApproval, deniedApproval)
	})

	findingNode, err := task.Store.AddNode(db.KindFinding, map[string]any{"summary": "finding without traffic proof"}, 9, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	findingID, err := task.Store.AddStandaloneFinding(taskID, findingNode, "test", "binding distinction", "high", "finding", "evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.PG().Exec(`DELETE FROM findings WHERE id=$1`, findingID) })

	advice, err := s.runSupervisorCheckpoint(context.Background(), task, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	requests := primary.captured()
	if len(requests) != 1 {
		t.Fatalf("primary requests=%d want 1", len(requests))
	}
	rawSnapshot := requests[0].Messages[0].Text()
	for _, forbidden := range []string{"approval-secret-never-prompted", "another-secret-never-prompted", "hidden-token-never-prompted"} {
		if strings.Contains(rawSnapshot, forbidden) {
			t.Fatalf("supervisor snapshot leaked approval secret %q", forbidden)
		}
	}
	var snapshot struct {
		RuntimeState map[string]any `json:"runtime_state"`
	}
	if err := json.Unmarshal([]byte(rawSnapshot), &snapshot); err != nil {
		t.Fatal(err)
	}
	traffic := snapshot.RuntimeState["traffic_capture"].(map[string]any)
	expectedRecorder := s.m.Traffic() != nil
	if traffic["enabled"] != true || traffic["recorder_available"] != expectedRecorder || traffic["tools_available"] != expectedRecorder {
		t.Fatalf("traffic state=%+v, want enabled with recorder availability=%v", traffic, expectedRecorder)
	}
	binding := snapshot.RuntimeState["agent_traffic_binding"].(map[string]any)
	if binding["enabled"] != true || binding["bindings_total"].(float64) != 0 || binding["unbound_findings_total"].(float64) != 1 {
		t.Fatalf("binding state=%+v, enabled must be distinct from zero bound proof", binding)
	}
	workers := snapshot.RuntimeState["workers"].(map[string]any)
	counts := workers["intent_state_counts"].(map[string]any)
	if counts["open"].(float64) < 1 || counts["running"].(float64) < 1 {
		t.Fatalf("worker counts=%+v", counts)
	}
	intents := workers["current_intents"].([]any)
	seenOpen, seenRunning := false, false
	for _, raw := range intents {
		intent := raw.(map[string]any)
		id := int64(intent["intent_id"].(float64))
		seenOpen = seenOpen || (id == openIntent && intent["state"] == "open")
		seenRunning = seenRunning || (id == runningIntent && intent["state"] == "running" && intent["worker"] == "work#snapshot")
	}
	if !seenOpen || !seenRunning {
		t.Fatalf("current intents omit ready/running state: %+v", intents)
	}
	approvals := snapshot.RuntimeState["approvals"].(map[string]any)
	approvalCounts := approvals["status_counts"].(map[string]any)
	if approvalCounts["pending"].(float64) != 1 || approvalCounts["denied"].(float64) != 1 {
		t.Fatalf("approval counts=%+v", approvalCounts)
	}

	// The arbiter and returned Planner advice must receive the same scrubbed,
	// immutable runtime object rather than re-reading settings after the leads.
	if len(advice.RuntimeState) == 0 {
		t.Fatal("Planner advice omitted authoritative runtime state")
	}
	arbiterRequests := arbiter.captured()
	if len(arbiterRequests) != 1 || !strings.Contains(arbiterRequests[0].Messages[0].Text(), `"current_runtime_state"`) ||
		!strings.Contains(arbiterRequests[0].Messages[0].Text(), `"agent_traffic_binding":{"bindings_total":0,"enabled":true`) {
		t.Fatalf("arbiter did not receive authoritative runtime state: %+v", arbiterRequests)
	}
	var adviceRuntime map[string]any
	if err := json.Unmarshal(advice.RuntimeState, &adviceRuntime); err != nil || adviceRuntime["traffic_capture"] == nil {
		t.Fatalf("advice runtime=%s err=%v", advice.RuntimeState, err)
	}
}

func TestSupervisorDegradesToPersistedFallbackWhenOneLeadAndArbiterFail(t *testing.T) {
	primary := &supervisorProbeProvider{text: `{"assessment":"primary survives","recommended_directions":[],"evidence_gaps":[],"conflicts_or_challenges":[],"stop_or_continue":"continue","blocking_conditions":[]}`}
	secondary := &supervisorProbeProvider{err: errors.New("secondary unavailable")}
	arbiter := &supervisorProbeProvider{err: errors.New("arbiter unavailable")}
	s, task, _, _, _ := createSupervisorRuntimeFixture(t, primary, secondary, arbiter)

	advice, err := s.runSupervisorCheckpoint(context.Background(), task, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if advice.State != "partial" || advice.DegradedCause == "" || len(advice.Decision) == 0 || len(advice.Primary) == 0 || len(advice.Secondary) != 0 {
		t.Fatalf("unexpected degraded advice: %+v", advice)
	}
	rounds, err := s.m.pg.SupervisorRoundDetails(mustTaskID(t, task.ID), 1)
	if err != nil || len(rounds) != 1 {
		t.Fatalf("rounds=%+v err=%v", rounds, err)
	}
	if rounds[0].State != "partial" || rounds[0].Decision == nil {
		t.Fatalf("fallback decision was not persisted: %+v", rounds[0])
	}
	failed := 0
	for _, review := range rounds[0].Reviews {
		if review.State == "failed" {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("failed reviews=%d want 1: %+v", failed, rounds[0].Reviews)
	}
}

func TestSupervisorCheckpointPolicyAndJSONExtraction(t *testing.T) {
	if trigger, ok := strategicSupervisorTrigger([]agent.TriggerEvent{{Kind: "worker_done"}, {Kind: "finding"}}); !ok || trigger != "finding" {
		t.Fatalf("strategic trigger=%q ok=%v", trigger, ok)
	}
	raw, err := extractSupervisorObject("```json\n{\"assessment\":\"ok\"}\n```")
	if err != nil || string(raw) != `{"assessment":"ok"}` {
		t.Fatalf("raw=%s err=%v", raw, err)
	}
	if _, err := extractSupervisorObject("no object"); err == nil {
		t.Fatal("missing JSON object must fail")
	}
}

func TestManualSupervisorEndpointPersistsAdviceAndWakesPlanner(t *testing.T) {
	primary := &supervisorProbeProvider{text: `{"assessment":"primary","recommended_directions":[],"evidence_gaps":[],"conflicts_or_challenges":[],"stop_or_continue":"continue","blocking_conditions":[]}`}
	secondary := &supervisorProbeProvider{text: `{"assessment":"secondary","recommended_directions":[],"evidence_gaps":[],"conflicts_or_challenges":[],"stop_or_continue":"continue","blocking_conditions":[]}`}
	arbiter := &supervisorProbeProvider{text: `{"consensus_summary":"consume this manual decision","selected_directions":[],"rejected_directions":[],"conflicts":[],"idle_slot_reasons":[],"planner_constraints":[]}`}
	s, task, _, _, _ := createSupervisorRuntimeFixture(t, primary, secondary, arbiter)
	// Creation may have queued a startup wake. The endpoint must contribute its
	// own wake only after the decision has been durably saved.
	for {
		select {
		case <-task.notify:
		default:
			goto drained
		}
	}
drained:
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+task.ID+"/supervisor/run", nil)
	req.SetPathValue("id", task.ID)
	recorder := httptest.NewRecorder()
	s.runTaskSupervisor(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	select {
	case <-task.notify:
	case <-time.After(time.Second):
		t.Fatal("manual supervisor endpoint did not wake the Planner")
	}
	taskID := mustTaskID(t, task.ID)
	advice, pending, err := s.pendingManualSupervisorAdvice(taskID)
	if err != nil || !pending || advice.RoundID <= 0 || advice.Rationale != "consume this manual decision" {
		t.Fatalf("pending=%v advice=%+v err=%v", pending, advice, err)
	}
	if _, err := task.Store.AppendActivity(db.Activity{Worker: "planner", Kind: "round", Summary: "consumed manual review"}); err != nil {
		t.Fatal(err)
	}
	if advice, pending, err = s.pendingManualSupervisorAdvice(taskID); err != nil || pending || advice.RoundID != 0 {
		t.Fatalf("manual advice remained pending after Planner marker: pending=%v advice=%+v err=%v", pending, advice, err)
	}
}

func TestConcurrentSupervisorCheckpointCannotFailActiveRound(t *testing.T) {
	entered := make(chan string, 2)
	release := make(chan struct{})
	primary := &supervisorProbeProvider{
		text:    `{"assessment":"primary","recommended_directions":[],"evidence_gaps":[],"conflicts_or_challenges":[],"stop_or_continue":"continue","blocking_conditions":[]}`,
		entered: entered, release: release,
	}
	secondary := &supervisorProbeProvider{
		text:    `{"assessment":"secondary","recommended_directions":[],"evidence_gaps":[],"conflicts_or_challenges":[],"stop_or_continue":"continue","blocking_conditions":[]}`,
		entered: entered, release: release,
	}
	arbiter := &supervisorProbeProvider{text: `{"consensus_summary":"done","selected_directions":[],"rejected_directions":[],"conflicts":[],"idle_slot_reasons":[],"planner_constraints":[]}`}
	s, task, _, _, _ := createSupervisorRuntimeFixture(t, primary, secondary, arbiter)
	type outcome struct {
		advice agent.SupervisorAdvice
		err    error
	}
	firstDone := make(chan outcome, 1)
	go func() {
		advice, err := s.runSupervisorCheckpoint(context.Background(), task, nil, "manual")
		firstDone <- outcome{advice: advice, err: err}
	}()
	<-entered
	<-entered
	if _, err := s.runSupervisorCheckpoint(context.Background(), task, nil, "manual"); !errors.Is(err, errSupervisorRoundActive) {
		t.Fatalf("concurrent checkpoint error=%v, want errSupervisorRoundActive", err)
	}
	close(release)
	first := <-firstDone
	if first.err != nil || first.advice.RoundID <= 0 {
		t.Fatalf("first checkpoint advice=%+v err=%v", first.advice, first.err)
	}
	rounds, err := s.m.PG().SupervisorRoundDetails(mustTaskID(t, task.ID), 10)
	if err != nil || len(rounds) != 1 || rounds[0].State != "completed" {
		t.Fatalf("active round was corrupted: rounds=%+v err=%v", rounds, err)
	}
}

func TestTaskLLMCompleteReplaysRefusalOnDifferentReadyProfile(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	newProfile := func(label string) int64 {
		t.Helper()
		id, err := m.pg.SaveProfile(&db.LLMProfile{
			Name: label + "-" + time.Now().Format("150405.000000000"), Format: "openai",
			BaseURL: "http://127.0.0.1:1/v1", Model: label, APIKey: "test-key", PoolExclude: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	refusedID := newProfile("refusal-source")
	fallbackID := newProfile("refusal-fallback")
	task, err := m.CreateTaskWithOptions("refusal fallback", "keep the worker lane moving", db.TaskCreateOptions{
		LLMProfileIDs: []int64{refusedID, fallbackID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = m.pg.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, task.ID)
		_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
		_ = m.pg.DeleteProfile(refusedID)
		_ = m.pg.DeleteProfile(fallbackID)
	}()
	refused := &supervisorProbeProvider{err: errors.New(`Claude Code failed: {"stop_reason":"refusal","result":"safeguards flagged this message"}`)}
	fallback := &supervisorProbeProvider{text: "fallback completed", usage: llm.Usage{InputTokens: 5, OutputTokens: 2}}
	s := &Server{m: m, provByProfile: map[int64]*provEntry{
		refusedID:  {prov: refused, cfg: agent.Config{Model: "refusal-source"}},
		fallbackID: {prov: fallback, cfg: agent.Config{Model: "refusal-fallback"}},
	}}
	runtime := &taskLLMRuntime{s: s, taskID: task.ID, agentKey: "worker"}
	for attempt := 0; attempt < llmFailStreakThreshold+1; attempt++ {
		msg, _, usage, err := runtime.Complete(withLLMProfilePin(context.Background(), refusedID), llm.CompletionRequest{
			Messages: []llm.Message{llm.UserText("authorized assessment")},
		})
		if err != nil {
			t.Fatal(err)
		}
		if msg.Text() != "fallback completed" || usage.InputTokens != 5 || usage.OutputTokens != 2 {
			t.Fatalf("attempt %d message=%q usage=%+v", attempt, msg.Text(), usage)
		}
	}
	if len(refused.captured()) != llmFailStreakThreshold+1 || len(fallback.captured()) != llmFailStreakThreshold+1 {
		t.Fatalf("refused calls=%d fallback calls=%d, want %d each", len(refused.captured()), len(fallback.captured()), llmFailStreakThreshold+1)
	}
	if !isProviderRefusalError(refused.err) || isProviderRefusalError(errors.New("connection reset")) {
		t.Fatal("provider refusal classification is incorrect")
	}
	persisted, err := m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	if persisted == nil || len(persisted.ReadyLLMProfileIDs) != 2 {
		t.Fatalf("policy refusals changed durable profile health: %+v", persisted)
	}
}
