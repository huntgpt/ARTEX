package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func saveRefusalTestProfile(t *testing.T, m *Manager, label string) int64 {
	t.Helper()
	id, err := m.pg.SaveProfile(&db.LLMProfile{
		Name:        label + "-" + time.Now().Format("150405.000000000"),
		Format:      "openai",
		BaseURL:     "http://127.0.0.1:1/v1",
		Model:       label,
		APIKey:      "test-key",
		PoolExclude: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func cleanupRefusalTestTask(t *testing.T, m *Manager, task *Task, profileIDs ...int64) {
	t.Helper()
	_, _ = m.pg.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, task.ID)
	_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
	for _, id := range profileIDs {
		_ = m.pg.DeleteProfile(id)
	}
}

func TestProviderRefusalClassification(t *testing.T) {
	t.Parallel()
	for _, message := range []string{
		`Claude Code failed: { "stop_reason" : "refusal" }`,
		`provider: {"stopReason":"refusal"}`,
		`{"finish_reason":"content_filter"}`,
		`Claude Code returned an error: I'm sorry, but I can't assist with that request.`,
		`Claude Code failed: exit status 1: {"type":"result","is_error":true,"result":"I must decline this request."}`,
		`request refused by safety policy`,
		`blocked by the safety system`,
	} {
		if !isProviderRefusalError(errors.New(message)) {
			t.Errorf("error %q was not classified as a refusal", message)
		}
	}
	for _, message := range []string{
		"connection reset by peer",
		"HTTP status 403 forbidden",
		"the report discusses a content filter",
		`validation failed: {"message":"The provider said: I'm sorry, but I can't assist."}`,
	} {
		if isProviderRefusalError(errors.New(message)) {
			t.Errorf("ordinary error %q was classified as a refusal", message)
		}
	}

	for _, text := range []string{
		"I'm sorry, but I can't assist with that request.",
		"I’m unable to help with that.",
		"I must decline this request.",
	} {
		if !isProviderRefusalResult(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}, "") {
			t.Errorf("assistant text %q was not classified as a refusal", text)
		}
	}
	for _, text := range []string{
		"I cannot confirm the issue without more evidence.",
		"The provider said: I'm sorry, but I can't assist.",
		"I found three authorization gaps.",
	} {
		if isProviderRefusalResult(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}, "end_turn") {
			t.Errorf("ordinary assistant text %q was classified as a refusal", text)
		}
	}
	if !isProviderRefusalResult(llm.Message{}, "content_filter") {
		t.Fatal("content_filter stop reason was not classified as a refusal")
	}
}

func TestTaskLLMRefusalFallbackSticksToTranscriptSession(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	refusedID := saveRefusalTestProfile(t, m, "sticky-refused")
	fallbackID := saveRefusalTestProfile(t, m, "sticky-fallback")
	task, err := m.CreateTaskWithOptions("sticky refusal", "finish one intent", db.TaskCreateOptions{
		LLMProfileIDs: []int64{refusedID, fallbackID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupRefusalTestTask(t, m, task, refusedID, fallbackID)

	refusedUsage := llm.Usage{InputTokens: 3, OutputTokens: 1}
	fallbackUsage := llm.Usage{InputTokens: 5, OutputTokens: 2}
	refused := &supervisorProbeProvider{
		err:   errors.New(`Claude Code failed: { "stop_reason" : "refusal" }`),
		usage: refusedUsage,
	}
	fallback := &supervisorProbeProvider{text: "accepted", usage: fallbackUsage}
	s := &Server{m: m, provByProfile: map[int64]*provEntry{
		refusedID:  {prov: refused, cfg: agent.Config{Model: "sticky-refused"}},
		fallbackID: {prov: fallback, cfg: agent.Config{Model: "sticky-fallback"}},
	}}
	runtime := &taskLLMRuntime{s: s, taskID: task.ID, agentKey: "worker"}
	ctx := transcript.WithSessionID(context.Background(), "exp-sticky-worker-i101")
	ctx = withLLMProfilePin(ctx, refusedID)

	for call := 0; call < 2; call++ {
		msg, _, usage, err := runtime.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("continue")}})
		if err != nil || msg.Text() != "accepted" {
			t.Fatalf("call %d msg=%q err=%v", call, msg.Text(), err)
		}
		want := fallbackUsage
		if call == 0 {
			want.Add(refusedUsage)
		}
		if usage != want {
			t.Fatalf("call %d usage=%+v want=%+v", call, usage, want)
		}
	}
	if got := len(refused.captured()); got != 1 {
		t.Fatalf("refused profile calls=%d want=1; fallback was not sticky", got)
	}
	if got := len(fallback.captured()); got != 2 {
		t.Fatalf("fallback profile calls=%d want=2", got)
	}

	// A different intent/session starts from its own selected profile. Sticky
	// failover must never leak across concurrent worker lanes.
	other := transcript.WithSessionID(context.Background(), "exp-sticky-worker-i202")
	other = withLLMProfilePin(other, refusedID)
	if _, _, _, err := runtime.Complete(other, llm.CompletionRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := len(refused.captured()); got != 2 {
		t.Fatalf("other session did not independently try the selected profile: calls=%d", got)
	}
}

func TestTaskLLMRefusalFallbackOverridesAgentBinding(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	boundID := saveRefusalTestProfile(t, m, "bound-refused")
	fallbackID := saveRefusalTestProfile(t, m, "bound-fallback")
	if err := m.pg.SetAgentLLMProfile("worker", &boundID); err != nil {
		t.Fatal(err)
	}
	task, err := m.CreateTaskWithOptions("bound refusal", "fall back from binding", db.TaskCreateOptions{
		LLMProfileIDs: []int64{fallbackID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = m.pg.SetAgentLLMProfile("worker", nil)
		cleanupRefusalTestTask(t, m, task, boundID, fallbackID)
	}()

	bound := &supervisorProbeProvider{err: errors.New("request refused by safety policy")}
	fallback := &supervisorProbeProvider{text: "alternate accepted"}
	s := &Server{m: m, provByProfile: map[int64]*provEntry{
		boundID:    {prov: bound, cfg: agent.Config{Model: "bound-refused"}},
		fallbackID: {prov: fallback, cfg: agent.Config{Model: "bound-fallback"}},
	}}
	runtime := &taskLLMRuntime{s: s, taskID: task.ID, agentKey: "worker"}
	ctx := transcript.WithSessionID(context.Background(), "exp-bound-worker-i303")
	for call := 0; call < 2; call++ {
		msg, _, _, err := runtime.Complete(ctx, llm.CompletionRequest{})
		if err != nil || msg.Text() != "alternate accepted" {
			t.Fatalf("call %d msg=%q err=%v", call, msg.Text(), err)
		}
	}
	if len(bound.captured()) != 1 || len(fallback.captured()) != 2 {
		t.Fatalf("bound calls=%d fallback calls=%d", len(bound.captured()), len(fallback.captured()))
	}
}

func TestTaskLLMStreamTextRefusalReplaysAndSticks(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	refusedID := saveRefusalTestProfile(t, m, "stream-refused")
	fallbackID := saveRefusalTestProfile(t, m, "stream-fallback")
	task, err := m.CreateTaskWithOptions("stream refusal", "replay before commit", db.TaskCreateOptions{
		LLMProfileIDs: []int64{refusedID, fallbackID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupRefusalTestTask(t, m, task, refusedID, fallbackID)

	refused := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 7}},
		{Type: llm.SETextDelta, Text: "I'm sorry, "},
		{Type: llm.SETextDelta, Text: "but I can't assist with that request."},
		{Type: llm.SEMessageDelta, StopReason: "end_turn", Usage: llm.Usage{OutputTokens: 4}},
		{Type: llm.SEMessageStop},
	}}
	fallback := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 9}},
		{Type: llm.SETextDelta, Text: "validated evidence"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn", Usage: llm.Usage{OutputTokens: 2}},
		{Type: llm.SEMessageStop},
	}}
	s := &Server{m: m, provByProfile: map[int64]*provEntry{
		refusedID:  {prov: refused, cfg: agent.Config{Model: "stream-refused"}},
		fallbackID: {prov: fallback, cfg: agent.Config{Model: "stream-fallback"}},
	}}
	runtime := &taskLLMRuntime{s: s, taskID: task.ID, agentKey: "worker"}
	ctx := transcript.WithSessionID(context.Background(), "exp-stream-worker-i404")
	ctx = withLLMProfilePin(ctx, refusedID)

	for call := 0; call < 2; call++ {
		events, err := collectTaskLLMStream(runtime.Stream(ctx, llm.CompletionRequest{}))
		if err != nil {
			t.Fatalf("call %d: %v", call, err)
		}
		acc := llm.NewAccumulator()
		for _, event := range events {
			acc.Add(event)
		}
		if text := acc.Message().Text(); text != "validated evidence" || strings.Contains(text, "can't assist") {
			t.Fatalf("call %d leaked refusal or lost fallback: %q", call, text)
		}
		wantInput := 9
		if call == 0 {
			wantInput += 7
		}
		wantOutput := 2
		if call == 0 {
			wantOutput += 4
		}
		if acc.Usage.InputTokens != wantInput || acc.Usage.OutputTokens != wantOutput {
			t.Fatalf("call %d usage=%+v want input=%d output=%d", call, acc.Usage, wantInput, wantOutput)
		}
	}
	if refused.calls != 1 || fallback.calls != 2 {
		t.Fatalf("refused calls=%d fallback calls=%d", refused.calls, fallback.calls)
	}
}

// This unit-level test does not need Postgres, so streamed refusal replay and
// cross-provider usage accounting stay covered even when the integration DB is
// unavailable on a developer machine.
func TestTaskLLMStreamRefusalFallbackPreservesUsage(t *testing.T) {
	t.Parallel()
	refused := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 7}},
		{Type: llm.SETextDelta, Text: "I’m unable to help with that request."},
		{Type: llm.SEMessageDelta, StopReason: "end_turn", Usage: llm.Usage{OutputTokens: 4}},
		{Type: llm.SEMessageStop},
	}}
	fallback := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 9}},
		{Type: llm.SETextDelta, Text: "fallback evidence"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn", Usage: llm.Usage{OutputTokens: 2}},
		{Type: llm.SEMessageStop},
	}}
	stuck := int64(0)
	hooks := taskLLMStreamHooks{
		current: func(ctx context.Context) (taskLLMSelection, error) {
			if profileID, ok := llmRefusalProfilePinFrom(ctx); ok && profileID == 22 {
				return taskLLMSelection{profileID: 22, provider: fallback}, nil
			}
			return taskLLMSelection{profileID: 11, provider: refused}, nil
		},
		refusalFallback: func(refusedProfileID int64) int64 {
			if refusedProfileID != 11 {
				t.Fatalf("refused profile=%d want=11", refusedProfileID)
			}
			return 22
		},
		stickRefusalFallback: func(_ context.Context, profileID int64) { stuck = profileID },
	}
	events, err := collectTaskLLMStream(streamTaskLLM(t.Context(), "unit-refusal", llm.CompletionRequest{}, hooks))
	if err != nil {
		t.Fatal(err)
	}
	acc := llm.NewAccumulator()
	for _, event := range events {
		acc.Add(event)
	}
	if got := acc.Message().Text(); got != "fallback evidence" {
		t.Fatalf("text=%q; refused output leaked or fallback output missing", got)
	}
	wantUsage := llm.Usage{InputTokens: 16, OutputTokens: 6}
	if acc.Usage != wantUsage {
		t.Fatalf("usage=%+v want=%+v", acc.Usage, wantUsage)
	}
	if refused.calls != 1 || fallback.calls != 1 || stuck != 22 {
		t.Fatalf("calls refused=%d fallback=%d sticky=%d", refused.calls, fallback.calls, stuck)
	}
}
