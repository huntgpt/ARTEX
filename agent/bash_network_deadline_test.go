package agent

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

type recordingBash struct {
	input json.RawMessage
	tc    *actool.ToolContext
	res   actool.Result
}

func (b *recordingBash) Name() string                           { return "Bash" }
func (b *recordingBash) Description() string                    { return "test bash" }
func (b *recordingBash) Prompt() string                         { return "" }
func (b *recordingBash) InputSchema() map[string]any            { return map[string]any{"type": "object"} }
func (b *recordingBash) IsReadOnly(json.RawMessage) bool        { return false }
func (b *recordingBash) IsConcurrencySafe(json.RawMessage) bool { return false }
func (b *recordingBash) CheckPermissions(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Allowed()
}
func (b *recordingBash) Call(_ context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	b.input = append(b.input[:0], in...)
	b.tc = tc
	return b.res, nil
}

func TestNetworkDeadlineBashBoundsCurlWithoutMutatingContext(t *testing.T) {
	inner := &recordingBash{res: actool.Text("unexpected delegation")}
	manager := &actool.Manager{}
	tc := &actool.ToolContext{WorkingDir: t.TempDir(), Tasks: manager, Env: []string{"MARKER=1"}}
	var gotCommand string
	var gotTimeout time.Duration
	var gotTC *actool.ToolContext
	tool := &networkDeadlineBash{CoreTool: inner, run: func(_ context.Context, command string, timeout time.Duration, callTC *actool.ToolContext) (actool.Result, error) {
		gotCommand, gotTimeout, gotTC = command, timeout, callTC
		return actool.Text("ok"), nil
	}}

	res, err := tool.Call(t.Context(), json.RawMessage(`{"command":"curl -sS https://example.test/","run_in_background":true}`), tc)
	if err != nil || res.IsError || res.Flatten() != "ok" {
		t.Fatalf("Call() = (%q, error=%v), err=%v", res.Flatten(), res.IsError, err)
	}
	if tc.Tasks != manager {
		t.Fatal("wrapper mutated the caller's ToolContext")
	}
	if gotCommand != "curl -sS https://example.test/" || gotTimeout != networkRequestDeadlineMS*time.Millisecond || gotTC != tc {
		t.Fatalf("runner got command=%q timeout=%s tc_same=%v", gotCommand, gotTimeout, gotTC == tc)
	}
	if len(inner.input) != 0 {
		t.Fatalf("request client unexpectedly delegated to background-capable Bash: %s", inner.input)
	}
}

func TestNetworkDeadlineBashPreservesShorterExplicitDeadline(t *testing.T) {
	inner := &recordingBash{res: actool.Text("unexpected delegation")}
	var gotTimeout time.Duration
	tool := &networkDeadlineBash{CoreTool: inner, run: func(_ context.Context, _ string, timeout time.Duration, _ *actool.ToolContext) (actool.Result, error) {
		gotTimeout = timeout
		return actool.Text("ok"), nil
	}}
	_, _ = tool.Call(t.Context(), json.RawMessage(`{"command":"wget https://example.test/x","timeout_ms":12000}`), nil)
	if gotTimeout != 12*time.Second {
		t.Fatalf("timeout = %s, want 12s", gotTimeout)
	}
}

func TestNetworkDeadlineBashLeavesNonRequestCommandsUnchanged(t *testing.T) {
	inner := &recordingBash{res: actool.Text("ok")}
	tool := boundedNetworkBash(inner)
	tc := &actool.ToolContext{Tasks: &actool.Manager{}}
	in := json.RawMessage(`{"command":"go test ./...","timeout_ms":600000,"run_in_background":true}`)
	_, _ = tool.Call(t.Context(), in, tc)
	if string(inner.input) != string(in) || inner.tc != tc {
		t.Fatalf("non-request call changed: input=%s tc_same=%v", inner.input, inner.tc == tc)
	}
}

func TestDefaultToolsBashWrapperPreservesSecurityMetadata(t *testing.T) {
	raw := actool.NewBash()
	var wrapped actool.CoreTool
	for _, candidate := range defaultTools(t.TempDir()) {
		if candidate.Name() == "Bash" {
			wrapped = candidate
			break
		}
	}
	if wrapped == nil {
		t.Fatal("defaultTools omitted Bash")
	}
	if wrapped.Name() != raw.Name() || wrapped.Description() != raw.Description() || wrapped.Prompt() != raw.Prompt() || !reflect.DeepEqual(wrapped.InputSchema(), raw.InputSchema()) {
		t.Fatal("Bash wrapper changed tool identity or advertised schema")
	}
	input := json.RawMessage(`{"command":"curl https://example.test/path"}`)
	permissionContext := permission.Context{Mode: permission.ModeDefault, WorkingDir: t.TempDir()}
	if got, want := wrapped.CheckPermissions(t.Context(), input, permissionContext), raw.CheckPermissions(t.Context(), input, permissionContext); !reflect.DeepEqual(got, want) {
		t.Fatalf("wrapped permission = %#v, want %#v", got, want)
	}
	targets := intercept.ExtractTargets(wrapped.Name(), input)
	if len(targets) != 1 || targets[0].Host != "example.test" {
		t.Fatalf("target gate extraction through wrapped identity = %+v", targets)
	}
	sonarInput := json.RawMessage(`{"command":"BASE=https://sonarqube-dgt.pttdigital.com; curl -sS \"$BASE/api/components/search\" && curl -sS \"$BASE/api/sources/raw?key=project:file\""}`)
	targets = intercept.ExtractTargets(wrapped.Name(), sonarInput)
	if len(targets) != 1 || targets[0].Host != "sonarqube-dgt.pttdigital.com" {
		t.Fatalf("dynamic Sonar command escaped target extraction: %+v", targets)
	}
}

func TestContainsRequestClient(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{`curl -sS https://example.test/`, true},
		{`printf ready && /usr/bin/curl -I https://example.test/`, true},
		{`cat hosts | wget -i -`, true},
		{`env FOO=1 curl https://example.test/`, true},
		{`BASE=https://example.test; curl -sS "$BASE/x"`, true},
		{`BASE=https://sonarqube-dgt.pttdigital.com; curl -sS "$BASE/api/components/search" && curl -sS "$BASE/api/sources/raw?key=project:file"`, true},
		{`env TOKEN="$TOKEN" curl -H "Authorization: Bearer $TOKEN" "$BASE/x"`, true},
		{`echo curl`, false},
		{`printf '%s' wget`, false},
		{`go test ./...`, false},
		{`nmap -p- 192.0.2.1`, false},
		{`rustscan -a 192.0.2.1`, false},
		{`$HTTP_CLIENT https://example.test/`, false},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			if got := containsRequestClient(tt.command); got != tt.want {
				t.Fatalf("containsRequestClient(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestNetworkDeadlineBashAddsEnvironmentalBlockerOnTimeout(t *testing.T) {
	tool := &networkDeadlineBash{CoreTool: &recordingBash{}, run: func(_ context.Context, _ string, timeout time.Duration, _ *actool.ToolContext) (actool.Result, error) {
		return actool.Errorf("curl: (28) timeout\n\n[command timed out after " + timeout.String() + "]\n\n[ARTEX environmental blocker: blocker_type=network_environment; retryable=true; operator_action=none; request process terminated and was not backgrounded]"), nil
	}}
	res, err := tool.Call(t.Context(), json.RawMessage(`{"command":"curl https://example.test/"}`), nil)
	if err != nil || !res.IsError {
		t.Fatalf("Call() = (%q, error=%v), err=%v", res.Flatten(), res.IsError, err)
	}
	for _, want := range []string{"blocker_type=network_environment", "retryable=true", "operator_action=none", "not backgrounded"} {
		if !strings.Contains(res.Flatten(), want) {
			t.Fatalf("result %q missing %q", res.Flatten(), want)
		}
	}
}
