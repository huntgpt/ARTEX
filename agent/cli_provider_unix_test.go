//go:build unix

package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/norma/llm"
)

func writeFakeCLI(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-cli")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLIProviderCodexStructuredToolCall(t *testing.T) {
	exe := writeFakeCLI(t, `
answer=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "--output-last-message" ]; then answer="$arg"; fi
  previous="$arg"
done
test -n "$answer"
printf '%s' '{"text":"","tool_calls":[{"id":"call-1","name":"probe","input_json":"{\"target\":\"example.com\"}"}],"stop_reason":"tool_use"}' > "$answer"
printf '%s\n' '{"type":"turn.completed","usage":{"input_tokens":12,"output_tokens":7,"cached_input_tokens":3}}'
`)
	dir := t.TempDir()
	provider, err := newCLIProvider(Config{Format: FormatCodexCLI, Model: "test", CLIPath: exe, CLIConfigDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	message, stop, usage, err := provider.Complete(context.Background(), llm.CompletionRequest{
		Messages: []llm.Message{llm.UserText("select the probe tool")},
		Tools:    []llm.ToolSchema{{Name: "probe", InputSchema: map[string]any{"type": "object"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stop != "tool_use" || len(message.ToolUses()) != 1 || message.ToolUses()[0].Name != "probe" {
		t.Fatalf("message=%+v stop=%q", message, stop)
	}
	if usage.InputTokens != 12 || usage.OutputTokens != 7 || usage.CacheReadTokens != 3 {
		t.Fatalf("usage=%+v", usage)
	}
}

func TestCLIProviderClaudeTextAndSanitizedEnvironment(t *testing.T) {
	exe := writeFakeCLI(t, `
test -n "${CLAUDE_CONFIG_DIR:-}"
test -z "${ANTHROPIC_API_KEY:-}"
printf '%s\n' '{"is_error":false,"result":"{\"text\":\"OK\",\"tool_calls\":[],\"stop_reason\":\"end_turn\"}","usage":{"input_tokens":5,"output_tokens":2,"cache_read_input_tokens":1}}'
`)
	t.Setenv("ANTHROPIC_API_KEY", "must-not-reach-child")
	provider, err := newCLIProvider(Config{Format: FormatClaudeCLI, Model: "test", CLIPath: exe, CLIConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	message, stop, usage, err := provider.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}})
	if err != nil {
		t.Fatal(err)
	}
	if message.Text() != "OK" || stop != "end_turn" || usage.InputTokens != 5 || usage.OutputTokens != 2 {
		t.Fatalf("message=%+v stop=%q usage=%+v", message, stop, usage)
	}
}

func TestCLIProviderClaudeOAuthTokenUsesPrivateFileDescriptor(t *testing.T) {
	exe := writeFakeCLI(t, `
test "${CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR:-}" = "3"
test -z "${CLAUDE_CODE_OAUTH_TOKEN:-}"
IFS= read -r token <&3
test "$token" = "oauth-test-token"
printf '%s\n' '{"is_error":false,"result":"{\"text\":\"OK\",\"tool_calls\":[],\"stop_reason\":\"end_turn\"}","usage":{"input_tokens":1,"output_tokens":1}}'
`)
	tokenFile := filepath.Join(t.TempDir(), "oauth-token")
	if err := os.WriteFile(tokenFile, []byte("oauth-test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := newCLIProvider(Config{
		Format: FormatClaudeCLI, Model: "test", CLIPath: exe,
		CLIConfigDir: t.TempDir(), CLIAuthTokenFile: tokenFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	message, _, _, err := provider.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}})
	if err != nil || message.Text() != "OK" {
		t.Fatalf("message=%+v err=%v", message, err)
	}

	if err := os.Chmod(tokenFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := newCLIProvider(Config{
		Format: FormatClaudeCLI, Model: "test", CLIPath: exe,
		CLIConfigDir: t.TempDir(), CLIAuthTokenFile: tokenFile,
	}); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("insecure token file error=%v", err)
	}
}

func TestCLIProviderRejectsUnknownToolsAndSharedImplicitProfile(t *testing.T) {
	_, err := newCLIProvider(Config{Format: FormatCodexCLI, Model: "test", CLIPath: os.Args[0], CLIConfigDir: "relative"})
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("relative config dir error=%v", err)
	}
	_, _, err = normalizeCLIBridgeResponse(cliBridgeResponse{ToolCalls: []cliBridgeToolCall{{Name: "not-allowed", InputJSON: `{}`}}}, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown ARTEX tool") {
		t.Fatalf("unknown tool error=%v", err)
	}
}

func TestCLIProviderCallTimeoutConfiguration(t *testing.T) {
	t.Setenv("ARTEX_LLM_CLI_TIMEOUT", "")
	if got, err := resolveCLICallTimeout(0); err != nil || got != defaultCLICallTimeout {
		t.Fatalf("default timeout = %s, %v; want %s", got, err, defaultCLICallTimeout)
	}
	if got, err := resolveCLICallTimeout(75 * time.Millisecond); err != nil || got != 75*time.Millisecond {
		t.Fatalf("explicit timeout = %s, %v", got, err)
	}
	t.Setenv("ARTEX_LLM_CLI_TIMEOUT", "7m")
	if got, err := resolveCLICallTimeout(0); err != nil || got != 7*time.Minute {
		t.Fatalf("environment timeout = %s, %v", got, err)
	}
	for _, value := range []string{"not-a-duration", "1s", "31m"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("ARTEX_LLM_CLI_TIMEOUT", value)
			if _, err := resolveCLICallTimeout(0); err == nil {
				t.Fatalf("invalid timeout %q accepted", value)
			}
		})
	}
}

func TestCLIProviderTimeoutKillsProcessGroupAndPreservesPartialOutput(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("process-group cancellation is guaranteed on macOS and Linux")
	}
	exe := writeFakeCLI(t, `
printf '%s\n' 'partial-timeout-evidence' >&2
(
  while :; do
    printf x >> "${CLAUDE_CONFIG_DIR}/heartbeat"
    sleep 0.02
  done
) &
wait
`)
	configDir := t.TempDir()
	provider, err := newCLIProvider(Config{
		Format: FormatClaudeCLI, Model: "test", CLIPath: exe,
		// macOS can take hundreds of milliseconds to spawn /bin/sh under the
		// race detector; leave enough time to prove the descendant started.
		CLIConfigDir: configDir, CLICallTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, _, _, err = provider.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}})
	if !errors.Is(err, ErrCLIProviderTimeout) {
		t.Fatalf("timeout error = %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("provider timeout must not classify as task deadline: %v", err)
	}
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() || !networkError.Temporary() {
		t.Fatalf("timeout is not classified as retryable net.Error: %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "partial-timeout-evidence") {
		t.Fatalf("partial stderr was not preserved in provider error: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("timeout returned after %s", elapsed)
	}

	heartbeat := filepath.Join(configDir, "heartbeat")
	before, statErr := os.Stat(heartbeat)
	if statErr != nil || before.Size() == 0 {
		t.Fatalf("descendant never started: info=%v err=%v", before, statErr)
	}
	time.Sleep(150 * time.Millisecond)
	after, statErr := os.Stat(heartbeat)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if after.Size() != before.Size() {
		t.Fatalf("CLI descendant survived process-group cancellation: heartbeat grew %d -> %d", before.Size(), after.Size())
	}
}

func TestCLIProviderParentCancellationIsNotProviderTimeout(t *testing.T) {
	exe := writeFakeCLI(t, `sleep 10`)
	provider, err := newCLIProvider(Config{
		Format: FormatClaudeCLI, Model: "test", CLIPath: exe,
		CLIConfigDir: t.TempDir(), CLICallTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, _, _, err = provider.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrCLIProviderTimeout) {
		t.Fatalf("parent cancellation classification = %v", err)
	}
}

func TestCLIProviderStreamTimeoutFailsOverToNextReadyProfile(t *testing.T) {
	hanging := writeFakeCLI(t, `
printf '%s\n' 'first-profile-stalled' >&2
sleep 10
`)
	success := writeFakeCLI(t, `
printf '%s\n' '{"is_error":false,"result":"{\"text\":\"fallback-ok\",\"tool_calls\":[],\"stop_reason\":\"end_turn\"}","usage":{"input_tokens":2,"output_tokens":1}}'
`)
	first, err := newCLIProvider(Config{
		Format: FormatClaudeCLI, Model: "first", CLIPath: hanging,
		CLIConfigDir: t.TempDir(), CLICallTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := newCLIProvider(Config{
		Format: FormatClaudeCLI, Model: "second", CLIPath: success,
		CLIConfigDir: t.TempDir(), CLICallTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool := llmpool.New([]*llmpool.Member{
		{ID: 1, Name: "stalled", Model: "first", Rank: 2, Prov: first},
		{ID: 2, Name: "ready", Model: "second", Rank: 1, Prov: second},
	}, nil)
	var text, stop string
	var usage llm.Usage
	for event, streamErr := range pool.Stream(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}}) {
		if streamErr != nil {
			t.Fatal(streamErr)
		}
		switch event.Type {
		case llm.SEMessageStart:
			usage = event.Usage
		case llm.SETextDelta:
			text += event.Text
		case llm.SEMessageDelta:
			stop = event.StopReason
		}
	}
	if text != "fallback-ok" || stop != "end_turn" || usage.InputTokens != 2 || usage.OutputTokens != 1 {
		t.Fatalf("fallback result: text=%q stop=%q usage=%+v", text, stop, usage)
	}
}
