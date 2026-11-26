//go:build unix

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
