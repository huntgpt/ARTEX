//go:build unix

package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestCLIProviderClaudeRefusalPreservesUsage(t *testing.T) {
	exe := writeFakeCLI(t, `
printf '%s\n' '{"is_error":true,"result":"{\"stop_reason\":\"refusal\"}","usage":{"input_tokens":17,"output_tokens":3,"cache_read_input_tokens":5,"cache_creation_input_tokens":2}}'
`)
	provider, err := newCLIProvider(Config{Format: FormatClaudeCLI, Model: "test", CLIPath: exe, CLIConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	_, _, usage, err := provider.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}})
	if err == nil || !strings.Contains(err.Error(), `"stop_reason":"refusal"`) {
		t.Fatalf("refusal error=%v", err)
	}
	if usage.InputTokens != 17 || usage.OutputTokens != 3 || usage.CacheReadTokens != 5 || usage.CacheWriteTokens != 2 {
		t.Fatalf("usage=%+v", usage)
	}
}

func TestCLIProviderClaudePrefixedBridgeKeepsUsage(t *testing.T) {
	exe := writeFakeCLI(t, `
printf '%s\n' '{"is_error":false,"result":"Bridge response:\\n\u0060\u0060\u0060json\\n{\"text\":\"OK\",\"tool_calls\":[],\"stop_reason\":\"end_turn\"}\\n\u0060\u0060\u0060","usage":{"input_tokens":9,"output_tokens":4,"cache_read_input_tokens":2}}'
`)
	provider, err := newCLIProvider(Config{Format: FormatClaudeCLI, Model: "test", CLIPath: exe, CLIConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	message, stop, usage, err := provider.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}})
	if err != nil {
		t.Fatal(err)
	}
	if message.Text() != "OK" || stop != "end_turn" || usage.InputTokens != 9 || usage.OutputTokens != 4 || usage.CacheReadTokens != 2 {
		t.Fatalf("message=%+v stop=%q usage=%+v", message, stop, usage)
	}
}
