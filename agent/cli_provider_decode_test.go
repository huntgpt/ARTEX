package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestDecodeCLIBridgeResponsePresentationWrappers(t *testing.T) {
	want := `{"text":"ok","tool_calls":[],"stop_reason":"end_turn"}`
	cases := map[string]string{
		"plain":           want,
		"fenced":          "```json\n" + want + "\n```",
		"prefixed":        "Here is the requested bridge response:\n" + want,
		"log prefix":      "[INFO] structured response follows\n" + want,
		"prefixed fenced": "Result:\n```JSON\n" + want + "\n```\n",
		"encoded once":    `"{\"text\":\"ok\",\"tool_calls\":[],\"stop_reason\":\"end_turn\"}"`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := decodeCLIBridgeResponse([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if got.Text != "ok" || got.StopReason != "end_turn" || len(got.ToolCalls) != 0 {
				t.Fatalf("response=%+v", got)
			}
		})
	}
}

func TestDecodeCLIBridgeResponseRejectsAmbiguousOrPartialJSON(t *testing.T) {
	valid := `{"text":"ok","tool_calls":[],"stop_reason":"end_turn"}`
	cases := map[string]string{
		"empty":           "",
		"partial":         `{"text":"ok","tool_calls":[]`,
		"malformed":       `{text:"ok"}`,
		"array":           `[{"text":"ok"}]`,
		"multiple":        valid + "\n" + valid,
		"stray close":     "noise }\n" + valid,
		"valid then open": valid + "\n{",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCLIBridgeResponse([]byte(raw)); err == nil {
				t.Fatal("expected invalid bridge JSON")
			}
		})
	}
}

func TestNormalizeCLIBridgeToolInputWrappers(t *testing.T) {
	tool := []llm.ToolSchema{{Name: "Bash", InputSchema: map[string]any{"type": "object"}}}
	cases := map[string]string{
		"plain":    `{"command":"printf '{safe}'"}`,
		"fenced":   "```json\n{\"command\":\"pwd\"}\n```",
		"prefixed": "Arguments:\n{\"command\":\"pwd\"}",
		"encoded":  `"{\"command\":\"pwd\"}"`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			message, stop, err := normalizeCLIBridgeResponse(cliBridgeResponse{
				ToolCalls: []cliBridgeToolCall{{Name: "Bash", InputJSON: input}},
			}, tool)
			if err != nil {
				t.Fatal(err)
			}
			if stop != "tool_use" || len(message.ToolUses()) != 1 {
				t.Fatalf("message=%+v stop=%q", message, stop)
			}
			if !strings.Contains(string(message.ToolUses()[0].Input), "command") {
				t.Fatalf("input=%s", message.ToolUses()[0].Input)
			}
		})
	}
}

func TestNormalizeCLIBridgeToolInputRejectsUnsafeRecovery(t *testing.T) {
	tool := []llm.ToolSchema{{Name: "Bash"}}
	for name, input := range map[string]string{
		"partial":   `{"command":"pwd"`,
		"array":     `[{"command":"pwd"}]`,
		"multiple":  `{"command":"pwd"}{"command":"id"}`,
		"malformed": `{command:"pwd"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := normalizeCLIBridgeResponse(cliBridgeResponse{
				ToolCalls: []cliBridgeToolCall{{Name: "Bash", InputJSON: input}},
			}, tool)
			if err == nil || !strings.Contains(err.Error(), "invalid input JSON") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
