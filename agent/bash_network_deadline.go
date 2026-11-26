package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
	"mvdan.cc/sh/v3/syntax"
)

// networkRequestDeadlineMS is deliberately shorter than Norma's 120-second
// Bash default. It is long enough for a bounded HTTP request through the
// recording proxy, while ensuring a dead route releases its Worker promptly.
const networkRequestDeadlineMS = 45_000

// requestClientPrograms are request/response clients whose useful work should
// finish within one bounded call. Broad scanners (nmap, rustscan, nuclei, …)
// are intentionally absent: they retain Norma's background-task behavior and
// their caller-selected timeout.
var requestClientPrograms = map[string]bool{
	"curl":   true,
	"wget":   true,
	"http":   true, // HTTPie
	"https":  true, // HTTPie HTTPS shortcut
	"httpie": true,
}

type networkCommandRunner func(context.Context, string, time.Duration, *actool.ToolContext) (actool.Result, error)

type networkDeadlineBash struct {
	actool.CoreTool
	run networkCommandRunner
}

func boundedNetworkBash(t actool.CoreTool) actool.CoreTool {
	if t == nil || t.Name() != "Bash" {
		return t
	}
	return &networkDeadlineBash{CoreTool: t, run: runBoundedNetworkCommand}
}

func (t *networkDeadlineBash) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var decoded map[string]any
	if json.Unmarshal(input, &decoded) != nil {
		return t.CoreTool.Call(ctx, input, tc)
	}
	command, _ := decoded["command"].(string)
	if !containsRequestClient(command) {
		return t.CoreTool.Call(ctx, input, tc)
	}

	// Do not let the SDK detach a timed-out HTTP request into its background
	// manager. A shallow ToolContext copy is sufficient: only the Tasks pointer
	// changes, and all other per-call capture/progress/environment state remains
	// intact. The original context is never mutated, so concurrent tool calls do
	// not race with one another.
	timeoutMS, ok := jsonNumberAsInt(decoded["timeout_ms"])
	if !ok || timeoutMS <= 0 || timeoutMS > networkRequestDeadlineMS {
		timeoutMS = networkRequestDeadlineMS
	}
	run := t.run
	if run == nil {
		run = runBoundedNetworkCommand
	}
	return run(ctx, command, time.Duration(timeoutMS)*time.Millisecond, tc)
}

func runBoundedNetworkCommand(ctx context.Context, command string, timeout time.Duration, tc *actool.ToolContext) (actool.Result, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := newBoundedShellCommand(deadlineCtx, command)
	if tc != nil {
		cmd.Dir = tc.WorkingDir
		cmd.Env = boundedShellEnv(tc.Env)
	} else {
		cmd.Env = boundedShellEnv(nil)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	captured := actool.Capture(tc, output.String())
	if errors.Is(deadlineCtx.Err(), context.DeadlineExceeded) {
		return actool.Errorf(captured + fmt.Sprintf("\n\n[command timed out after %s]\n\n[ARTEX environmental blocker: blocker_type=network_environment; retryable=true; operator_action=none; request process terminated and was not backgrounded]", timeout)), nil
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if captured == "" {
				captured = "(no output)"
			}
			return actool.Errorf(fmt.Sprintf("%s\n\n[exit code %d]", captured, exitErr.ExitCode())), nil
		}
		return actool.Errorf(fmt.Sprintf("%s\n\n[failed to run: %v]", captured, err)), nil
	}
	if strings.TrimSpace(captured) == "" {
		captured = "(command produced no output)"
	}
	return actool.Text(captured), nil
}

var boundedNonInteractiveEnv = []string{
	"PAGER=cat",
	"GIT_PAGER=cat",
	"SYSTEMD_PAGER=cat",
	"DEBIAN_FRONTEND=noninteractive",
}

// boundedShellEnv uses the same last-value-wins precedence as Norma's Bash
// tool: process environment < non-interactive defaults < ARTEX proxy/CA env.
func boundedShellEnv(extra []string) []string {
	env := append([]string{}, os.Environ()...)
	env = append(env, boundedNonInteractiveEnv...)
	return append(env, extra...)
}

func jsonNumberAsInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), n == float64(int(n))
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

// containsRequestClient parses the whole Bash program so chained and piped
// requests are found without mistaking data such as `echo curl` for a client.
// Wrapper commands are handled conservatively by looking for a known client in
// their literal argv; expansions/substitutions remain unclassified and retain
// the ordinary Bash behavior.
func containsRequestClient(command string) bool {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return false
	}
	found := false
	syntax.Walk(f, func(node syntax.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		program, literal := literalShellWord(call.Args[0])
		if !literal {
			return true
		}
		if requestClientPrograms[filepath.Base(program)] {
			found = true
			return false
		}
		switch filepath.Base(program) {
		case "command", "env", "exec", "nice", "nohup", "stdbuf", "sudo", "timeout":
			// Wrapper flags and assignments can themselves be dynamic. Inspect
			// every later literal independently so a dynamic header/URL does
			// not hide a literal curl/wget executable.
			for _, word := range call.Args[1:] {
				arg, ok := literalShellWord(word)
				if !ok {
					continue
				}
				if requestClientPrograms[filepath.Base(arg)] {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func literalShellWord(word *syntax.Word) (string, bool) {
	var out strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			out.WriteString(p.Value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			out.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return "", false
			}
			for _, quoted := range p.Parts {
				literal, ok := quoted.(*syntax.Lit)
				if !ok {
					return "", false
				}
				out.WriteString(literal.Value)
			}
		default:
			return "", false
		}
	}
	return out.String(), true
}
