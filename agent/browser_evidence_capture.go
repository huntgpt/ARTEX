package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	browserCaptureReceiptVersion = 1
	browserCaptureReceiptMax     = 64 << 10
	browserCaptureTimeout        = 60 * time.Second
)

// browserCaptureReceipt is a process-authenticated statement that ARTEX's
// code-owned Playwright helper, rather than the model or a shell command,
// produced the declared files. The HMAC key exists only in server process
// memory. Hash/path validation still runs at import time; the receipt adds the
// missing capture-origin proof.
type browserCaptureReceipt struct {
	Version           int    `json:"version"`
	ReceiptID         string `json:"receipt_id"`
	TaskID            int64  `json:"task_id"`
	Workspace         string `json:"workspace"`
	SourceURL         string `json:"source_url"`
	CapturedAt        string `json:"captured_at"`
	ScreenshotPath    string `json:"screenshot_path"`
	ScreenshotSHA256  string `json:"screenshot_sha256"`
	TracePath         string `json:"trace_path,omitempty"`
	TraceSHA256       string `json:"trace_sha256,omitempty"`
	TraceFormat       string `json:"trace_format,omitempty"`
	CaptureTool       string `json:"capture_tool"`
	CaptureToolUseID  string `json:"capture_tool_use_id"`
	Browser           string `json:"browser"`
	PlaywrightVersion string `json:"playwright_version"`
}

type signedBrowserCaptureReceipt struct {
	Claims    browserCaptureReceipt `json:"claims"`
	Signature string                `json:"signature"`
}

var browserCaptureReceiptKey = func() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("generate browser capture receipt key: " + err.Error())
	}
	return key
}()

func browserReceiptSignature(claims browserCaptureReceipt) (string, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, browserCaptureReceiptKey)
	_, _ = mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func signBrowserCaptureReceipt(claims browserCaptureReceipt) (signedBrowserCaptureReceipt, error) {
	signature, err := browserReceiptSignature(claims)
	return signedBrowserCaptureReceipt{Claims: claims, Signature: signature}, err
}

func verifyBrowserCaptureReceipt(raw []byte) (browserCaptureReceipt, error) {
	var envelope signedBrowserCaptureReceipt
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return browserCaptureReceipt{}, errors.New("capture receipt is malformed")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return browserCaptureReceipt{}, errors.New("capture receipt has trailing content")
	}
	want, err := browserReceiptSignature(envelope.Claims)
	if err != nil || !hmac.Equal([]byte(want), []byte(strings.ToLower(strings.TrimSpace(envelope.Signature)))) {
		return browserCaptureReceipt{}, errors.New("capture receipt signature is invalid")
	}
	return envelope.Claims, nil
}

func browserRunWorkspace(base, dir string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absBase, absDir)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return "", errors.New("run directory is outside the data directory")
	}
	return filepath.ToSlash(rel), nil
}

func writeBrowserCaptureReceipt(path string, claims browserCaptureReceipt) error {
	envelope, err := signBrowserCaptureReceipt(claims)
	if err != nil {
		return err
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if len(b) > browserCaptureReceiptMax {
		return errors.New("capture receipt exceeds size cap")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// CapturePlaywrightEvidenceTool is exported for the retest conversation adapter.
func (t *ToolSet) CapturePlaywrightEvidenceTool() actool.CoreTool {
	return t.capturePlaywrightEvidence()
}

func (t *ToolSet) capturePlaywrightEvidence() actool.CoreTool {
	const name = "capture_playwright_evidence"
	return actool.Build(actool.Spec{
		Name:        name,
		Description: "Capture a real web page with ARTEX's code-owned Playwright helper and create a signed receipt for ingest_browser_evidence. This tool performs the browser navigation itself; it does not accept an existing screenshot, arbitrary script, or output path. The URL is target-gated. On success, call ingest_browser_evidence with the returned receipt_path; only that signed receipt can become verified Finding evidence.",
		Schema: obj(map[string]any{
			"source_url":          str("exact http/https page URL to open in Chromium"),
			"wait_ms":             map[string]any{"type": "integer", "minimum": 0, "maximum": 10000, "description": "optional bounded delay after navigation before capture"},
			"full_page":           map[string]any{"type": "boolean", "description": "capture the full scrollable page (default true)"},
			"save_trace":          map[string]any{"type": "boolean", "description": "save an original HAR network trace (default true; may contain secrets)"},
			"ignore_https_errors": map[string]any{"type": "boolean", "description": "allow an invalid target TLS certificate"},
		}, "source_url"),
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			return t.needExploration(name, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				return t.runPlaywrightCapture(ctx, in, tc)
			})(ctx, in)
		},
	})
}

func (t *ToolSet) runPlaywrightCapture(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if t.taskID <= 0 || strings.TrimSpace(t.workBase) == "" || tc == nil || strings.TrimSpace(tc.WorkingDir) == "" || strings.TrimSpace(tc.ToolUseID) == "" {
		return actool.Errorf("Playwright capture requires task, run-directory, and audited tool-call context"), nil
	}
	if t.worker != "retester" && !browserEvidenceIntentDir(t.workBase, t.taskID, tc.WorkingDir) {
		return actool.Errorf("Playwright capture requires the current task intent directory"), nil
	}
	var input struct {
		SourceURL         string `json:"source_url"`
		WaitMS            int    `json:"wait_ms"`
		FullPage          *bool  `json:"full_page"`
		SaveTrace         *bool  `json:"save_trace"`
		IgnoreHTTPSErrors bool   `json:"ignore_https_errors"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return actool.Errorf("invalid input: " + err.Error()), nil
	}
	input.SourceURL = strings.TrimSpace(input.SourceURL)
	u, err := url.Parse(input.SourceURL)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return actool.Errorf("source_url must be an http/https URL without userinfo"), nil
	}
	if input.WaitMS < 0 || input.WaitMS > 10000 {
		return actool.Errorf("wait_ms must be between 0 and 10000"), nil
	}
	workspace, err := browserRunWorkspace(t.workBase, tc.WorkingDir)
	if err != nil {
		return actool.Errorf("Playwright capture requires a confined run directory"), nil
	}
	playwright, err := exec.LookPath("playwright")
	if err != nil {
		return actool.Errorf("Playwright CLI is unavailable; install the pinned Playwright runtime on the ARTEX worker host"), nil
	}
	receiptIDBytes := make([]byte, 16)
	if _, err := rand.Read(receiptIDBytes); err != nil {
		return actool.Errorf("could not allocate capture receipt id"), nil
	}
	receiptID := hex.EncodeToString(receiptIDBytes)
	screenshotName := ".artex-playwright-" + receiptID + ".png"
	traceName := ".artex-playwright-" + receiptID + ".har"
	receiptName := ".artex-playwright-" + receiptID + ".receipt.json"
	screenshotPath := filepath.Join(tc.WorkingDir, screenshotName)
	tracePath := filepath.Join(tc.WorkingDir, traceName)
	receiptPath := filepath.Join(tc.WorkingDir, receiptName)
	fullPage := input.FullPage == nil || *input.FullPage
	saveTrace := input.SaveTrace == nil || *input.SaveTrace
	args := []string{"screenshot", "--browser", "chromium", "--timeout", "45000"}
	if input.WaitMS > 0 {
		args = append(args, "--wait-for-timeout", strconv.Itoa(input.WaitMS))
	}
	if fullPage {
		args = append(args, "--full-page")
	}
	if input.IgnoreHTTPSErrors {
		args = append(args, "--ignore-https-errors")
	}
	if saveTrace {
		args = append(args, "--save-har", tracePath)
	}
	proxy := browserCaptureProxy(tc.Env)
	if proxy != "" {
		args = append(args, "--proxy-server", proxy)
	}
	args = append(args, u.String(), screenshotPath)
	runCtx, cancel := context.WithTimeout(ctx, browserCaptureTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, playwright, args...)
	cmd.Dir = tc.WorkingDir
	cmd.Env = append(os.Environ(), tc.Env...)
	var commandOutput limitedBrowserCaptureOutput
	cmd.Stdout, cmd.Stderr = &commandOutput, &commandOutput
	if err := cmd.Run(); err != nil {
		_ = os.Remove(screenshotPath)
		_ = os.Remove(tracePath)
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return actool.Errorf("Playwright capture timed out"), nil
		}
		detail := commandOutput.String()
		if proxy != "" {
			detail = strings.ReplaceAll(detail, proxy, "[configured proxy]")
		}
		return actool.Errorf("Playwright capture failed: " + detail), nil
	}
	imageBytes, err := readConfinedEvidenceFile(t.workBase, tc.WorkingDir, screenshotName, playwrightImageMaxBytes)
	if err != nil {
		return actool.Errorf("Playwright did not produce a valid confined screenshot"), nil
	}
	if _, _, err := validateBrowserImage(imageBytes); err != nil {
		return actool.Errorf("Playwright screenshot is invalid"), nil
	}
	imageHash := sha256.Sum256(imageBytes)
	claims := browserCaptureReceipt{
		Version: browserCaptureReceiptVersion, ReceiptID: receiptID, TaskID: t.taskID,
		Workspace: workspace, SourceURL: u.String(), CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ScreenshotPath: screenshotName, ScreenshotSHA256: hex.EncodeToString(imageHash[:]),
		CaptureTool: "artex_playwright_cli", CaptureToolUseID: strings.TrimSpace(tc.ToolUseID),
		Browser: "chromium", PlaywrightVersion: browserPlaywrightVersion(playwright),
	}
	if saveTrace {
		traceBytes, err := readConfinedEvidenceFile(t.workBase, tc.WorkingDir, traceName, playwrightTraceMaxBytes)
		if err != nil || validateBrowserTrace(traceBytes, "har") != nil {
			return actool.Errorf("Playwright did not produce a valid confined HAR trace"), nil
		}
		traceHash := sha256.Sum256(traceBytes)
		claims.TracePath, claims.TraceSHA256, claims.TraceFormat = traceName, hex.EncodeToString(traceHash[:]), "har"
	}
	if err := writeBrowserCaptureReceipt(receiptPath, claims); err != nil {
		return actool.Errorf("Playwright capture receipt could not be stored"), nil
	}
	return jsonResult(map[string]any{
		"receipt_path": receiptName, "receipt_id": receiptID, "source_url": claims.SourceURL,
		"captured_at": claims.CapturedAt, "screenshot_sha256": claims.ScreenshotSHA256,
		"trace_sha256": claims.TraceSHA256, "capture_tool_use_id": claims.CaptureToolUseID,
		"next_action": "call ingest_browser_evidence with receipt_path",
	})
}

type limitedBrowserCaptureOutput struct{ bytes.Buffer }

func (b *limitedBrowserCaptureOutput) Write(p []byte) (int, error) {
	original := len(p)
	if b.Len() < 8<<10 {
		remain := (8 << 10) - b.Len()
		if len(p) > remain {
			p = p[:remain]
		}
		_, _ = b.Buffer.Write(p)
	}
	return original, nil
}

func (b *limitedBrowserCaptureOutput) String() string {
	s := strings.TrimSpace(b.Buffer.String())
	if s == "" {
		return "browser process exited unsuccessfully"
	}
	return s
}

func browserCaptureProxy(env []string) string {
	values := map[string]string{}
	for _, item := range env {
		if key, value, ok := strings.Cut(item, "="); ok {
			values[strings.ToUpper(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"} {
		if values[key] != "" {
			return values[key]
		}
	}
	return ""
}

func browserPlaywrightVersion(binary string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return "unknown"
	}
	version := strings.TrimSpace(string(out))
	if len(version) > 100 {
		version = version[:100]
	}
	return version
}

func browserReceiptHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func browserReceiptError(err error) string {
	if err == nil {
		return "capture receipt is invalid"
	}
	return fmt.Sprintf("capture receipt is invalid: %s", err)
}
