package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Deterministic ingestion of scanner output files (nmap -oX, nuclei -jsonl,
// httpx -json, ffuf -of json). The rules are the bbot parser's: only typed
// fields are read and validated, and every free-text field the target shapes
// (banner, product, title, template name, extracted value) is kept only inside
// one Go-quoted fact detail. It never reaches a summary, a notable
// item or an instruction.

// scanNotableMax caps the notable items returned per type.
const scanNotableMax = 20

// scanMaxItems caps the assets and facts one file may yield. The records past
// it are counted, not ingested, and the result is marked truncated.
const scanMaxItems = 50000

// scanIngest is what one scanner file yields: counters, the insert_assets
// items, the facts, and a capped list of notable items per type.
type scanIngest struct {
	Events, Ports, Skipped, Oversized, OverCap int
	Truncated                                  bool
	hosts, urls                                map[string]bool
	Assets                                     []assetInputItem
	Facts                                      []factItem
	Secrets                                    []db.DiscoveredSecretInput
	BrowserScreenshots                         []browserScreenshotCandidate
	ContentAnomalies                           []webContentAnomaly
	WebApplications                            []webApplicationCandidate
	Notable                                    map[string][]string
}

type webContentAnomaly struct {
	Host string
	URL  string
}

type webApplicationCandidate struct {
	Host   string
	Origin string
}

// webApplicationCandidateMax bounds automated follow-up fan-out from a single
// scanner file. Only responses with an HTML signal are candidates, so this is
// a safety backstop rather than the primary filter.
const webApplicationCandidateMax = 50

// suspiciousWebTitle is deliberately narrow: it promotes likely compromise,
// defacement, or gambling content to a validation intent without treating every
// ordinary title change as a vulnerability. The title itself remains untrusted
// data and is never copied into an agent instruction.
func suspiciousWebTitle(title string) bool {
	title = strings.ToLower(strings.TrimSpace(title))
	for _, marker := range []string{
		"casino", "betting", "sportsbook", "slot gacor", "บาคาร่า", "สล็อตออนไลน์",
		"เว็บพนัน", "pg5", "ฝาก 1 รับ", "hacked by", "defaced by",
	} {
		if strings.Contains(title, marker) {
			return true
		}
	}
	return false
}

func (s *scanIngest) noteContentAnomaly(host, rawURL, title string) {
	if !suspiciousWebTitle(title) || host == "" {
		return
	}
	for _, item := range s.ContentAnomalies {
		if item.Host == host {
			return
		}
	}
	s.ContentAnomalies = append(s.ContentAnomalies, webContentAnomaly{Host: host, URL: rawURL})
}

func (s *scanIngest) noteWebApplication(host, rawURL string, status int, title, contentType string, tech []string) {
	if host == "" || status < 200 || status >= 400 {
		return
	}
	htmlSignal := strings.Contains(strings.ToLower(contentType), "text/html") || strings.TrimSpace(title) != ""
	if !htmlSignal {
		for _, name := range tech {
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "react", "angular", "vue.js", "vue", "next.js", "nuxt.js", "svelte", "webpack", "vite":
				htmlSignal = true
			}
		}
	}
	if !htmlSignal {
		return
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	for _, item := range s.WebApplications {
		if item.Origin == origin {
			return
		}
	}
	if len(s.WebApplications) >= webApplicationCandidateMax {
		s.Truncated = true
		return
	}
	s.WebApplications = append(s.WebApplications, webApplicationCandidate{Host: host, Origin: origin})
}

type browserScreenshotCandidate struct {
	FileName   string
	SourceURL  string
	CapturedAt string
}

func newScanIngest() *scanIngest {
	return &scanIngest{hosts: map[string]bool{}, urls: map[string]bool{}, Notable: map[string][]string{}}
}

func (s *scanIngest) note(kind, item string) {
	if len(s.Notable[kind]) < scanNotableMax {
		s.Notable[kind] = append(s.Notable[kind], item)
	}
}

// full reports whether the item cap is reached; the record is then counted
// in OverCap and dropped. It is checked once per record, so the last record
// admitted may take the total slightly past the cap.
func (s *scanIngest) full() bool {
	if len(s.Assets)+len(s.Facts) < scanMaxItems {
		return false
	}
	s.OverCap++
	s.Truncated = true
	return true
}

// fact records a tool_output fact: the summary is built by the caller from
// typed fields only, the detail is the compact JSON of detail as one Go-quoted
// inert string.
func (s *scanIngest) fact(summary string, detail any) {
	b, _ := json.Marshal(detail)
	s.Facts = append(s.Facts, factItem{Summary: summary, Detail: strconv.Quote(string(b)), Source: factSourceToolOutput})
}

// scanHost returns h as a lower-case IP or hostname, "" when it is neither.
func scanHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	if bbotHostRe.MatchString(h) {
		return h
	}
	return ""
}

// scanURL returns raw re-serialized without its userinfo, and its host, when
// it is an http(s) URL with a valid host, "" otherwise.
func scanURL(raw string) (string, string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", ""
	}
	h := scanHost(u.Hostname())
	if h == "" {
		return "", ""
	}
	u.User = nil // credentials never reach an asset, a note or a fact
	return u.String(), h
}

// stripUserinfo removes the userinfo (user:pass@) from raw, a URL or a bare
// host[:port] as a scanner prints it, and keeps every other byte. It is for
// the raw values kept in a fact detail: unlike scanURL it never rejects, and a
// value with no userinfo, or a path with no authority, is returned unchanged.
func stripUserinfo(raw string) string {
	start := 0 // the authority follows "scheme://" or "//"; a bare value is all authority
	if i := strings.Index(raw, "//"); i == 0 || i > 0 && raw[i-1] == ':' && !strings.ContainsAny(raw[:i-1], "/?#@") {
		start = i + 2
	} else if strings.ContainsAny(raw, "/?#") {
		return raw
	}
	auth := raw[start:]
	if j := strings.IndexAny(auth, "/?#"); j >= 0 {
		auth = auth[:j]
	}
	if at := strings.LastIndex(auth, "@"); at >= 0 {
		return raw[:start] + raw[start+at+1:]
	}
	return raw
}

// scanHostOf reads a host from a URL, a host:port or a bare host.
func scanHostOf(s string) string {
	if _, h := scanURL(s); h != "" {
		return h
	}
	if h, _, err := net.SplitHostPort(strings.TrimSpace(s)); err == nil {
		return scanHost(h)
	}
	return scanHost(s)
}

// ---- certificate-transparency JSON (crt.sh output=json) ----

type ctJSONResult struct {
	NameValue string `json:"name_value"`
}

// readCTJSON streams the crt.sh JSON array. A certificate may carry several
// newline-delimited DNS names; wildcards are normalized to their concrete
// suffix and duplicate names are emitted once.
func readCTJSON(r io.Reader, s *scanIngest) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '[' {
		return errors.New("certificate-transparency JSON must be an array")
	}
	for dec.More() {
		var item ctJSONResult
		if err := dec.Decode(&item); err != nil {
			if s.Events > 0 {
				s.Truncated = true
				return nil
			}
			return err
		}
		s.Events++
		for _, rawName := range strings.Split(item.NameValue, "\n") {
			name := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(rawName)), "*.")
			name = scanHost(name)
			if name == "" || net.ParseIP(name) != nil || s.hosts[name] {
				continue
			}
			if s.full() {
				continue
			}
			s.hosts[name] = true
			s.Assets = append(s.Assets, assetInputItem{Type: "subdomain", Domain: name})
			s.note("subdomains", name)
			s.fact(fmt.Sprintf("certificate transparency observed hostname %s", name), map[string]any{"hostname": name})
		}
	}
	_, err = dec.Token()
	return err
}

// ---- DNS JSONL ({name,A,AAAA,CNAME}) ----

type dnsJSONResult struct {
	Name  string          `json:"name"`
	A     json.RawMessage `json:"A"`
	AAAA  json.RawMessage `json:"AAAA"`
	CNAME json.RawMessage `json:"CNAME"`
}

func scanStringList(raw json.RawMessage) []string {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var single string
	if json.Unmarshal(raw, &single) == nil && single != "" {
		return []string{single}
	}
	return nil
}

func validDNSValues(recordType string, raw json.RawMessage) []string {
	seen := map[string]bool{}
	var out []string
	for _, candidate := range scanStringList(raw) {
		candidate = strings.TrimSpace(candidate)
		switch recordType {
		case "A", "AAAA":
			ip := net.ParseIP(candidate)
			if ip == nil || recordType == "A" && ip.To4() == nil || recordType == "AAAA" && ip.To4() != nil {
				continue
			}
			candidate = ip.String()
		case "CNAME":
			candidate = scanHost(candidate)
			if candidate == "" || net.ParseIP(candidate) != nil {
				continue
			}
		}
		if !seen[candidate] {
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	return out
}

func (s *scanIngest) addDNSJSON(line []byte) {
	if s.full() {
		return
	}
	var item dnsJSONResult
	if json.Unmarshal(line, &item) != nil {
		s.Skipped++
		return
	}
	name := scanHost(item.Name)
	if name == "" || net.ParseIP(name) != nil {
		s.Skipped++
		return
	}
	s.Events++
	s.hosts[name] = true
	records := map[string][]string{
		"A": validDNSValues("A", item.A), "AAAA": validDNSValues("AAAA", item.AAAA), "CNAME": validDNSValues("CNAME", item.CNAME),
	}
	added := false
	for _, recordType := range []string{"A", "AAAA", "CNAME"} {
		values := records[recordType]
		if len(values) == 0 {
			continue
		}
		added = true
		s.Assets = append(s.Assets, assetInputItem{Type: "subdomain", Domain: name, RecordType: recordType, RecordValue: values})
	}
	if !added {
		s.Assets = append(s.Assets, assetInputItem{Type: "subdomain", Domain: name})
	}
	s.note("dns", name)
	s.fact(fmt.Sprintf("DNS resolution collected for %s", name), map[string]any{"name": name, "A": records["A"], "AAAA": records["AAAA"], "CNAME": records["CNAME"]})
}

// ---- nmap -oX ----

type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addrs []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Names []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Proto string `xml:"protocol,attr"`
		ID    string `xml:"portid,attr"`
		State struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Svc struct {
			Name    string   `xml:"name,attr"`
			Product string   `xml:"product,attr"`
			Version string   `xml:"version,attr"`
			Tunnel  string   `xml:"tunnel,attr"`
			CPE     []string `xml:"cpe"`
		} `xml:"service"`
	} `xml:"ports>port"`
	OS []struct {
		Name     string `xml:"name,attr"`
		Accuracy string `xml:"accuracy,attr"`
	} `xml:"os>osmatch"`
}

// readNmapXML streams the file and decodes one <host> element at a time. A file
// cut short keeps the hosts read before the cut and is marked truncated; a file
// with no <nmaprun> root, or with no complete host that fails to parse, is an
// error.
func readNmapXML(r io.Reader, s *scanIngest) error {
	dec := xml.NewDecoder(r)
	root := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if !root {
				return errors.New("no nmaprun element")
			}
			return nil
		}
		if err == nil {
			se, ok := tok.(xml.StartElement)
			root = root || (ok && se.Name.Local == "nmaprun")
			if !ok || se.Name.Local != "host" {
				continue
			}
			var h nmapHost
			if err = dec.DecodeElement(&h, &se); err == nil {
				s.Events++
				s.addNmapHost(h)
				continue
			}
		}
		if s.Events == 0 {
			return err
		}
		s.Truncated = true
		return nil
	}
}

// nmapWebScheme returns the URL scheme of an nmap web service, "" otherwise.
func nmapWebScheme(name, tunnel string) string {
	switch name {
	case "http", "http-alt", "http-proxy":
		if tunnel == "ssl" {
			return "https"
		}
		return "http"
	case "https", "https-alt":
		return "https"
	}
	return ""
}

func (s *scanIngest) addNmapHost(h nmapHost) {
	if h.Status.State != "up" || s.full() {
		return
	}
	ip := ""
	for _, a := range h.Addrs {
		if ip == "" && (a.Type == "ipv4" || a.Type == "ipv6") && net.ParseIP(a.Addr) != nil {
			ip = scanHost(a.Addr)
		}
	}
	if ip == "" {
		s.Skipped++
		return
	}
	s.hosts[ip] = true
	detail := map[string]any{"ip": ip, "hostnames": h.Names, "os": h.OS}
	var bound []string
	for _, n := range h.Names {
		// Only the name the operator scanned is bound to the IP; a PTR name is
		// third-party data and stays in the fact detail.
		if hn := scanHost(n.Name); n.Type == "user" && hn != "" && net.ParseIP(hn) == nil {
			bound = append(bound, hn)
		}
	}
	var open []db.PortService
	var list []string
	var ports []map[string]any
	for _, p := range h.Ports {
		port, err := strconv.Atoi(p.ID)
		if err != nil || port <= 0 || port > 65535 || p.State.State != "open" ||
			(p.Proto != "tcp" && p.Proto != "udp" && p.Proto != "sctp") {
			continue
		}
		name := bbotToken(p.Svc.Name)
		if name == "" {
			name = "unknown"
		}
		s.Ports++
		pp := fmt.Sprintf("%d/%s", port, p.Proto)
		list = append(list, pp)
		open = append(open, db.PortService{Port: port, Service: name})
		ports = append(ports, map[string]any{"port": pp, "service": p.Svc.Name, "product": p.Svc.Product,
			"version": p.Svc.Version, "tunnel": p.Svc.Tunnel, "cpe": p.Svc.CPE})
		s.note("ports", ip+" "+pp+" "+name)
		if scheme := nmapWebScheme(name, p.Svc.Tunnel); scheme != "" && p.Proto == "tcp" {
			u := scheme + "://" + net.JoinHostPort(ip, strconv.Itoa(port))
			s.urls[u] = true
			s.note("urls", u)
			s.Assets = append(s.Assets, assetInputItem{Type: "service", URL: u, IP: ip})
		} else {
			s.Assets = append(s.Assets, assetInputItem{Type: "service", IP: ip, Port: port, ServiceName: name})
		}
	}
	s.Assets = append(s.Assets, assetInputItem{Type: "ip", IP: ip, BoundDomains: bound, OpenPorts: open})
	s.note("hosts", fmt.Sprintf("%s (%d open ports)", ip, len(list)))
	shown := list
	if len(shown) > 50 {
		shown = shown[:50]
	}
	summary := fmt.Sprintf("nmap: host %s has %d open ports: %s", ip, len(list), strings.Join(shown, ", "))
	if len(list) > len(shown) {
		summary += fmt.Sprintf(" and %d more", len(list)-len(shown))
	}
	detail["ports"] = ports
	s.fact(summary, detail)
}

// gowitnessMaxLineBytes is deliberately larger than the generic JSONL limit:
// Gowitness v3 records may embed the page HTML and network log in the same JSON
// object even though ARTEX allow-lists and retains none of those fields. Keep a
// firm per-record bound below the 256 MiB file cap so one hostile record cannot
// cause unbounded allocation while normal multi-megabyte captures still ingest.
const gowitnessMaxLineBytes = 16 << 20

// readJSONLines calls fn with each non-blank line of r, and returns the number
// of lines skipped for exceeding bbotMaxLineBytes. fn must not keep the line:
// its buffer is reused by the next read.
func readJSONLines(r io.Reader, fn func(line []byte)) (int, error) {
	return readJSONLinesLimit(r, bbotMaxLineBytes, fn)
}

// readJSONLinesLimit is the bounded JSONL reader shared by scanner importers.
// It grows only the current accepted record, up to maxLineBytes; after crossing
// the cap it discards chunks until the next newline without retaining them. A
// line exactly at the cap (including its newline) remains valid.
func readJSONLinesLimit(r io.Reader, maxLineBytes int, fn func(line []byte)) (int, error) {
	if maxLineBytes <= 0 {
		return 0, errors.New("JSONL line limit must be positive")
	}
	oversized := 0
	// A small reader buffer avoids reserving the full Gowitness allowance for
	// ordinary records. The accumulated line is the only value that can grow to
	// maxLineBytes.
	br := bufio.NewReaderSize(r, min(maxLineBytes, bbotMaxLineBytes))
	line := make([]byte, 0, min(maxLineBytes, bbotMaxLineBytes))
	dropping := false
	for {
		chunk, err := br.ReadSlice('\n')
		if !dropping {
			if len(line)+len(chunk) <= maxLineBytes {
				line = append(line, chunk...)
			} else {
				dropping = true
				line = line[:0]
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if dropping {
			oversized++
		} else if len(bytes.TrimSpace(line)) > 0 {
			fn(line)
		}
		line = line[:0]
		dropping = false
		if errors.Is(err, io.EOF) {
			return oversized, nil
		}
		if err != nil {
			return oversized, err
		}
	}
}

// ---- nuclei -jsonl ----

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched-at"`
	MatcherName string   `json:"matcher-name"`
	Extracted   []string `json:"extracted-results"`
}

// addNuclei records one nuclei result as a fact, and the scanned target (not
// the matched path) as an asset when it is valid. No finding: a scanner match
// is unverified until the planner checks it.
func (s *scanIngest) addNuclei(line []byte) {
	var r nucleiResult
	if s.full() {
		return
	}
	if json.Unmarshal(line, &r) != nil {
		s.Skipped++
		return
	}
	host := scanHostOf(r.Host)
	if host == "" {
		host = scanHostOf(r.MatchedAt)
	}
	tid := bbotToken(r.TemplateID)
	if tid == "" || host == "" {
		s.Skipped++
		return
	}
	sev := strings.ToLower(r.Info.Severity)
	switch sev {
	case "info", "low", "medium", "high", "critical":
	default:
		sev = "unknown"
	}
	s.Events++
	s.hosts[host] = true
	if u, _ := scanURL(r.MatchedAt); u != "" {
		s.urls[u] = true
	}
	switch u, _ := scanURL(r.Host); {
	case u != "":
		s.Assets = append(s.Assets, assetInputItem{Type: "service", URL: u})
	case net.ParseIP(host) != nil:
		s.Assets = append(s.Assets, assetInputItem{Type: "ip", IP: host})
	default:
		s.Assets = append(s.Assets, assetInputItem{Type: "subdomain", Domain: host})
	}
	s.note("results", tid+" ("+sev+") on "+host)
	s.fact(fmt.Sprintf("nuclei: template %s (severity %s) matched on %s; unverified scanner result", tid, sev, host),
		map[string]any{"name": r.Info.Name, "host": stripUserinfo(r.Host), "matched_at": stripUserinfo(r.MatchedAt),
			"matcher_name": r.MatcherName, "extracted_results": r.Extracted})
}

// ---- httpx -json ----

type httpxResult struct {
	URL           string          `json:"url"`
	StatusCode    int             `json:"status_code"`
	Title         string          `json:"title"`
	ContentType   string          `json:"content_type"`
	Tech          []string        `json:"tech"`
	Webserver     string          `json:"webserver"`
	ContentLength int64           `json:"content_length"`
	Host          string          `json:"host"`
	IP            string          `json:"ip"`
	TLS           json.RawMessage `json:"tls"`
}

func (s *scanIngest) addHttpx(line []byte) {
	var r httpxResult
	if s.full() {
		return
	}
	if json.Unmarshal(line, &r) != nil {
		s.Skipped++
		return
	}
	u, host := scanURL(r.URL)
	if u == "" {
		s.Skipped++
		return
	}
	s.Events++
	s.hosts[host] = true
	s.urls[u] = true
	item := assetInputItem{Type: "service", URL: u, PageTitle: r.Title, Technologies: r.Tech}
	for _, c := range []string{r.IP, r.Host} {
		if ip := net.ParseIP(strings.TrimSpace(c)); ip != nil {
			item.IP = ip.String()
			break
		}
	}
	if r.StatusCode > 0 {
		item.StatusCode = &r.StatusCode
	}
	if r.ContentLength > 0 {
		item.ContentLength = &r.ContentLength
	}
	s.Assets = append(s.Assets, item)
	s.noteContentAnomaly(host, u, r.Title)
	s.noteWebApplication(host, u, r.StatusCode, r.Title, r.ContentType, r.Tech)
	s.note("urls", fmt.Sprintf("%s %d", u, r.StatusCode))
	s.fact(fmt.Sprintf("httpx: %s responded with status %d", u, r.StatusCode),
		map[string]any{"title": r.Title, "tech": r.Tech, "webserver": r.Webserver, "content_length": r.ContentLength,
			"host": stripUserinfo(r.Host), "ip": r.IP, "tls": r.TLS})
}

// ---- gowitness v3 --write-jsonl ----

// gowitnessResult intentionally allow-lists only non-sensitive result fields.
// Real Gowitness records can contain response bodies, headers, cookies, console
// output and network content. Those fields must never enter ARTEX facts or
// assets: besides being attacker-controlled, concurrent browser scans may
// associate ambient session cookies with a different result record.
type gowitnessResult struct {
	URL           string `json:"url"`
	FinalURL      string `json:"final_url"`
	ResponseCode  int    `json:"response_code"`
	ContentLength int64  `json:"content_length"`
	Title         string `json:"title"`
	FileName      string `json:"file_name"`
	Failed        bool   `json:"failed"`
	FailedReason  string `json:"failed_reason"`
	ProbedAt      string `json:"probed_at"`
	Protocol      string `json:"protocol"`
	Technologies  []struct {
		Value string `json:"value"`
	} `json:"technologies"`
	TLS struct {
		Protocol                 string `json:"protocol"`
		Cipher                   string `json:"cipher"`
		SubjectName              string `json:"subject_name"`
		Issuer                   string `json:"issuer"`
		ValidFrom                string `json:"valid_from"`
		ValidTo                  string `json:"valid_to"`
		EncryptedClientHello     bool   `json:"encrypted_client_hello"`
		ServerSignatureAlgorithm int    `json:"server_signature_algorithm"`
	} `json:"tls"`
}

func safeScreenshotName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || filepath.Base(raw) != raw || strings.Contains(raw, `\`) {
		return ""
	}
	switch strings.ToLower(filepath.Ext(raw)) {
	case ".jpeg", ".jpg", ".png", ".webp":
		return raw
	default:
		return ""
	}
}

func (s *scanIngest) addGowitness(line []byte) {
	var r gowitnessResult
	if s.full() {
		return
	}
	if json.Unmarshal(line, &r) != nil || r.Failed {
		s.Skipped++
		return
	}
	original, _ := scanURL(r.URL)
	final, host := scanURL(r.FinalURL)
	if final == "" {
		final, host = scanURL(r.URL)
	}
	if final == "" {
		s.Skipped++
		return
	}
	fileName := safeScreenshotName(r.FileName)
	if fileName == "" {
		s.Skipped++
		return
	}
	var tech []string
	for _, item := range r.Technologies {
		if value := bbotToken(item.Value); value != "" {
			tech = append(tech, value)
		}
	}
	s.Events++
	s.hosts[host] = true
	s.urls[final] = true
	asset := assetInputItem{Type: "service", URL: final, PageTitle: r.Title, Technologies: tech}
	if r.ResponseCode > 0 {
		asset.StatusCode = &r.ResponseCode
	}
	if r.ContentLength > 0 {
		asset.ContentLength = &r.ContentLength
	}
	s.Assets = append(s.Assets, asset)
	s.noteContentAnomaly(host, final, r.Title)
	s.note("screenshots", fmt.Sprintf("%s %d", final, r.ResponseCode))
	s.BrowserScreenshots = append(s.BrowserScreenshots, browserScreenshotCandidate{
		FileName: fileName, SourceURL: final, CapturedAt: r.ProbedAt,
	})
	s.fact(fmt.Sprintf("gowitness: screenshot captured for %s with status %d", final, r.ResponseCode), map[string]any{
		"original_url": original, "final_url": final, "title": r.Title, "screenshot_file": fileName,
		"content_length": r.ContentLength, "probed_at": r.ProbedAt, "protocol": r.Protocol,
		"technologies": tech,
		"tls": map[string]any{
			"protocol": r.TLS.Protocol, "cipher": r.TLS.Cipher, "subject_name": r.TLS.SubjectName,
			"issuer": r.TLS.Issuer, "valid_from": r.TLS.ValidFrom, "valid_to": r.TLS.ValidTo,
			"encrypted_client_hello":     r.TLS.EncryptedClientHello,
			"server_signature_algorithm": r.TLS.ServerSignatureAlgorithm,
		},
	})
}

// ---- ffuf -of json ----

type ffufResult struct {
	Input    json.RawMessage `json:"input"`
	Status   int             `json:"status"`
	Length   int64           `json:"length"`
	Words    int             `json:"words"`
	Lines    int             `json:"lines"`
	URL      string          `json:"url"`
	Redirect string          `json:"redirectlocation"`
}

// readFfufJSON walks the top-level object and decodes results[] one element at
// a time. Other keys are skipped. A file cut short keeps the results read
// before the cut and is marked truncated.
func readFfufJSON(r io.Reader, s *scanIngest) error {
	dec := json.NewDecoder(r)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	err := func() error {
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			if key != "results" {
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return err
				}
				continue
			}
			if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
				return errors.New("results is not an array")
			}
			for dec.More() {
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return err
				}
				s.addFfuf(raw)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return err
			}
		}
		_, err := dec.Token() // '}'
		return err
	}()
	if err != nil {
		s.Truncated = true
	}
	return nil
}

func (s *scanIngest) addFfuf(raw json.RawMessage) {
	var r ffufResult
	if s.full() {
		return
	}
	if json.Unmarshal(raw, &r) != nil {
		s.Skipped++
		return
	}
	u, host := scanURL(r.URL)
	if u == "" {
		s.Skipped++
		return
	}
	s.Events++
	s.hosts[host] = true
	s.urls[u] = true
	item := assetInputItem{Type: "service", URL: u}
	if r.Status > 0 {
		item.StatusCode = &r.Status
	}
	if r.Length > 0 {
		item.ContentLength = &r.Length
	}
	s.Assets = append(s.Assets, item)
	s.note("urls", fmt.Sprintf("%s %d", u, r.Status))
	s.fact(fmt.Sprintf("ffuf: %s returned status %d, %d bytes, %d words, %d lines", u, r.Status, r.Length, r.Words, r.Lines),
		map[string]any{"input": r.Input, "redirectlocation": stripUserinfo(r.Redirect)})
}

// ---- TruffleHog -j ----

type truffleHogResult struct {
	DetectorName   string          `json:"DetectorName"`
	DetectorType   json.RawMessage `json:"DetectorType"`
	SourceType     json.RawMessage `json:"SourceType"`
	SourceName     string          `json:"SourceName"`
	Verified       bool            `json:"Verified"`
	Raw            string          `json:"Raw"`
	RawV2          string          `json:"RawV2"`
	Redacted       string          `json:"Redacted"`
	SourceMetadata json.RawMessage `json:"SourceMetadata"`
}

// truffleString turns the scanner's string or numeric enum into a stable label.
func truffleString(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

// findJSONScalar searches scanner metadata for a location field. It is used
// only for a small allow-list; the complete metadata is deliberately not put in
// a fact because it may contain credentials or attacker-controlled text.
func findJSONScalar(v any, names ...string) string {
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[strings.ToLower(name)] = true
	}
	var walk func(any) string
	walk = func(current any) string {
		switch value := current.(type) {
		case map[string]any:
			for key, item := range value {
				if !wanted[strings.ToLower(key)] {
					continue
				}
				switch scalar := item.(type) {
				case string:
					return scalar
				case json.Number:
					return scalar.String()
				case float64:
					return strconv.FormatFloat(scalar, 'f', -1, 64)
				}
			}
			for _, item := range value {
				if found := walk(item); found != "" {
					return found
				}
			}
		case []any:
			for _, item := range value {
				if found := walk(item); found != "" {
					return found
				}
			}
		}
		return ""
	}
	return walk(v)
}

func (s *scanIngest) addTruffleHog(line []byte) {
	if s.full() {
		return
	}
	var result truffleHogResult
	if json.Unmarshal(line, &result) != nil || strings.TrimSpace(result.DetectorName) == "" || result.Raw == "" {
		s.Skipped++
		return
	}
	var metadata any
	decoder := json.NewDecoder(bytes.NewReader(result.SourceMetadata))
	decoder.UseNumber()
	_ = decoder.Decode(&metadata)
	repository := findJSONScalar(metadata, "repository", "repositoryurl", "repo")
	filePath := findJSONScalar(metadata, "file", "filepath", "path")
	commit := findJSONScalar(metadata, "commit", "commithash", "commitid")
	lineNumber, _ := strconv.Atoi(findJSONScalar(metadata, "line", "linenumber"))
	if lineNumber < 0 {
		lineNumber = 0
	}
	location := strings.Trim(strings.Join([]string{repository, filePath}, "/"), "/")
	if location == "" {
		location = strings.TrimSpace(result.SourceName)
	}
	if location == "" {
		location = "unknown location"
	}
	state := "unverified"
	if result.Verified {
		state = "verified"
	}
	locationMetadata, _ := json.Marshal(map[string]any{
		"repository":  repository,
		"file_path":   filePath,
		"line_number": lineNumber,
		"commit_hash": commit,
	})
	s.Events++
	s.Secrets = append(s.Secrets, db.DiscoveredSecretInput{
		Detector:        strings.TrimSpace(result.DetectorName),
		SourceType:      truffleString(result.SourceType),
		SourceName:      strings.TrimSpace(result.SourceName),
		Repository:      repository,
		FilePath:        filePath,
		LineNumber:      lineNumber,
		CommitHash:      commit,
		Verified:        result.Verified,
		SecretValue:     result.Raw,
		SecretValueV2:   result.RawV2,
		ScannerRedacted: result.Redacted,
		Metadata:        locationMetadata,
	})
	s.note("secrets", fmt.Sprintf("%s (%s) at %s", result.DetectorName, state, location))
	s.fact(fmt.Sprintf("trufflehog: %s secret candidate (%s) at %s", bbotToken(result.DetectorName), state, location),
		map[string]any{"detector": result.DetectorName, "verified": result.Verified, "repository": repository,
			"file_path": filePath, "line_number": lineNumber, "commit_hash": commit})
}

// ---- OpenDoor --json ----

type openDoorResult struct {
	URL      string          `json:"url"`
	Size     scanInt         `json:"size"`
	Code     scanInt         `json:"code"`
	Status   scanInt         `json:"status"`
	Metadata json.RawMessage `json:"metadata"`
}

type scanInt int64

func (value *scanInt) UnmarshalJSON(raw []byte) error {
	var number int64
	if json.Unmarshal(raw, &number) == nil {
		*value = scanInt(number)
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return err
	}
	text = strings.TrimSpace(text)
	end := 0
	for end < len(text) && text[end] >= '0' && text[end] <= '9' {
		end++
	}
	if end == 0 {
		*value = 0
		return nil
	}
	parsed, err := strconv.ParseInt(text[:end], 10, 64)
	if err != nil {
		return err
	}
	*value = scanInt(parsed)
	return nil
}

func decodeOpenDoorItems(raw json.RawMessage) ([]openDoorResult, error) {
	var direct []openDoorResult
	if err := json.Unmarshal(raw, &direct); err == nil {
		return direct, nil
	}
	var grouped map[string]json.RawMessage
	if err := json.Unmarshal(raw, &grouped); err != nil {
		return nil, err
	}
	var out []openDoorResult
	for bucket, encoded := range grouped {
		var items []openDoorResult
		if err := json.Unmarshal(encoded, &items); err == nil {
			out = append(out, items...)
			continue
		}
		var urls []string
		if err := json.Unmarshal(encoded, &urls); err != nil {
			return nil, err
		}
		var code scanInt
		_ = code.UnmarshalJSON([]byte(strconv.Quote(bucket)))
		for _, endpoint := range urls {
			out = append(out, openDoorResult{URL: endpoint, Code: code})
		}
	}
	return out, nil
}

func readOpenDoorJSON(r io.Reader, s *scanIngest) error {
	var document struct {
		Items         json.RawMessage `json:"items"`
		ReportItems   json.RawMessage `json:"report_items"`
		FilteredItems json.RawMessage `json:"filtered_items"`
	}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	raw := document.ReportItems
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		raw = document.Items
	}
	items, err := decodeOpenDoorItems(raw)
	if err != nil {
		return errors.New("items are not an array or status map")
	}
	for _, item := range items {
		s.addOpenDoor(item)
	}
	if len(bytes.TrimSpace(document.FilteredItems)) > 0 && !bytes.Equal(bytes.TrimSpace(document.FilteredItems), []byte("null")) {
		if filtered, err := decodeOpenDoorItems(document.FilteredItems); err == nil {
			s.Skipped += len(filtered)
		}
	}
	return nil
}

func (s *scanIngest) addOpenDoor(result openDoorResult) {
	if s.full() {
		return
	}
	endpoint, host := scanURL(result.URL)
	if endpoint == "" {
		s.Skipped++
		return
	}
	status := int(result.Code)
	if status == 0 {
		status = int(result.Status)
	}
	s.Events++
	s.hosts[host] = true
	s.urls[endpoint] = true
	asset := assetInputItem{Type: "service", URL: endpoint}
	if status > 0 {
		asset.StatusCode = &status
	}
	contentLength := int64(result.Size)
	if contentLength > 0 {
		asset.ContentLength = &contentLength
	}
	s.Assets = append(s.Assets, asset)
	s.note("urls", fmt.Sprintf("%s %d", endpoint, status))
	s.fact(fmt.Sprintf("opendoor: %s returned status %d and %d bytes", endpoint, status, contentLength),
		map[string]any{"metadata": result.Metadata})
}
