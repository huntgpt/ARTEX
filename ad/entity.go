// Package ad defines the task-scoped Active Directory observation model.
//
// The package is deliberately pure: it performs no network or database I/O.
// Collector output is untrusted data. Only typed identifiers and validated DNS
// hostnames are promoted into graph fields; target-controlled text remains in
// inert, JSON-encoded detail.
package ad

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type EntityKind string

const (
	EntityDomain   EntityKind = "domain"
	EntityUser     EntityKind = "user"
	EntityGroup    EntityKind = "group"
	EntityComputer EntityKind = "computer"
)

type Relation string

const (
	RelationMemberOf   Relation = "member_of"
	RelationAdminTo    Relation = "admin_to"
	RelationHasSession Relation = "has_session"
)

type ObservationState string

const (
	Observed ObservationState = "observed"
	Inferred ObservationState = "inferred"
)

// Entity is one AD principal or domain. Key is the stable SID/GUID supplied by
// the collector. DNSHostname is populated only for a syntactically valid DNS
// name. Detail contains inert JSON and must never be interpolated into prompts.
type Entity struct {
	Key         string           `json:"key"`
	Kind        EntityKind       `json:"kind"`
	SID         string           `json:"sid,omitempty"`
	DNSHostname string           `json:"dns_hostname,omitempty"`
	DomainSID   string           `json:"domain_sid,omitempty"`
	State       ObservationState `json:"state"`
	Detail      json.RawMessage  `json:"detail,omitempty"`
}

type Edge struct {
	SourceKey string           `json:"source_key"`
	Relation  Relation         `json:"relation"`
	TargetKey string           `json:"target_key"`
	State     ObservationState `json:"state"`
}

// Observation is the deterministic result of parsing one collector artifact.
type Observation struct {
	Source    string   `json:"source"`
	Records   int      `json:"records"`
	Skipped   int      `json:"skipped"`
	OverCap   int      `json:"over_cap"`
	Truncated bool     `json:"truncated"`
	Entities  []Entity `json:"entities"`
	Edges     []Edge   `json:"edges"`
}

const MaxItems = 50000

var (
	sidPattern  = regexp.MustCompile(`(?i)^S-1-(?:\d+-){1,14}\d+$`)
	guidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	dnsLabel    = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

func ValidObjectKey(v string) bool {
	v = strings.TrimSpace(v)
	return sidPattern.MatchString(v) || guidPattern.MatchString(v)
}

func NormalizeObjectKey(v string) string {
	v = strings.TrimSpace(v)
	if !ValidObjectKey(v) {
		return ""
	}
	return strings.ToUpper(v)
}

func NormalizeDNSName(v string) string {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if v == "" || len(v) > 253 {
		return ""
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return ""
	}
	for _, part := range parts {
		if !dnsLabel.MatchString(part) {
			return ""
		}
	}
	return v
}

func ValidEntityKind(v EntityKind) bool {
	switch v {
	case EntityDomain, EntityUser, EntityGroup, EntityComputer:
		return true
	default:
		return false
	}
}

func ValidRelation(v Relation) bool {
	switch v {
	case RelationMemberOf, RelationAdminTo, RelationHasSession:
		return true
	default:
		return false
	}
}

func (o *Observation) Normalize() error {
	if o == nil {
		return errors.New("nil AD observation")
	}
	entities := make(map[string]Entity, len(o.Entities))
	for _, e := range o.Entities {
		e.Key = NormalizeObjectKey(e.Key)
		if e.Key == "" || !ValidEntityKind(e.Kind) {
			o.Skipped++
			continue
		}
		if sidPattern.MatchString(e.Key) {
			e.SID = e.Key
		} else {
			e.SID = ""
		}
		e.DNSHostname = NormalizeDNSName(e.DNSHostname)
		e.DomainSID = NormalizeObjectKey(e.DomainSID)
		if e.State == "" {
			e.State = Observed
		}
		if e.State != Observed && e.State != Inferred {
			return fmt.Errorf("entity %s has invalid observation state %q", e.Key, e.State)
		}
		if len(e.Detail) > 0 && !json.Valid(e.Detail) {
			return fmt.Errorf("entity %s has invalid detail JSON", e.Key)
		}
		if prior, ok := entities[e.Key]; ok {
			// Prefer the richer deterministic record without merging free text.
			if prior.DNSHostname == "" && e.DNSHostname != "" {
				prior.DNSHostname = e.DNSHostname
			}
			if prior.DomainSID == "" && e.DomainSID != "" {
				prior.DomainSID = e.DomainSID
			}
			entities[e.Key] = prior
			continue
		}
		entities[e.Key] = e
	}

	o.Entities = o.Entities[:0]
	for _, e := range entities {
		o.Entities = append(o.Entities, e)
	}
	sort.Slice(o.Entities, func(i, j int) bool { return o.Entities[i].Key < o.Entities[j].Key })

	edges := make(map[string]Edge, len(o.Edges))
	for _, e := range o.Edges {
		e.SourceKey = NormalizeObjectKey(e.SourceKey)
		e.TargetKey = NormalizeObjectKey(e.TargetKey)
		if e.SourceKey == "" || e.TargetKey == "" || e.SourceKey == e.TargetKey || !ValidRelation(e.Relation) {
			o.Skipped++
			continue
		}
		if _, ok := entities[e.SourceKey]; !ok {
			o.Skipped++
			continue
		}
		if _, ok := entities[e.TargetKey]; !ok {
			o.Skipped++
			continue
		}
		if e.State == "" {
			e.State = Observed
		}
		if e.State != Observed && e.State != Inferred {
			return fmt.Errorf("edge %s has invalid observation state %q", e.Relation, e.State)
		}
		edges[e.SourceKey+"\x00"+string(e.Relation)+"\x00"+e.TargetKey] = e
	}
	o.Edges = o.Edges[:0]
	for _, e := range edges {
		o.Edges = append(o.Edges, e)
	}
	sort.Slice(o.Edges, func(i, j int) bool {
		a, b := o.Edges[i], o.Edges[j]
		if a.SourceKey != b.SourceKey {
			return a.SourceKey < b.SourceKey
		}
		if a.Relation != b.Relation {
			return a.Relation < b.Relation
		}
		return a.TargetKey < b.TargetKey
	})
	return nil
}
