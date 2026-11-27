package ad

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type bloodHoundEnvelope struct {
	Data []bloodHoundObject `json:"data"`
	Meta struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	} `json:"meta"`
}

type bloodHoundObject struct {
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	Properties       map[string]any `json:"Properties"`
	Members          []struct {
		ObjectIdentifier string `json:"ObjectIdentifier"`
		ObjectType       string `json:"ObjectType"`
	} `json:"Members"`
	// ChildObjects is emitted by SharpHound for domains, OUs and containers and
	// enumerates the directly contained objects.
	ChildObjects []struct {
		ObjectIdentifier string `json:"ObjectIdentifier"`
		ObjectType       string `json:"ObjectType"`
	} `json:"ChildObjects"`
	// Links enumerates the GPOs linked to a domain/OU; GUID is the GPO identifier.
	Links []struct {
		GUID       string `json:"GUID"`
		IsEnforced bool   `json:"IsEnforced"`
	} `json:"Links"`
	LocalAdmins bloodHoundPrincipalSet `json:"LocalAdmins"`
	Sessions    bloodHoundPrincipalSet `json:"Sessions"`
}

type bloodHoundPrincipalSet struct {
	Results []struct {
		ObjectIdentifier string `json:"ObjectIdentifier"`
		ObjectType       string `json:"ObjectType"`
	} `json:"Results"`
}

func entityKindForCollection(v string) EntityKind {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "domains", "domain":
		return EntityDomain
	case "users", "user":
		return EntityUser
	case "groups", "group":
		return EntityGroup
	case "computers", "computer":
		return EntityComputer
	case "ous", "ou":
		return EntityOU
	case "gpos", "gpo":
		return EntityGPO
	case "containers", "container":
		return EntityContainer
	default:
		return ""
	}
}

func entityKindForObjectType(v string) EntityKind {
	return entityKindForCollection(v)
}

func typedProperty(m map[string]any, names ...string) string {
	for _, name := range names {
		for k, value := range m {
			if !strings.EqualFold(k, name) {
				continue
			}
			if s, ok := value.(string); ok {
				return s
			}
		}
	}
	return ""
}

// ParseBloodHound parses one BloodHound/SharpHound JSON collection. It does not
// infer permissions or execute an attack. Cross-file edge endpoints are emitted
// as typed stub entities so later files can enrich them deterministically.
func ParseBloodHound(r io.Reader) (Observation, error) {
	var env bloodHoundEnvelope
	dec := json.NewDecoder(io.LimitReader(r, 256<<20))
	if err := dec.Decode(&env); err != nil {
		return Observation{}, fmt.Errorf("decode BloodHound JSON: %w", err)
	}
	kind := entityKindForCollection(env.Meta.Type)
	if kind == "" {
		return Observation{}, fmt.Errorf("unsupported BloodHound collection type %q", env.Meta.Type)
	}
	o := Observation{Source: "bloodhound-json"}
	// entityIndex and edgeSeen deduplicate before enforcing MaxItems. Collector
	// files repeat principals and relationships heavily; counting those repeats
	// previously exhausted the cap before Normalize could collapse them.
	entityIndex := make(map[string]int)
	edgeSeen := make(map[string]struct{})
	atCap := func() bool { return len(o.Entities)+len(o.Edges) >= MaxItems }
	// addEntity returns true when the key is present after the call (either newly
	// added or already seen) and false only when the cap blocked a new insert. A
	// full record may arrive after a stub, so enrich the retained entity without
	// merging arbitrary non-empty target-controlled detail.
	addEntity := func(e Entity) bool {
		if idx, ok := entityIndex[e.Key]; ok {
			prior := &o.Entities[idx]
			if prior.DNSHostname == "" && e.DNSHostname != "" {
				prior.DNSHostname = e.DNSHostname
			}
			if prior.DomainSID == "" && e.DomainSID != "" {
				prior.DomainSID = e.DomainSID
			}
			if len(prior.Detail) == 0 && len(e.Detail) > 0 {
				prior.Detail = e.Detail
			}
			return true
		}
		if atCap() {
			o.OverCap++
			o.Truncated = true
			return false
		}
		entityIndex[e.Key] = len(o.Entities)
		o.Entities = append(o.Entities, e)
		return true
	}
	addStub := func(key string, stubKind EntityKind) string {
		key = NormalizeObjectKey(key)
		if key == "" || !ValidEntityKind(stubKind) {
			return ""
		}
		if !addEntity(Entity{Key: key, Kind: stubKind, State: Observed}) {
			return ""
		}
		return key
	}
	addEdge := func(e Edge) {
		edgeKey := e.SourceKey + "\x00" + string(e.Relation) + "\x00" + e.TargetKey
		if _, ok := edgeSeen[edgeKey]; ok {
			return
		}
		if atCap() {
			o.OverCap++
			o.Truncated = true
			return
		}
		edgeSeen[edgeKey] = struct{}{}
		o.Edges = append(o.Edges, e)
	}
	for _, object := range env.Data {
		o.Records++
		key := NormalizeObjectKey(object.ObjectIdentifier)
		if key == "" {
			o.Skipped++
			continue
		}
		detail, _ := json.Marshal(map[string]any{"properties": object.Properties})
		if !addEntity(Entity{
			Key:         key,
			Kind:        kind,
			DNSHostname: typedProperty(object.Properties, "dnshostname"),
			DomainSID:   typedProperty(object.Properties, "domainsid", "domain_sid"),
			State:       Observed,
			Detail:      detail,
		}) {
			continue
		}

		if kind == EntityGroup {
			for _, member := range object.Members {
				memberKey := addStub(member.ObjectIdentifier, entityKindForObjectType(member.ObjectType))
				if memberKey != "" {
					addEdge(Edge{SourceKey: memberKey, Relation: RelationMemberOf, TargetKey: key, State: Observed})
				}
			}
		}
		if kind == EntityComputer {
			for _, principal := range object.LocalAdmins.Results {
				principalKey := addStub(principal.ObjectIdentifier, entityKindForObjectType(principal.ObjectType))
				if principalKey != "" {
					addEdge(Edge{SourceKey: principalKey, Relation: RelationAdminTo, TargetKey: key, State: Observed})
				}
			}
			for _, session := range object.Sessions.Results {
				sessionKey := addStub(session.ObjectIdentifier, entityKindForObjectType(session.ObjectType))
				if sessionKey != "" {
					addEdge(Edge{SourceKey: sessionKey, Relation: RelationHasSession, TargetKey: key, State: Observed})
				}
			}
		}
		// Domains, OUs and containers carry the directory hierarchy and GPO links.
		if kind == EntityDomain || kind == EntityOU || kind == EntityContainer {
			for _, child := range object.ChildObjects {
				childKey := addStub(child.ObjectIdentifier, entityKindForObjectType(child.ObjectType))
				if childKey != "" {
					addEdge(Edge{SourceKey: key, Relation: RelationContains, TargetKey: childKey, State: Observed})
				}
			}
			for _, link := range object.Links {
				gpoKey := addStub(link.GUID, EntityGPO)
				if gpoKey != "" {
					addEdge(Edge{SourceKey: gpoKey, Relation: RelationGPLink, TargetKey: key, State: Observed})
				}
			}
		}
	}
	if err := o.Normalize(); err != nil {
		return Observation{}, err
	}
	return o, nil
}
