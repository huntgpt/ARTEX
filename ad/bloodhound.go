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
	addStub := func(key string, stubKind EntityKind) string {
		key = NormalizeObjectKey(key)
		if key == "" || !ValidEntityKind(stubKind) {
			return ""
		}
		o.Entities = append(o.Entities, Entity{Key: key, Kind: stubKind, State: Observed})
		return key
	}
	for _, object := range env.Data {
		o.Records++
		if len(o.Entities)+len(o.Edges) >= MaxItems {
			o.OverCap++
			o.Truncated = true
			continue
		}
		key := NormalizeObjectKey(object.ObjectIdentifier)
		if key == "" {
			o.Skipped++
			continue
		}
		detail, _ := json.Marshal(map[string]any{"properties": object.Properties})
		entity := Entity{
			Key:         key,
			Kind:        kind,
			DNSHostname: typedProperty(object.Properties, "dnshostname"),
			DomainSID:   typedProperty(object.Properties, "domainsid", "domain_sid"),
			State:       Observed,
			Detail:      detail,
		}
		o.Entities = append(o.Entities, entity)

		if kind == EntityGroup {
			for _, member := range object.Members {
				memberKey := addStub(member.ObjectIdentifier, entityKindForObjectType(member.ObjectType))
				if memberKey != "" {
					o.Edges = append(o.Edges, Edge{SourceKey: memberKey, Relation: RelationMemberOf, TargetKey: key, State: Observed})
				}
			}
		}
		if kind == EntityComputer {
			for _, principal := range object.LocalAdmins.Results {
				principalKey := addStub(principal.ObjectIdentifier, entityKindForObjectType(principal.ObjectType))
				if principalKey != "" {
					o.Edges = append(o.Edges, Edge{SourceKey: principalKey, Relation: RelationAdminTo, TargetKey: key, State: Observed})
				}
			}
			for _, session := range object.Sessions.Results {
				sessionKey := addStub(session.ObjectIdentifier, entityKindForObjectType(session.ObjectType))
				if sessionKey != "" {
					o.Edges = append(o.Edges, Edge{SourceKey: sessionKey, Relation: RelationHasSession, TargetKey: key, State: Observed})
				}
			}
		}
	}
	if err := o.Normalize(); err != nil {
		return Observation{}, err
	}
	return o, nil
}
