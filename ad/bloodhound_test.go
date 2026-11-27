package ad

import (
	"strings"
	"testing"
)

func TestParseBloodHoundGroupsDeterministic(t *testing.T) {
	raw := `{
  "data": [{
    "ObjectIdentifier": "S-1-5-21-1-2-3-512",
    "Properties": {"name":"DOMAIN ADMINS@CORP.EXAMPLE.COM","domainsid":"S-1-5-21-1-2-3","description":"target supplied text"},
    "Members": [
      {"ObjectIdentifier":"S-1-5-21-1-2-3-1104","ObjectType":"User"},
      {"ObjectIdentifier":"S-1-5-21-1-2-3-1104","ObjectType":"User"}
    ]
  }],
  "meta": {"type":"groups","count":1}
}`
	first, err := ParseBloodHound(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseBloodHound(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Entities) != 2 || len(first.Edges) != 1 {
		t.Fatalf("entities=%d edges=%d: %#v", len(first.Entities), len(first.Edges), first)
	}
	if first.Edges[0].Relation != RelationMemberOf || first.Edges[0].TargetKey != "S-1-5-21-1-2-3-512" {
		t.Fatalf("unexpected edge: %#v", first.Edges[0])
	}
	if string(first.Entities[0].Detail) != string(second.Entities[0].Detail) || first.Edges[0] != second.Edges[0] {
		t.Fatal("parse is not deterministic")
	}
}

func TestParseBloodHoundOUContainsAndGPLink(t *testing.T) {
	raw := `{
  "data": [{
    "ObjectIdentifier": "AAAAAAAA-1111-1111-1111-111111111111",
    "Properties": {"name":"WORKSTATIONS@CORP.EXAMPLE.COM"},
    "ChildObjects": [
      {"ObjectIdentifier":"S-1-5-21-1-2-3-1105","ObjectType":"Computer"},
      {"ObjectIdentifier":"S-1-5-21-1-2-3-1105","ObjectType":"Computer"}
    ],
    "Links": [{"GUID":"BBBBBBBB-2222-2222-2222-222222222222","IsEnforced":false}]
  }],
  "meta": {"type":"ous","count":1}
}`
	o, err := ParseBloodHound(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	// OU entity + one deduplicated computer child + one GPO stub.
	if len(o.Entities) != 3 {
		t.Fatalf("entities=%d: %#v", len(o.Entities), o.Entities)
	}
	// contains edge (duplicated child collapses to one) + gp_link edge.
	if len(o.Edges) != 2 {
		t.Fatalf("edges=%d: %#v", len(o.Edges), o.Edges)
	}
	ou := NormalizeObjectKey("AAAAAAAA-1111-1111-1111-111111111111")
	var hasContains, hasGPLink bool
	for _, e := range o.Edges {
		switch e.Relation {
		case RelationContains:
			hasContains = e.SourceKey == ou && e.TargetKey == "S-1-5-21-1-2-3-1105"
		case RelationGPLink:
			hasGPLink = e.TargetKey == ou && e.SourceKey == NormalizeObjectKey("BBBBBBBB-2222-2222-2222-222222222222")
		}
	}
	if !hasContains || !hasGPLink {
		t.Fatalf("missing structural edges contains=%v gp_link=%v: %#v", hasContains, hasGPLink, o.Edges)
	}
}

func TestParseBloodHoundGPOAndContainerTypes(t *testing.T) {
	gpo := `{"data":[{"ObjectIdentifier":"CCCCCCCC-3333-3333-3333-333333333333","Properties":{"name":"DEFAULT DOMAIN POLICY"}}],"meta":{"type":"gpos","count":1}}`
	o, err := ParseBloodHound(strings.NewReader(gpo))
	if err != nil {
		t.Fatalf("gpos type must parse: %v", err)
	}
	if len(o.Entities) != 1 || o.Entities[0].Kind != EntityGPO {
		t.Fatalf("expected one gpo entity: %#v", o.Entities)
	}

	container := `{"data":[{"ObjectIdentifier":"DDDDDDDD-4444-4444-4444-444444444444","Properties":{"name":"COMPUTERS"},"ChildObjects":[{"ObjectIdentifier":"S-1-5-21-7-7-7-1010","ObjectType":"Computer"}]}],"meta":{"type":"containers","count":1}}`
	c, err := ParseBloodHound(strings.NewReader(container))
	if err != nil {
		t.Fatalf("containers type must parse: %v", err)
	}
	if len(c.Entities) != 2 || len(c.Edges) != 1 || c.Edges[0].Relation != RelationContains {
		t.Fatalf("container contains edge missing: %#v / %#v", c.Entities, c.Edges)
	}
}

func TestParseBloodHoundSharedMemberDedup(t *testing.T) {
	// A principal that belongs to two groups must yield one entity and two
	// membership edges, not two entities. This is the dedup that keeps high-fanout
	// collections from exhausting MaxItems and truncating records.
	raw := `{"data":[
    {"ObjectIdentifier":"S-1-5-21-9-9-9-512","Properties":{"name":"A"},"Members":[{"ObjectIdentifier":"S-1-5-21-9-9-9-1001","ObjectType":"User"}]},
    {"ObjectIdentifier":"S-1-5-21-9-9-9-513","Properties":{"name":"B"},"Members":[{"ObjectIdentifier":"S-1-5-21-9-9-9-1001","ObjectType":"User"}]}
  ],"meta":{"type":"groups","count":2}}`
	o, err := ParseBloodHound(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Entities) != 3 {
		t.Fatalf("expected 3 entities (2 groups + 1 shared user), got %d: %#v", len(o.Entities), o.Entities)
	}
	if len(o.Edges) != 2 {
		t.Fatalf("expected 2 member_of edges, got %d: %#v", len(o.Edges), o.Edges)
	}
	if o.Truncated || o.OverCap != 0 {
		t.Fatalf("unexpected truncation: truncated=%v over_cap=%d", o.Truncated, o.OverCap)
	}
}

func TestParseBloodHoundStubIsEnrichedByLaterRecord(t *testing.T) {
	raw := `{"data":[
    {"ObjectIdentifier":"S-1-5-21-9-9-9-512","Properties":{"name":"A"},"Members":[{"ObjectIdentifier":"S-1-5-21-9-9-9-513","ObjectType":"Group"}]},
    {"ObjectIdentifier":"S-1-5-21-9-9-9-513","Properties":{"name":"B","domainsid":"S-1-5-21-9-9-9"},"Members":[]}
  ],"meta":{"type":"groups","count":2}}`
	o, err := ParseBloodHound(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, entity := range o.Entities {
		if entity.Key != "S-1-5-21-9-9-9-513" {
			continue
		}
		if entity.DomainSID != "S-1-5-21-9-9-9" || len(entity.Detail) == 0 {
			t.Fatalf("later full record did not enrich stub: %#v", entity)
		}
		return
	}
	t.Fatal("referenced group entity was not retained")
}

func TestParseBloodHoundDuplicateEdgesDoNotConsumeCap(t *testing.T) {
	var raw strings.Builder
	raw.WriteString(`{"data":[{"ObjectIdentifier":"S-1-5-21-8-8-8-512","Properties":{"name":"A"},"Members":[`)
	member := `{"ObjectIdentifier":"S-1-5-21-8-8-8-1001","ObjectType":"User"}`
	for i := 0; i < MaxItems+10; i++ {
		if i > 0 {
			raw.WriteByte(',')
		}
		raw.WriteString(member)
	}
	raw.WriteString(`]}],"meta":{"type":"groups","count":1}}`)

	o, err := ParseBloodHound(strings.NewReader(raw.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Entities) != 2 || len(o.Edges) != 1 {
		t.Fatalf("entities=%d edges=%d", len(o.Entities), len(o.Edges))
	}
	if o.Truncated || o.OverCap != 0 {
		t.Fatalf("duplicate relationships consumed cap: truncated=%v over_cap=%d", o.Truncated, o.OverCap)
	}
}

func TestParseBloodHoundUnsupportedType(t *testing.T) {
	if _, err := ParseBloodHound(strings.NewReader(`{"data":[],"meta":{"type":"wombat","count":0}}`)); err == nil {
		t.Fatal("expected error for unsupported collection type")
	}
}

func TestParseBloodHoundComputerRelations(t *testing.T) {
	raw := `{
  "data": [{
    "ObjectIdentifier":"S-1-5-21-1-2-3-1001",
    "Properties":{"name":"DC01.CORP.EXAMPLE.COM","dnshostname":"DC01.CORP.EXAMPLE.COM"},
    "LocalAdmins":{"Results":[{"ObjectIdentifier":"S-1-5-21-1-2-3-512","ObjectType":"Group"}]},
    "Sessions":{"Results":[{"ObjectIdentifier":"S-1-5-21-1-2-3-1104","ObjectType":"User"}]}
  }],
  "meta":{"type":"computers","count":1}
}`
	o, err := ParseBloodHound(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Entities) != 3 || len(o.Edges) != 2 {
		t.Fatalf("entities=%d edges=%d: %#v", len(o.Entities), len(o.Edges), o)
	}
	var host string
	for _, e := range o.Entities {
		if e.Kind == EntityComputer {
			host = e.DNSHostname
		}
	}
	if host != "dc01.corp.example.com" {
		t.Fatalf("dns hostname=%q", host)
	}
}
