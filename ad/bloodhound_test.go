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
