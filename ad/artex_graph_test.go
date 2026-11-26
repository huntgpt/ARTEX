package ad

import (
	"strings"
	"testing"
)

func TestParseARTEXGraphExtendedAttackPaths(t *testing.T) {
	raw := `{
  "source":"configmanbearpig",
  "entities":[
    {"key":"SCCM:SITE:ABC","kind":"sccm_site","state":"observed"},
    {"key":"MSSQL:SQL01:1433","kind":"mssql_server","state":"observed"},
    {"key":"S-1-5-21-1-2-3-1104","kind":"user","state":"observed"},
    {"key":"11111111-2222-3333-4444-555555555555","kind":"cert_template","state":"observed"}
  ],
  "edges":[
    {"source_key":"S-1-5-21-1-2-3-1104","relation":"sccm_full_administrator","target_key":"SCCM:SITE:ABC","state":"observed"},
    {"source_key":"SCCM:SITE:ABC","relation":"mssql_control_server","target_key":"MSSQL:SQL01:1433","state":"observed"},
    {"source_key":"S-1-5-21-1-2-3-1104","relation":"adcs_esc1","target_key":"11111111-2222-3333-4444-555555555555","state":"inferred"}
  ]
}`
	observation, err := ParseARTEXGraph(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Source != "configmanbearpig" || len(observation.Entities) != 4 || len(observation.Edges) != 3 {
		t.Fatalf("unexpected graph: %+v", observation)
	}
	if observation.Edges[0].Relation != "adcs_esc1" {
		t.Fatalf("edges were not normalized deterministically: %+v", observation.Edges)
	}
}

func TestNormalizeOpaqueObjectKeyHashesUnsafeText(t *testing.T) {
	one := NormalizeObjectKey("unsafe key with spaces")
	two := NormalizeObjectKey("unsafe key with spaces")
	if one == "" || one != two || !strings.HasPrefix(one, "OPAQUE:") {
		t.Fatalf("opaque key normalization is not stable: %q %q", one, two)
	}
}
