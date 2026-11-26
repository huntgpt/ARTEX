package ad

import "testing"

func TestRunTransitions(t *testing.T) {
	valid := [][2]RunState{{RunQueued, RunApproved}, {RunApproved, RunIngesting}, {RunIngesting, RunComplete}}
	for _, tr := range valid {
		if err := ValidateTransition(tr[0], tr[1]); err != nil {
			t.Fatalf("expected %s -> %s: %v", tr[0], tr[1], err)
		}
	}
	for _, tr := range [][2]RunState{{RunQueued, RunComplete}, {RunComplete, RunRunning}, {RunRejected, RunApproved}} {
		if err := ValidateTransition(tr[0], tr[1]); err == nil {
			t.Fatalf("expected rejection for %s -> %s", tr[0], tr[1])
		}
	}
}

func TestNormalizeDNSName(t *testing.T) {
	if got := NormalizeDNSName("DC01.CORP.EXAMPLE.COM."); got != "dc01.corp.example.com" {
		t.Fatalf("got %q", got)
	}
	for _, bad := range []string{"dc01", "-bad.example.com", "bad_.example.com", ""} {
		if got := NormalizeDNSName(bad); got != "" {
			t.Fatalf("%q normalized to %q", bad, got)
		}
	}
}
