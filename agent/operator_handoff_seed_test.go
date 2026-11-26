package agent

import "strings"
import "testing"

// Environmental network failures must stay autonomous in the executor agents'
// default seeds: one identical retry, one structured fact, and no operator wait.
func TestPromptSeedsCarryEnvironmentalBlockerContract(t *testing.T) {
	for name, tmpl := range BuiltinPromptSeeds() {
		switch name {
		case "worker", "pentest":
			for _, marker := range []string{
				"Environmental failure handling",
				"two total attempts maximum",
				"[environmental_blocker]",
				"operator_action=none",
				"Never ask the operator merely to repeat a failed network probe",
			} {
				if !strings.Contains(tmpl, marker) {
					t.Errorf("%s seed missing environmental-blocker marker %q", name, marker)
				}
			}
		}
	}
}
