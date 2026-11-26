package ad

import "fmt"

type RunState string

const (
	RunQueued    RunState = "queued"
	RunApproved  RunState = "approved"
	RunRunning   RunState = "running"
	RunIngesting RunState = "ingesting"
	RunComplete  RunState = "complete"
	RunPartial   RunState = "partial"
	RunRejected  RunState = "rejected"
	RunFailed    RunState = "failed"
	RunCancelled RunState = "cancelled"
)

var runTransitions = map[RunState]map[RunState]bool{
	RunQueued:    {RunApproved: true, RunRejected: true, RunCancelled: true},
	RunApproved:  {RunRunning: true, RunIngesting: true, RunCancelled: true},
	RunRunning:   {RunIngesting: true, RunFailed: true, RunCancelled: true},
	RunIngesting: {RunComplete: true, RunPartial: true, RunFailed: true, RunCancelled: true},
}

func CanTransition(from, to RunState) bool {
	return from != to && runTransitions[from][to]
}

func ValidateTransition(from, to RunState) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("invalid AD collection run transition %q -> %q", from, to)
	}
	return nil
}

func (s RunState) Terminal() bool {
	switch s {
	case RunComplete, RunPartial, RunRejected, RunFailed, RunCancelled:
		return true
	default:
		return false
	}
}
