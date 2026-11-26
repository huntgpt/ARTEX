package server

import (
	"net/http"
	"strings"
)

func (s *Server) taskRedTeamWorkflow(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	workflow, err := s.m.PG().RedTeamWorkflowRuns(r.Context(), task.ExpID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"phases": workflow})
}

func (s *Server) transitionTaskRedTeamPhase(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var body struct {
		State         string `json:"state"`
		Owner         string `json:"owner"`
		Tool          string `json:"tool"`
		CurrentResult string `json:"current_result"`
		BlockerReason string `json:"blocker_reason"`
		BlockerKind   string `json:"blocker_kind"`
		BlockerSource string `json:"blocker_source"`
	}
	if err := decode(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	phases, err := s.m.PG().TransitionRedTeamPhase(r.Context(), task.ExpID, strings.TrimSpace(r.PathValue("phase")), body.State, body.Owner, body.Tool, body.CurrentResult, body.BlockerReason, body.BlockerKind, body.BlockerSource)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"phases": phases})
}
