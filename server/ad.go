package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/ad"
	"github.com/Autumn-27/artex/db"
)

func (s *Server) taskADGraph(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	graph, err := task.Store.ADGraph(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entities": graph.Entities, "edges": graph.Edges,
		"entity_count": len(graph.Entities), "edge_count": len(graph.Edges),
	})
}

func (s *Server) taskADRuns(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	runs, err := s.m.PG().ListADCollectionRuns(r.Context(), task.ExpID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

func (s *Server) createTaskADRun(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var body struct {
		Collector   string `json:"collector"`
		Mode        string `json:"mode"`
		RequestedBy string `json:"requested_by"`
	}
	if err := decode(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.RequestedBy) == "" {
		body.RequestedBy = "operator"
	}
	run, err := s.m.PG().CreateADCollectionRun(r.Context(), task.ExpID, body.Collector, body.Mode, body.RequestedBy)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) transitionTaskADRun(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	runID, err := strconv.ParseInt(r.PathValue("run"), 10, 64)
	if err != nil || runID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid AD collection run id")
		return
	}
	var body struct {
		State  ad.RunState `json:"state"`
		Actor  string      `json:"actor"`
		Reason string      `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.Actor) == "" {
		body.Actor = "operator"
	}
	run, err := s.m.PG().TransitionADCollectionRun(r.Context(), task.ExpID, runID, body.State, body.Actor, body.Reason)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, db.ErrADRunStateConflict) {
			status = http.StatusConflict
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}
