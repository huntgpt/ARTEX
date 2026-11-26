package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) getTaskSupervisor(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, task.supervisorSnapshot())
}

func (s *Server) updateTaskSupervisor(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req db.TaskSupervisorConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	normalized, err := db.NormalizeTaskSupervisorConfig(&req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	profileIDs := make([]int64, 0, 2)
	if normalized.PrimaryProfileID != nil {
		profileIDs = append(profileIDs, *normalized.PrimaryProfileID)
	}
	if normalized.SecondaryProfileID != nil {
		profileIDs = append(profileIDs, *normalized.SecondaryProfileID)
	}
	if err := s.validateTaskProfileIDs(profileIDs); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg, err := s.m.ReplaceTaskSupervisorConfig(task.ID, &normalized)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, db.ErrSupervisorConfigInvalid) || errors.Is(err, db.ErrSupervisorProfileAbsent) {
			status = http.StatusBadRequest
		} else if errors.Is(err, sql.ErrNoRows) {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) listTaskSupervisorRounds(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	taskID, err := parseTaskID(task.ID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rounds, err := s.m.PG().SupervisorRoundDetails(taskID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rounds})
}

func (s *Server) runTaskSupervisor(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if task.supervisorSnapshot().Mode == db.SupervisorModeOff {
		writeErr(w, http.StatusConflict, "project supervision is disabled for this task")
		return
	}
	advice, err := s.runSupervisorCheckpoint(r.Context(), task, nil, "manual")
	if err != nil {
		status := http.StatusInternalServerError
		lower := strings.ToLower(err.Error())
		if errors.Is(err, errSupervisorRoundActive) || strings.Contains(lower, "open supervisor round") || strings.Contains(lower, "duplicate key") {
			status = http.StatusConflict
		}
		writeErr(w, status, err.Error())
		return
	}
	// The completed decision is durable in supervisor_decisions. Wake the
	// canonical Planner, which consumes the newest unconsumed manual decision
	// before it may run another automatic checkpoint.
	task.Notify()
	writeJSON(w, http.StatusOK, advice)
}
