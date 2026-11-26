package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	maxPlannerTodoItems   = 128
	maxPlannerTodoContent = 16 << 10
)

// PlannerTodo is the durable representation of one planner TodoWrite item.
// It intentionally lives in db rather than importing the agent SDK into the
// persistence layer.
type PlannerTodo struct {
	Content string `json:"content"`
	Status  string `json:"status"`
}

func validatePlannerTodos(items []PlannerTodo) error {
	if len(items) > maxPlannerTodoItems {
		return fmt.Errorf("planner todo count %d exceeds limit %d", len(items), maxPlannerTodoItems)
	}
	for i, item := range items {
		if len(item.Content) > maxPlannerTodoContent {
			return fmt.Errorf("planner todo %d content exceeds %d bytes", i, maxPlannerTodoContent)
		}
		switch strings.TrimSpace(item.Status) {
		case "pending", "in_progress", "completed":
		default:
			return fmt.Errorf("planner todo %d has invalid status %q", i, item.Status)
		}
	}
	return nil
}

// LoadPlannerTodos returns the latest task-level planner scratchpad. A task
// without a saved plan returns an empty slice.
func (s *ExplorationStore) LoadPlannerTodos() ([]PlannerTodo, error) {
	var raw []byte
	err := s.db.QueryRow(`SELECT items FROM planner_todos WHERE exploration_id=$1`, s.expID).Scan(&raw)
	if err == sql.ErrNoRows {
		return []PlannerTodo{}, nil
	}
	if err != nil {
		return nil, err
	}
	var items []PlannerTodo
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("decode planner todos: %w", err)
	}
	if err := validatePlannerTodos(items); err != nil {
		return nil, fmt.Errorf("stored planner todos: %w", err)
	}
	return items, nil
}

// SavePlannerTodos atomically replaces the scratchpad, matching TodoWrite's
// replace-the-whole-list semantics.
func (s *ExplorationStore) SavePlannerTodos(items []PlannerTodo) error {
	if err := validatePlannerTodos(items); err != nil {
		return err
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO planner_todos(exploration_id, items, updated_at)
		VALUES ($1, $2::jsonb, now())
		ON CONFLICT (exploration_id) DO UPDATE
		SET items=EXCLUDED.items, updated_at=now()`, s.expID, raw)
	return err
}
