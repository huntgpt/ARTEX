package ad

import (
	"encoding/json"
	"fmt"
	"io"
)

// ParseARTEXGraph imports a normalized graph produced by adapters for
// BloodHound OpenGraph, Certipy, ConfigManBearPig, MSSQL or Exchange tooling.
// Node/edge names remain typed, inert identifiers; no supplied text is executed.
func ParseARTEXGraph(r io.Reader) (Observation, error) {
	var observation Observation
	decoder := json.NewDecoder(io.LimitReader(r, 256<<20))
	if err := decoder.Decode(&observation); err != nil {
		return Observation{}, fmt.Errorf("decode ARTEX AD graph: %w", err)
	}
	if observation.Source == "" {
		observation.Source = "artex-ad-graph-json"
	}
	if observation.Records == 0 {
		observation.Records = len(observation.Entities) + len(observation.Edges)
	}
	if err := observation.Normalize(); err != nil {
		return Observation{}, err
	}
	return observation, nil
}
