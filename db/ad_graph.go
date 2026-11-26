package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/ad"
)

type ADIngestResult struct {
	EntitiesUpserted int  `json:"entities_upserted"`
	EdgesUpserted    int  `json:"edges_upserted"`
	Records          int  `json:"records"`
	Skipped          int  `json:"skipped"`
	OverCap          int  `json:"over_cap"`
	Truncated        bool `json:"truncated"`
}

type ADGraph struct {
	Entities []ad.Entity `json:"entities"`
	Edges    []ad.Edge   `json:"edges"`
}

// IngestADObservation atomically merges typed collector observations into the
// current exploration. It never writes assets, task_scope or company_scope.
func (s *ExplorationStore) IngestADObservation(ctx context.Context, observation ad.Observation) (ADIngestResult, error) {
	if s == nil || s.db == nil || s.expID <= 0 {
		return ADIngestResult{}, fmt.Errorf("AD ingest requires an exploration")
	}
	if err := observation.Normalize(); err != nil {
		return ADIngestResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ADIngestResult{}, err
	}
	defer tx.Rollback()
	result := ADIngestResult{
		Records: observation.Records, Skipped: observation.Skipped,
		OverCap: observation.OverCap, Truncated: observation.Truncated,
	}
	for _, entity := range observation.Entities {
		detail := entity.Detail
		if len(detail) == 0 {
			detail = json.RawMessage(`{}`)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO ad_nodes(exploration_id, object_key, kind, sid, dns_hostname, domain_sid, state, detail)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (exploration_id, object_key) DO UPDATE SET
  kind=EXCLUDED.kind,
  sid=CASE WHEN EXCLUDED.sid <> '' THEN EXCLUDED.sid ELSE ad_nodes.sid END,
  dns_hostname=CASE WHEN EXCLUDED.dns_hostname <> '' THEN EXCLUDED.dns_hostname ELSE ad_nodes.dns_hostname END,
  domain_sid=CASE WHEN EXCLUDED.domain_sid <> '' THEN EXCLUDED.domain_sid ELSE ad_nodes.domain_sid END,
  state=CASE WHEN ad_nodes.state='observed' THEN ad_nodes.state ELSE EXCLUDED.state END,
  detail=CASE WHEN EXCLUDED.detail <> '{}'::jsonb THEN EXCLUDED.detail ELSE ad_nodes.detail END,
  last_seen_at=now()`, s.expID, entity.Key, entity.Kind, entity.SID, entity.DNSHostname,
			entity.DomainSID, entity.State, string(jsonbClean(detail))); err != nil {
			return ADIngestResult{}, err
		}
		result.EntitiesUpserted++
	}
	for _, edge := range observation.Edges {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO ad_edges(exploration_id, source_key, relation, target_key, state)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (exploration_id, source_key, relation, target_key) DO UPDATE SET
  state=CASE WHEN ad_edges.state='observed' THEN ad_edges.state ELSE EXCLUDED.state END,
  last_seen_at=now()`, s.expID, edge.SourceKey, edge.Relation, edge.TargetKey, edge.State); err != nil {
			return ADIngestResult{}, err
		}
		result.EdgesUpserted++
	}
	if err := tx.Commit(); err != nil {
		return ADIngestResult{}, err
	}
	return result, nil
}

func (s *ExplorationStore) ADGraph(ctx context.Context) (ADGraph, error) {
	if s == nil || s.db == nil || s.expID <= 0 {
		return ADGraph{}, fmt.Errorf("AD graph requires an exploration")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT object_key, kind, sid, dns_hostname, domain_sid, state, detail
FROM ad_nodes WHERE exploration_id=$1 ORDER BY object_key`, s.expID)
	if err != nil {
		return ADGraph{}, err
	}
	defer rows.Close()
	var graph ADGraph
	for rows.Next() {
		var entity ad.Entity
		var detail []byte
		if err := rows.Scan(&entity.Key, &entity.Kind, &entity.SID, &entity.DNSHostname,
			&entity.DomainSID, &entity.State, &detail); err != nil {
			return ADGraph{}, err
		}
		entity.Detail = append(json.RawMessage(nil), detail...)
		graph.Entities = append(graph.Entities, entity)
	}
	if err := rows.Err(); err != nil {
		return ADGraph{}, err
	}
	edgeRows, err := s.db.QueryContext(ctx, `
SELECT source_key, relation, target_key, state
FROM ad_edges WHERE exploration_id=$1 ORDER BY source_key, relation, target_key`, s.expID)
	if err != nil {
		return ADGraph{}, err
	}
	defer edgeRows.Close()
	for edgeRows.Next() {
		var edge ad.Edge
		if err := edgeRows.Scan(&edge.SourceKey, &edge.Relation, &edge.TargetKey, &edge.State); err != nil {
			return ADGraph{}, err
		}
		graph.Edges = append(graph.Edges, edge)
	}
	return graph, edgeRows.Err()
}

// ADGraphCounts is a compact read for progress and tests.
func (s *ExplorationStore) ADGraphCounts(ctx context.Context) (entities, edges int, err error) {
	if s == nil || s.db == nil || s.expID <= 0 {
		return 0, 0, fmt.Errorf("AD graph requires an exploration")
	}
	err = s.db.QueryRowContext(ctx, `
SELECT (SELECT count(*) FROM ad_nodes WHERE exploration_id=$1),
       (SELECT count(*) FROM ad_edges WHERE exploration_id=$1)`, s.expID).Scan(&entities, &edges)
	if err == sql.ErrNoRows {
		err = nil
	}
	return
}
