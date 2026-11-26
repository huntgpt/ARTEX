package db

// FindingIDsForEvidenceNode returns standalone finding IDs whose bounded
// evidence lineage includes nodeID. The forward walk stops at the first finding
// so arbitrary work after a finding is not inherited; a direct
// finding --derived_from--> follow-up is included explicitly.
func (s *ExplorationStore) FindingIDsForEvidenceNode(nodeID int64) ([]int64, error) {
	rows, err := s.db.Query(`
WITH RECURSIVE forward(id,kind) AS (
    SELECT n.id,n.kind
    FROM exploration_nodes n
    WHERE n.exploration_id=$1 AND n.id=$2
  UNION
    SELECT dst.id,dst.kind
    FROM exploration_edges e
    JOIN forward src ON src.id=e.src_id AND src.kind<>'finding'
    JOIN exploration_nodes dst ON dst.id=e.dst_id AND dst.exploration_id=e.exploration_id
    WHERE e.exploration_id=$1
), matched(node_id) AS (
    SELECT id FROM forward WHERE kind='finding'
  UNION
    SELECT e.src_id
    FROM exploration_edges e
    JOIN exploration_nodes finding ON finding.id=e.src_id AND finding.exploration_id=e.exploration_id AND finding.kind='finding'
    JOIN exploration_nodes followup ON followup.id=e.dst_id AND followup.exploration_id=e.exploration_id AND followup.kind='intent'
    WHERE e.exploration_id=$1 AND e.dst_id=$2 AND e.rel=$3
)
SELECT f.id
FROM findings f
JOIN matched m ON m.node_id=f.node_id
WHERE f.task_id IS NOT NULL
ORDER BY f.id`, s.expID, nodeID, RelDerivedFrom)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
