-- Keep AD/OpenGraph modeling extensible for new BloodHound base kinds and
-- vendor schemas (ADCS, SCCM/MECM, MSSQL, Exchange) without another migration
-- for every upstream node or edge kind.
ALTER TABLE ad_nodes DROP CONSTRAINT IF EXISTS ad_nodes_kind_check;
ALTER TABLE ad_nodes ADD CONSTRAINT ad_nodes_kind_check
    CHECK (kind ~ '^[a-z][a-z0-9_]{0,63}$');

ALTER TABLE ad_edges DROP CONSTRAINT IF EXISTS ad_edges_relation_check;
ALTER TABLE ad_edges ADD CONSTRAINT ad_edges_relation_check
    CHECK (relation ~ '^[a-z][a-z0-9_]{0,95}$');

ALTER TABLE ad_collection_runs DROP CONSTRAINT IF EXISTS ad_collection_runs_collector_check;
ALTER TABLE ad_collection_runs ADD CONSTRAINT ad_collection_runs_collector_check
    CHECK (collector IN (
      'sharphound','bloodhound-python','bloodhound','adexplorer','ldap','operator-upload',
      'certipy','configmanbearpig','bloodyad','ldapdomaindump','impacket','netexec'
    ));

ALTER TABLE ad_collection_artifacts DROP CONSTRAINT IF EXISTS ad_collection_artifacts_kind_check;
ALTER TABLE ad_collection_artifacts ADD CONSTRAINT ad_collection_artifacts_kind_check
    CHECK (kind IN (
      'bloodhound-json','bloodhound-zip','bloodhound-opengraph-json','artex-ad-graph-json',
      'adexplorer-snapshot','certipy-json','configmanbearpig-zip','collector-log'
    ));
