-- V32 — runtime.node.health and runtime.node.owning_gateway are no longer read or written.
-- SessionLayer Control Plane.
--
-- Both columns were stamped once at registration ('unknown', NULL) and updated by
-- nothing, so the API reported every working node as health=unknown with no owner —
-- an operator following the install guide read a successful Agent install as a
-- failure. The API now derives both at read time from the sources that actually
-- carry the state: runtime.presence (which Gateway holds the node's agent control
-- channel, and how recently, against the HA staleness window) and
-- runtime.node_host_key (whether the node has any enrollment-anchored host identity
-- — without one the Gateway aborts every session, because it never TOFUs).
--
-- The columns stay. Removals ship in a later release ("contract"), and the previous
-- release's binary still SELECTs them; this release simply stops mapping them, so
-- new rows take the health DEFAULT and both values go stale in place.
--
-- What must NOT stay is the catalog comment. COMMENT ON is executed into
-- pg_description on every running cluster and is what an operator reads from
-- \d+ runtime.node — shipped documentation that would otherwise keep asserting a
-- liveness story the code no longer implements. Metadata only: no table, column,
-- constraint, index or grant is created, altered or dropped, and no row is read or
-- written.

COMMENT ON COLUMN runtime.node.health IS
    'DEPRECATED — not read and not written. Retained for the expand/contract window only; new rows take the DEFAULT and the value never changes afterwards. The API derives health at read time: unhealthy when the node has no runtime.node_host_key anchor (the Gateway never TOFUs, so every session aborts); otherwise, for an agent-connected node, healthy/unreachable from the freshness of its runtime.presence claim and unknown when no Gateway has ever claimed it; agentless nodes are always unknown (no continuous liveness signal, no probe).';

COMMENT ON COLUMN runtime.node.owning_gateway IS
    'DEPRECATED — not read and not written. Retained for the expand/contract window only. The API derives the owner at read time from runtime.presence.owning_gateway, and only while that claim is fresh by the HA staleness window — the same rule connect-time routing applies, so the two answers cannot disagree.';
