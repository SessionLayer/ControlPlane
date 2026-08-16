-- The columns stay. Removals ship in a later release ("contract"), and the previous
-- release's binary still SELECTs them; this release simply stops mapping them, so
-- new rows take the health DEFAULT and both values go stale in place.

COMMENT ON COLUMN runtime.node.health IS
    'DEPRECATED — not read and not written. Retained for the expand/contract window only; new rows take the DEFAULT and the value never changes afterwards. The API derives health at read time: unhealthy when the node has no runtime.node_host_key anchor (the Gateway never TOFUs, so every session aborts); otherwise, for an agent-connected node, healthy/unreachable from the freshness of its runtime.presence claim and unknown when no Gateway has ever claimed it; agentless nodes are always unknown (no continuous liveness signal, no probe).';

COMMENT ON COLUMN runtime.node.owning_gateway IS
    'DEPRECATED — not read and not written. Retained for the expand/contract window only. The API derives the owner at read time from runtime.presence.owning_gateway, and only while that claim is fresh by the HA staleness window — the same rule connect-time routing applies, so the two answers cannot disagree.';
