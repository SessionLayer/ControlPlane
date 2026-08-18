ALTER TABLE runtime.agent_identity ADD COLUMN prev_fingerprint text;
COMMENT ON COLUMN runtime.agent_identity.prev_fingerprint IS
    'SHA-256 fingerprint of the previous-generation mTLS cert; pinned alongside fingerprint at renew to survive renew-ahead overlap (M6). Public material.';

-- Grants. V11 already granted cp_runtime SELECT/INSERT/UPDATE/DELETE on ALL
-- runtime tables (incl. agent_identity, join_token, node) plus default privileges
-- for future tables, so the agent-join write paths - agent_identity status flip
-- (UPDATE), node registration (INSERT/UPDATE), join_token issue/consume/revoke
-- (INSERT/UPDATE/DELETE), access_lock insert (SELECT/INSERT) - are already
-- covered, and the new prev_fingerprint column inherits the table-level grant.
-- V15 revoked DELETE only from the V14 token tables (gateway_enrollment_token /
-- session_signing_token), NOT from join_token, so join-token revoke (DELETE) is
-- available. Re-assert the join-token grants idempotently for legibility so this
-- migration is self-contained about the rights the agent-join API relies on.
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.join_token TO cp_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON runtime.agent_identity TO cp_runtime';
    END IF;
END
$grant$;
