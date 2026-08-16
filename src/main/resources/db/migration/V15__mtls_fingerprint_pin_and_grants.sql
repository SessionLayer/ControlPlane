ALTER TABLE runtime.gateway_identity ADD COLUMN prev_fingerprint text;
COMMENT ON COLUMN runtime.gateway_identity.prev_fingerprint IS
    'SHA-256 fingerprint of the previous-generation mTLS cert; pinned alongside fingerprint at the sign/renew tiers to survive renew-ahead overlap (M6). Public material.';

-- Both tables are single-use via an UPDATE (mark consumed/used); cp_runtime never
-- DELETEs a token row. Drop the DELETE grant V14 issued (mirrors V12's write-once
-- discipline).
DO $revoke$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'REVOKE DELETE ON runtime.gateway_enrollment_token FROM cp_runtime';
        EXECUTE 'REVOKE DELETE ON runtime.session_signing_token FROM cp_runtime';
    END IF;
END
$revoke$;
