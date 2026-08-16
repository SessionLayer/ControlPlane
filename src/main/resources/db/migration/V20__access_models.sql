-- Mirrors runtime.pin, but source-agnostic — a hardware token travels, so this
-- credential is deliberately not source-bound.
CREATE TABLE runtime.breakglass_credential (
    id                 uuid        PRIMARY KEY,
    key_fingerprint    text        NOT NULL UNIQUE,
    public_key         bytea       NOT NULL,                      -- OpenSSH sk-ecdsa-sha2-nistp256 wire pubkey (PUBLIC)
    sk_application      text,
    identity           text        NOT NULL,
    allowed_principals text[]      NOT NULL DEFAULT ARRAY[]::text[],
    node_selector      jsonb       CHECK (node_selector IS NULL OR jsonb_typeof(node_selector) = 'object'), -- optional node scope; NULL = fleet
    expires_at         timestamptz,
    revoked_at         timestamptz,
    created_by         text        NOT NULL,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.breakglass_credential IS 'FR-ACC-6 / §5.2: registered break-glass FIDO2 sk-ecdsa PUBLIC key (primary IdP-independent path). Public material only; revocable; scoped to allowed_principals + optional node_selector.';
CREATE INDEX idx_breakglass_credential_identity ON runtime.breakglass_credential (identity);

CREATE TABLE runtime.breakglass_offline_code (
    id                 uuid        PRIMARY KEY,
    code_hash          text        NOT NULL UNIQUE
                                   CHECK (code_hash NOT LIKE '%PRIVATE KEY%'),
    identity           text        NOT NULL,                      -- the break-glass operator identity (never client input)
    allowed_principals text[]      NOT NULL DEFAULT ARRAY[]::text[],
    node_selector      jsonb       CHECK (node_selector IS NULL OR jsonb_typeof(node_selector) = 'object'),
    source_cidr        text        CHECK (source_cidr IS NULL OR runtime.is_ip_or_cidr(source_cidr)),
    expires_at         timestamptz NOT NULL,
    used               boolean     NOT NULL DEFAULT false,
    used_at            timestamptz,
    revoked_at         timestamptz,
    created_by         text        NOT NULL,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.breakglass_offline_code IS 'FR-ACC-6: pre-issued single-use break-glass code (IdP-independent fallback). Stores code_hash only; atomic single-use; source-bound; ≥128-bit entropy.';
CREATE INDEX idx_breakglass_offline_code_identity ON runtime.breakglass_offline_code (identity);

-- Ties a break-glass Authorize to a genuine credential resolution performed by THIS
-- gateway — a Gateway can never assert break-glass without one.
CREATE TABLE runtime.breakglass_token (
    id                 uuid        PRIMARY KEY,
    token_hash         text        NOT NULL UNIQUE,
    gateway_id         uuid        NOT NULL,
    identity           text        NOT NULL,
    node_id            uuid,
    allowed_principals text[]      NOT NULL DEFAULT ARRAY[]::text[],
    source_address     text        CHECK (source_address IS NULL OR runtime.is_ip_or_cidr(source_address)),
    expires_at         timestamptz NOT NULL,
    used               boolean     NOT NULL DEFAULT false,
    used_at            timestamptz,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.breakglass_token IS 'FR-ACC-6 / §15: single-use break-glass Authorize authority, minted at ResolveBreakglass*, bound to {gateway,identity,node,source,exp}. Hash only; atomic single-use.';
CREATE INDEX idx_breakglass_token_gateway ON runtime.breakglass_token (gateway_id);

ALTER TABLE runtime.breakglass_activation
    ADD COLUMN identity       text,
    ADD COLUMN source_ip      text CHECK (source_ip IS NULL OR runtime.is_ip_or_cidr(source_ip)),
    ADD COLUMN target_node_id uuid,
    ADD COLUMN credential_ref text;
COMMENT ON COLUMN runtime.breakglass_activation.identity IS 'FR-ACC-6: the break-glass operator identity that authenticated (IdP-independent).';
COMMENT ON COLUMN runtime.breakglass_activation.credential_ref IS 'FR-ACC-6: the resolving credential reference (sk-ecdsa fingerprint or offline-code id); legibility for post-hoc review.';

ALTER TABLE runtime.jit_request
    ADD COLUMN policy_max_ttl_seconds integer CHECK (policy_max_ttl_seconds IS NULL OR policy_max_ttl_seconds > 0);
COMMENT ON COLUMN runtime.jit_request.policy_max_ttl_seconds IS 'FR-ACC-2: snapshot of jit_policy.max_ttl_seconds at submit; the grant clock = min(this, cluster ceiling). Prevents a mid-flight policy edit/delete from widening the grant.';

ALTER TABLE config.platform_role DROP CONSTRAINT platform_role_permissions_check;
ALTER TABLE config.platform_role
    ADD CONSTRAINT platform_role_permissions_check
    CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll',
        'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export',
        'audit:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[]);

-- Grants. V11's ALTER DEFAULT PRIVILEGES auto-grants cp_runtime CRUD on the three new
-- runtime tables. Mirror V15/V17 least-privilege on the SINGLE-USE stores: a code/token
-- row is consumed by an UPDATE (used=true), never DELETE, so drop DELETE there.
-- breakglass_credential keeps DELETE (an admin may remove a registration outright, in
-- addition to the soft revoked_at). Re-assert idempotently for legibility.
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.breakglass_credential TO cp_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON runtime.breakglass_offline_code TO cp_runtime';
        EXECUTE 'REVOKE DELETE ON runtime.breakglass_offline_code FROM cp_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON runtime.breakglass_token TO cp_runtime';
        EXECUTE 'REVOKE DELETE ON runtime.breakglass_token FROM cp_runtime';
    END IF;
END
$grant$;
