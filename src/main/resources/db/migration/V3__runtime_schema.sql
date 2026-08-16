-- V3 — RUNTIME schema (live operational state). SessionLayer Control Plane.
--
-- Design §12A "Core data model" (RUNTIME group) + §13. These entities are the
-- live operational state: registrations, presence, issued identities, sessions,
-- recordings, locks, JIT/break-glass state, pins/OTPs, audit. RUNTIME is the live
-- side of the config-vs-runtime boundary (FR-DATA-1); there is deliberately no
-- `origin` provenance column here.
--
-- Referential rules (docs/reference/data-model.md in the SessionLayer/Documentation repo):
--   * runtime->runtime: real FKs (ON DELETE SET NULL where history must outlive the
--     referenced row; CASCADE only for the 1:1 recording_ref).
--   * runtime->config: NEVER a hard FK — decision *snapshots* (plain uuid + copied
--     principal/capabilities/access_model/policy_epoch) so history survives config GC.
--   * audit_event: zero FKs (immortal; correlation by id value).
--
-- Table order below respects FK dependencies.

CREATE SCHEMA IF NOT EXISTS runtime;

-- Source restrictions are stored as text, not inet/cidr: r2dbc-postgresql 1.1.1 has no
-- codec that preserves a mask. The parse is deliberately lenient (::inet, not ::cidr)
-- because operators commonly write a restriction with host bits set (192.168.1.5/24),
-- which ::cidr rejects — pushing them to drop the restriction entirely. Network
-- containment is computed at query time.
CREATE OR REPLACE FUNCTION runtime.is_ip_or_cidr(value text)
    RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
BEGIN
    RETURN value::inet IS NOT NULL;
EXCEPTION
    WHEN others THEN
        RETURN false;
END;
$$;
COMMENT ON FUNCTION runtime.is_ip_or_cidr(text) IS 'Total IP/CIDR-literal validator (::inet, lenient): malformed input -> false (clean CHECK violation), not a cast error.';

CREATE TABLE runtime.node (
    id               uuid        PRIMARY KEY,
    name             text        NOT NULL UNIQUE,
    node_policy_name text,
    resolved_labels  jsonb       NOT NULL DEFAULT '{}'
                                 CHECK (jsonb_typeof(resolved_labels) = 'object'),
    connector_kind   text        NOT NULL CHECK (connector_kind IN ('agent', 'agentless')),
    status           text        NOT NULL DEFAULT 'pending'
                                 CHECK (status IN ('pending', 'active', 'quarantined', 'removed')),
    health           text        NOT NULL DEFAULT 'unknown'
                                 CHECK (health IN ('unknown', 'healthy', 'unhealthy', 'unreachable')),
    owning_gateway   text,                                       -- owning-gateway pointer (mirrors presence)
    address          text,
    version          bigint      NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT node_agentless_requires_address CHECK (connector_kind = 'agent' OR address IS NOT NULL)
);
COMMENT ON TABLE runtime.node IS 'Design §12A RUNTIME: live node registration; node_policy_name is a snapshot (no FK to config).';

CREATE TABLE runtime.presence (
    node_id        uuid        PRIMARY KEY REFERENCES runtime.node (id) ON DELETE CASCADE,
    owning_gateway text        NOT NULL,
    gateway_addr   text        NOT NULL,
    nonce          bigint      NOT NULL,
    nonce_id       uuid        NOT NULL,
    last_seen      timestamptz NOT NULL,
    version        bigint      NOT NULL DEFAULT 0,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.presence IS 'Design §10.2 / FR-HA-2: node -> owning_gateway,addr,monotonic nonce. Queried before routing.';

CREATE TABLE runtime.agent_identity (
    id                 uuid        PRIMARY KEY,
    node_id            uuid        NOT NULL REFERENCES runtime.node (id) ON DELETE CASCADE,
    mtls_identity_ref  text        NOT NULL
                                   CHECK (mtls_identity_ref NOT LIKE '%PRIVATE KEY%'),
    fingerprint        text,
    generation         bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),
    join_method        text        NOT NULL CHECK (join_method IN ('token', 'oidc', 'mtls')),
    status             text        NOT NULL DEFAULT 'active'
                                   CHECK (status IN ('active', 'locked', 'revoked')),
    issued_at          timestamptz,
    not_after          timestamptz,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_identity_validity_ordered CHECK (not_after IS NULL OR issued_at IS NULL OR not_after > issued_at)
);
COMMENT ON TABLE runtime.agent_identity IS 'Design §8: agent mTLS identity + generation counter. One active per node (partial unique index, V5).';

CREATE TABLE runtime.gateway_identity (
    id                uuid        PRIMARY KEY,
    name              text        NOT NULL UNIQUE,
    mtls_identity_ref text        NOT NULL CHECK (mtls_identity_ref NOT LIKE '%PRIVATE KEY%'),
    fingerprint       text,
    generation        bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),
    join_method       text        NOT NULL CHECK (join_method IN ('token', 'oidc', 'mtls')),
    status            text        NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active', 'locked', 'revoked')),
    issued_at         timestamptz,
    not_after         timestamptz,
    version           bigint      NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT gateway_identity_validity_ordered CHECK (not_after IS NULL OR issued_at IS NULL OR not_after > issued_at)
);
COMMENT ON TABLE runtime.gateway_identity IS 'FR-BOOT-3: Gateway is a first-class lockable principal; renewable mTLS identity + generation.';

CREATE TABLE runtime.join_token (
    id          uuid        PRIMARY KEY,
    token_hash  text        NOT NULL UNIQUE,
    scope       jsonb       NOT NULL CHECK (jsonb_typeof(scope) = 'object'),
    join_method text        NOT NULL CHECK (join_method IN ('token', 'oidc', 'mtls')),
    node_id     uuid        REFERENCES runtime.node (id) ON DELETE SET NULL,
    single_use  boolean     NOT NULL DEFAULT true,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_by  text,
    version     bigint      NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.join_token IS 'Design §8.1 / FR-JOIN-2: single-use join token. Stores token_hash only, never the raw token.';

CREATE TABLE runtime.jit_request (
    id                uuid        PRIMARY KEY,
    requester         text        NOT NULL,
    target_node_id    uuid        REFERENCES runtime.node (id) ON DELETE SET NULL,
    target_node_name  text,
    target_selector   jsonb       CHECK (target_selector IS NULL OR jsonb_typeof(target_selector) = 'object'),
    principal         text        NOT NULL,
    capabilities      text[]      NOT NULL DEFAULT ARRAY[]::text[]
                                  CHECK (capabilities <@ ARRAY['shell', 'exec', 'sftp', 'scp',
                                      'port_forward_local', 'port_forward_remote',
                                      'agent_forward', 'x11']::text[]),
    reason            text        NOT NULL,
    state             text        NOT NULL DEFAULT 'REQUESTED'
                                  CHECK (state IN ('REQUESTED', 'PENDING_APPROVAL', 'APPROVED',
                                      'DENIED', 'EXPIRED', 'ACTIVE', 'REVOKED')),
    jit_policy_id     uuid,
    jit_policy_name   text,
    approval_chain    jsonb       NOT NULL DEFAULT '[]'
                                  CHECK (jsonb_typeof(approval_chain) = 'array'
                                         AND jsonb_array_length(approval_chain) <= 3),
    -- Each element is {approver, level, decision, reason, at}, and an approver may not
    -- be the requester; neither can be expressed as a row CHECK over a jsonb array, so
    -- both are enforced by the application. The array is bounded so a runaway writer
    -- cannot grow the row without limit.
    approvals         jsonb       NOT NULL DEFAULT '[]'
                                  CHECK (jsonb_typeof(approvals) = 'array'
                                         AND jsonb_array_length(approvals) <= 16),
    approval_deadline timestamptz,
    grant_expires_at  timestamptz,
    requested_at      timestamptz NOT NULL,
    decided_at        timestamptz,
    version           bigint      NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.jit_request IS 'FR-ACC-2: JIT state machine + two clocks. jit_policy_id/approval_chain are snapshots.';

CREATE TABLE runtime.ssh_session (
    id              uuid        PRIMARY KEY,
    identity        text        NOT NULL,
    node_id         uuid        REFERENCES runtime.node (id) ON DELETE SET NULL,
    node_name       text,
    principal       text        NOT NULL,
    gateway_id      uuid        REFERENCES runtime.gateway_identity (id) ON DELETE SET NULL,
    gateway_name    text,
    access_model    text        NOT NULL CHECK (access_model IN ('standing', 'jit', 'breakglass')),
    capabilities    text[]      NOT NULL DEFAULT ARRAY[]::text[]
                                CHECK (capabilities <@ ARRAY['shell', 'exec', 'sftp', 'scp',
                                    'port_forward_local', 'port_forward_remote',
                                    'agent_forward', 'x11']::text[]),
    matched_rule_id uuid,                                        -- SNAPSHOT ref to config.dp_rule (NO FK)
    matched_rule_name text,
    jit_request_id  uuid        REFERENCES runtime.jit_request (id) ON DELETE SET NULL,
    breakglass_activation_id uuid,                               -- FK added below (breakglass_activation is defined later)
    policy_epoch    bigint,
    grant_expiry    timestamptz,
    started_at      timestamptz NOT NULL,
    ended_at        timestamptz,
    end_reason      text,                                        -- why/how it ended (lock|expiry|quarantine|client|...)
    version         bigint      NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.ssh_session IS 'Design §12A "session" (renamed ssh_session, §7.1). Holds the decision snapshot (§6): matched_rule_id/name, principal, capabilities, access_model, policy_epoch, grant_expiry.';

CREATE TABLE runtime.recording_ref (
    id                 uuid        PRIMARY KEY,
    session_id         uuid        NOT NULL UNIQUE
                                   REFERENCES runtime.ssh_session (id) ON DELETE RESTRICT,
                                   -- RESTRICT: a session prune must not cascade-erase recording provenance
    object_key         text        NOT NULL,
    encryption_key_ref text        NOT NULL
                                   CHECK (encryption_key_ref NOT LIKE '%PRIVATE KEY%'
                                          AND encryption_key_ref NOT LIKE '%BEGIN %'),
    hash_chain_head    text,
    worm_mode          text        CHECK (worm_mode IS NULL OR worm_mode IN ('compliance', 'governance')),
    size_bytes         bigint      CHECK (size_bytes IS NULL OR size_bytes >= 0),
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.recording_ref IS 'FR-DATA-2: 1:1 with ssh_session (UNIQUE session_id). encryption_key_ref is a reference only.';

CREATE TABLE runtime.access_lock (
    id              uuid        PRIMARY KEY,
    target_selector jsonb       NOT NULL CHECK (jsonb_typeof(target_selector) = 'object'),
    mode            text        NOT NULL CHECK (mode IN ('strict', 'best_effort')),
    ttl_seconds     integer     CHECK (ttl_seconds IS NULL OR ttl_seconds > 0),
    expires_at      timestamptz,
    reason          text        NOT NULL,
    created_by      text        NOT NULL,
    version         bigint      NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.access_lock IS 'Design §12A "lock" (renamed access_lock, §7.1). API-ONLY runtime resource (FR-DATA-1); the config-vs-runtime boundary keeps it out of config.';

CREATE TABLE runtime.breakglass_activation (
    id                   uuid        PRIMARY KEY,
    principal            text        NOT NULL,
    reason               text        NOT NULL,
    alert_ref            text,
    breakglass_policy_id   uuid,
    breakglass_policy_name text,
    review_status        text        NOT NULL DEFAULT 'pending'
                                     CHECK (review_status IN ('pending', 'reviewed')),
    reviewer             text,
    activated_at         timestamptz NOT NULL,
    reviewed_at          timestamptz,
    version              bigint      NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.breakglass_activation IS 'FR-ACC-6: break-glass activation with mandatory post-hoc review.';

ALTER TABLE runtime.ssh_session
    ADD CONSTRAINT ssh_session_breakglass_activation_fk
    FOREIGN KEY (breakglass_activation_id) REFERENCES runtime.breakglass_activation (id) ON DELETE SET NULL;

CREATE TABLE runtime.pin (
    id          uuid        PRIMARY KEY,
    fingerprint text        NOT NULL,
    identity    text        NOT NULL,
    source_cidr text        CHECK (source_cidr IS NULL OR runtime.is_ip_or_cidr(source_cidr)),
    principals  text[]      NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    version     bigint      NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (fingerprint, identity)
);
COMMENT ON TABLE runtime.pin IS 'Design §5.5: authN-shortcut pin {fp, identity, source-cidr, principals, expiry}. source_cidr validated by runtime.is_ip_or_cidr.';

CREATE TABLE runtime.otp (
    id                 uuid        PRIMARY KEY,
    otp_hash           text        NOT NULL UNIQUE,
    identity           text        NOT NULL,
    allowed_principals text[]      NOT NULL,
    source_cidr        text        CHECK (source_cidr IS NULL OR runtime.is_ip_or_cidr(source_cidr)),
    expires_at         timestamptz NOT NULL,
    used               boolean     NOT NULL DEFAULT false,
    used_at            timestamptz,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.otp IS 'Design §5.4 / FR-AUTH-9: single-use OTP. Stores otp_hash only, never the raw OTP.';

CREATE TABLE runtime.audit_event (
    id             uuid        PRIMARY KEY,
    -- seq: a dense, DB-assigned monotonic ordinal giving the hash chain a single
    -- well-defined predecessor even for intra-millisecond ties and concurrent (HA)
    -- writers, which UUIDv7 alone does not. GENERATED ALWAYS so the app can never set
    -- it (the ORM omits it from INSERT and Postgres assigns it); UNIQUE index in V5.
    seq            bigint      GENERATED ALWAYS AS IDENTITY,
    occurred_at    timestamptz NOT NULL,
    actor          text        NOT NULL,
    subject        text,
    action         text        NOT NULL,
    outcome        text        NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'error')),
    correlation_id uuid,
    session_id     uuid,
    node_id        uuid,
    node_labels    jsonb       CHECK (node_labels IS NULL OR jsonb_typeof(node_labels) = 'object'),
    source_ip      text        CHECK (source_ip IS NULL OR runtime.is_ip_or_cidr(source_ip)),
    access_model   text        CHECK (access_model IS NULL
                                      OR access_model IN ('standing', 'jit', 'breakglass')),
    capabilities   text[]      CHECK (capabilities IS NULL OR capabilities <@ ARRAY['shell', 'exec',
                                   'sftp', 'scp', 'port_forward_local', 'port_forward_remote',
                                   'agent_forward', 'x11']::text[]),
    detail         jsonb       CHECK (detail IS NULL OR jsonb_typeof(detail) = 'object'),
    prev_hash      text,
    record_hash    text,
    version        bigint      NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.audit_event IS 'Design §12.2 / FR-AUD-9: single correlated audit stream. Append-only (V4 trigger); zero FKs; seq = chain order; hash-chain cols are application-populated.';
