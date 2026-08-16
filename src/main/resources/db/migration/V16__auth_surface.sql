-- New owner-created tables auto-inherit cp_runtime CRUD via V11's ALTER DEFAULT
-- PRIVILEGES.

CREATE TABLE runtime.oidc_login (
    id                 uuid        PRIMARY KEY,
    -- SHA-256 of the opaque, high-entropy `state` (raw never stored). Lookup key at
    -- the callback + single-use guard (UNIQUE). The PKCE verifier and the nonce are
    -- NOT stored: they are derived from the raw `state` under a server HMAC key.
    state_hash         text        NOT NULL UNIQUE
                                   CHECK (state_hash NOT LIKE '%PRIVATE KEY%'),
    purpose            text        NOT NULL DEFAULT 'web_login'
                                   CHECK (purpose IN ('web_login', 'device')),
    device_flow_id     uuid        REFERENCES runtime.device_flow (id) ON DELETE CASCADE,
    source_ip          text        CHECK (source_ip IS NULL OR runtime.is_ip_or_cidr(source_ip)),
    status             text        NOT NULL DEFAULT 'pending'
                                   CHECK (status IN ('pending', 'completed', 'failed', 'expired')),
    resolved_identity  text,
    expires_at         timestamptz NOT NULL,
    consumed_at        timestamptz,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.oidc_login IS 'FR-AUTH-6: auth-code+PKCE relying-party state. state hash only; verifier/nonce derived (never stored). Single-use. Links a device_flow when purpose=device.';

CREATE INDEX idx_oidc_login_expires ON runtime.oidc_login (expires_at) WHERE status = 'pending';
CREATE INDEX idx_oidc_login_device_flow ON runtime.oidc_login (device_flow_id);

-- Source IP is a deny-only reducer: a mismatch is flagged + audited, never used as
-- positive identity evidence.
ALTER TABLE runtime.device_flow
    ADD COLUMN approver_source_ip   text
        CHECK (approver_source_ip IS NULL OR runtime.is_ip_or_cidr(approver_source_ip)),
    ADD COLUMN approver_context     jsonb
        CHECK (approver_context IS NULL OR jsonb_typeof(approver_context) = 'object'),
    ADD COLUMN source_context_match boolean;
COMMENT ON COLUMN runtime.device_flow.approver_source_ip IS '§5.2 anti-phishing: the approving browser IP captured at the CP verification page.';
COMMENT ON COLUMN runtime.device_flow.source_context_match IS '§5.2: result of correlating the approving browser context with the SSH source IP (deny-only reducer, FR-AUTH-15).';

-- Keyed by an opaque bucket (e.g. "otp:verify:<source-ip>"). Reset is implicit: a
-- request in a newer window overwrites window_start and resets count (an atomic
-- upsert).
CREATE TABLE runtime.auth_rate_limit (
    bucket       text        PRIMARY KEY,
    window_start timestamptz NOT NULL,
    count        integer     NOT NULL DEFAULT 0 CHECK (count >= 0),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.auth_rate_limit IS 'FR-AUTH-9: durable fixed-window rate-limit counters for OTP-verify + token endpoints (per-source-IP / per-identity bucket).';

CREATE TABLE runtime.consumed_assertion (
    jti_hash   text        PRIMARY KEY
                           CHECK (jti_hash NOT LIKE '%PRIVATE KEY%'),
    subject    text        NOT NULL,
    not_after  timestamptz NOT NULL,                             -- the assertion's own exp
    created_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.consumed_assertion IS 'FR-AUTH-12 / RFC 7523: single-use guard for private_key_jwt client-assertion jti (hash only). Blocks assertion replay within its lifetime.';

CREATE INDEX idx_consumed_assertion_not_after ON runtime.consumed_assertion (not_after);
