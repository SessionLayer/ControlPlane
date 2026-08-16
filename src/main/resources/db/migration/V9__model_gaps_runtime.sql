CREATE TABLE runtime.service_account_credential (
    id                   uuid        PRIMARY KEY,
    service_account_id   uuid        NOT NULL,
    service_account_name text        NOT NULL,
    credential_type      text        NOT NULL
                                     CHECK (credential_type IN ('private_key_jwt', 'mtls', 'client_secret')),
    -- Either the hash of a client_secret, or a public-key/cert fingerprint reference for
    -- the private_key_jwt and mtls credential types.
    secret_hash          text        NOT NULL
                                     CHECK (secret_hash NOT LIKE '%PRIVATE KEY%' AND secret_hash NOT LIKE '%BEGIN %'),
    fingerprint          text,
    status               text        NOT NULL DEFAULT 'active'
                                     CHECK (status IN ('active', 'revoked')),
    issued_at            timestamptz NOT NULL,
    not_after            timestamptz,
    revoked_at           timestamptz,
    revoked_reason       text,
    revoked_by           text,
    version              bigint      NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sac_validity_ordered CHECK (not_after IS NULL OR not_after > issued_at)
);
COMMENT ON TABLE runtime.service_account_credential IS 'FR-AUTH-12: issued machine-consumer credential (rotatable/revocable). Hash/reference only; service_account_id is a snapshot (no FK to config).';

CREATE INDEX idx_sac_service_account ON runtime.service_account_credential (service_account_id);
CREATE UNIQUE INDEX uq_sac_active_secret_hash
    ON runtime.service_account_credential (secret_hash) WHERE status = 'active';

CREATE TABLE runtime.device_flow (
    id                 uuid        PRIMARY KEY,
    device_code_hash   text        NOT NULL UNIQUE,
    user_code_hash     text        NOT NULL,
    identity           text,
    status             text        NOT NULL DEFAULT 'pending'
                                   CHECK (status IN ('pending', 'authorized', 'denied', 'expired')),
    connection_binding text,
    source_ip          text        CHECK (source_ip IS NULL OR runtime.is_ip_or_cidr(source_ip)),
    interval_seconds   integer     NOT NULL DEFAULT 5 CHECK (interval_seconds > 0),
    expires_at         timestamptz NOT NULL,
    last_polled_at     timestamptz,
    authorized_at      timestamptz,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.device_flow IS 'FR-AUTH-3: RFC 8628 device-flow state + 1:1 device_code<->connection anti-phishing binding (§15). Stores hashes only.';

CREATE INDEX idx_device_flow_expires ON runtime.device_flow (expires_at) WHERE status = 'pending';

CREATE TABLE runtime.node_host_key (
    id            uuid        PRIMARY KEY,
    node_id       uuid        NOT NULL REFERENCES runtime.node (id) ON DELETE CASCADE,
    key_type      text        NOT NULL
                              CHECK (key_type IN ('ssh-ed25519', 'ecdsa-sha2-nistp256',
                                  'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512')),
    public_key    text        NOT NULL CHECK (public_key NOT LIKE '%PRIVATE KEY%'),
    fingerprint   text        NOT NULL,
    host_cert_ref text        CHECK (host_cert_ref IS NULL OR host_cert_ref NOT LIKE '%PRIVATE KEY%'),
    source        text        NOT NULL DEFAULT 'pinned_key'
                              CHECK (source IN ('host_ca', 'pinned_key')),
    verified_at   timestamptz,
    version       bigint      NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (node_id, fingerprint)
);
COMMENT ON TABLE runtime.node_host_key IS 'FR-CONN-5: enrollment-anchored node host identity (host-CA cert primary, pinned key fallback) so inner-leg host verification is never TOFU. Public material only.';

CREATE INDEX idx_node_host_key_node ON runtime.node_host_key (node_id);

CREATE TABLE runtime.session_lease (
    id           uuid        PRIMARY KEY,
    identity     text        NOT NULL,
    session_id   uuid        REFERENCES runtime.ssh_session (id) ON DELETE SET NULL,
    gateway_name text,
    acquired_at  timestamptz NOT NULL,
    expires_at   timestamptz,
    released_at  timestamptz,
    version      bigint      NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.session_lease IS 'FR-SESS-3: durable per-identity concurrency lease (count unreleased leases = live sessions). Enforcement semaphore lives in the application layer.';

CREATE INDEX idx_session_lease_live ON runtime.session_lease (identity) WHERE released_at IS NULL;
CREATE INDEX idx_session_lease_session ON runtime.session_lease (session_id);
