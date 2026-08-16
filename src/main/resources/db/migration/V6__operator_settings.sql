CREATE TABLE config.operator_settings (
    id                          uuid        PRIMARY KEY,
    singleton                   boolean     NOT NULL DEFAULT true UNIQUE
                                            CHECK (singleton = true),

    -- A REFERENCE only (an env var name or KMS handle), never the KEK bytes: the
    -- key-encryption key itself is sourced from the environment at runtime.
    kek_reference               text        CHECK (kek_reference IS NULL
                                            OR (kek_reference NOT LIKE '%PRIVATE KEY%'
                                                AND kek_reference NOT LIKE '%BEGIN %')),

    default_ca_backend          text        NOT NULL DEFAULT 'local'
                                            CHECK (default_ca_backend IN ('local', 'aws_kms', 'azure_keyvault', 'vault')),

    audit_retention_days        integer     NOT NULL DEFAULT 365 CHECK (audit_retention_days > 0),

    -- Governance recordings are deletable by a privileged audited role (the GDPR escape
    -- hatch); compliance recordings are truly un-deletable.
    default_worm_mode           text        NOT NULL DEFAULT 'governance'
                                            CHECK (default_worm_mode IN ('compliance', 'governance')),

    otp_ttl_seconds             integer     NOT NULL DEFAULT 120
                                            CHECK (otp_ttl_seconds BETWEEN 60 AND 300),

    default_max_session_seconds integer     CHECK (default_max_session_seconds IS NULL OR default_max_session_seconds > 0),
    default_idle_timeout_seconds integer    CHECK (default_idle_timeout_seconds IS NULL OR default_idle_timeout_seconds > 0),
    default_max_concurrent_sessions integer CHECK (default_max_concurrent_sessions IS NULL OR default_max_concurrent_sessions > 0),

    bootstrap_admin_subject     text,
    bootstrap_credential_hash   text        CHECK (bootstrap_credential_hash IS NULL
                                            OR bootstrap_credential_hash NOT LIKE '%PRIVATE KEY%'),
    bootstrap_completed         boolean     NOT NULL DEFAULT false,
    bootstrap_completed_at      timestamptz,

    origin                      text        NOT NULL DEFAULT 'default'
                                            CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version                     bigint      NOT NULL DEFAULT 0,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.operator_settings IS 'Singleton cluster settings (KEK ref, default CA backend, retention/WORM/OTP/session-limit defaults, FR-BOOT-2 bootstrap self-disable). Cold start reads/writes this. bootstrap_* fields are runtime-managed (operational state, not config).';
