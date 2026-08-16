ALTER TABLE config.ca_config DROP CONSTRAINT ca_config_ca_kind_check;
ALTER TABLE config.ca_config
    ADD CONSTRAINT ca_config_ca_kind_check CHECK (ca_kind IN ('user', 'session', 'host', 'mtls'));
COMMENT ON COLUMN config.ca_config.ca_kind IS 'user|session|host (SSH CAs) or mtls (the internal CP<->Gateway X.509 CA).';

ALTER TABLE runtime.ca_key_material ADD COLUMN ca_certificate bytea;
COMMENT ON COLUMN runtime.ca_key_material.ca_certificate IS 'X.509 CA certificate (DER) for X.509 CA rows (mtls); NULL for SSH CAs. Public material.';

CREATE OR REPLACE FUNCTION runtime.enforce_ca_key_material_write_once()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.ca_config_id IS DISTINCT FROM OLD.ca_config_id
        OR NEW.wrapped_key IS DISTINCT FROM OLD.wrapped_key
        OR NEW.iv IS DISTINCT FROM OLD.iv
        OR NEW.public_key IS DISTINCT FROM OLD.public_key
        OR NEW.ca_certificate IS DISTINCT FROM OLD.ca_certificate THEN
        RAISE EXCEPTION 'ca_key_material (ca_config_id/wrapped_key/iv/public_key/ca_certificate) is write-once'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE runtime.gateway_enrollment_token (
    id           uuid        PRIMARY KEY,
    token_hash   text        NOT NULL UNIQUE,
    gateway_name text        NOT NULL,
    single_use   boolean     NOT NULL DEFAULT true,
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    created_by   text,
    version      bigint      NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.gateway_enrollment_token IS 'FR-JOIN-3 / Design §4.B: single-use, short-TTL Gateway enrollment token (hash only). Shares its JoinMethod shape with Agent enrollment.';
CREATE INDEX idx_gateway_enrollment_token_gateway ON runtime.gateway_enrollment_token (gateway_name);

CREATE TABLE runtime.session_signing_token (
    id             uuid        PRIMARY KEY,
    token_hash     text        NOT NULL UNIQUE,
    gateway_id     uuid        NOT NULL,               -- snapshot of the owning gateway_identity.id (no FK: runtime->runtime snapshot)
    session_id     uuid        NOT NULL,
    node_id        uuid,
    principal      text        NOT NULL,
    capabilities   text[]      NOT NULL DEFAULT ARRAY['shell', 'exec']::text[]
                               CHECK (capabilities <@ ARRAY['shell', 'exec', 'sftp', 'scp',
                                   'port_forward_local', 'port_forward_remote',
                                   'agent_forward', 'x11']::text[]),
    source_address text        CHECK (source_address IS NULL OR runtime.is_ip_or_cidr(source_address)),
    expires_at     timestamptz NOT NULL,
    used           boolean     NOT NULL DEFAULT false,
    used_at        timestamptz,
    version        bigint      NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.session_signing_token IS 'Design §15 / FR-CA-3: single-use session-signing token bound to {gateway,session,node,principal,exp}. Hash only; atomic single-use.';
CREATE INDEX idx_session_signing_token_gateway ON runtime.session_signing_token (gateway_id);

DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.gateway_enrollment_token TO cp_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.session_signing_token TO cp_runtime';
    END IF;
END
$grant$;
