CREATE TABLE runtime.ca_key_material (
    id            uuid        PRIMARY KEY,
    ca_config_id  uuid        NOT NULL UNIQUE,             -- snapshot ref to config.ca_config.id (NO FK)
    ca_config_name text       NOT NULL,
    wrap_algorithm text       NOT NULL DEFAULT 'AES-256-GCM'
                              CHECK (wrap_algorithm IN ('AES-256-GCM')),
    kek_reference text        NOT NULL
                              CHECK (kek_reference NOT LIKE '%PRIVATE KEY%'),
    wrapped_key   bytea       NOT NULL
                              -- ciphertext-only guard: reject a '-----BEGIN' PEM marker written into the blob
                              CHECK (octet_length(wrapped_key) > 0
                                     AND position('\x2d2d2d2d2d424547494e'::bytea in wrapped_key) = 0),
    iv            bytea       NOT NULL CHECK (octet_length(iv) = 12),
    public_key    bytea       NOT NULL,                    -- CA public key (X.509 SubjectPublicKeyInfo; public material)
    key_type      text        NOT NULL DEFAULT 'ecdsa-sha2-nistp256',
    version       bigint      NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.ca_key_material IS 'FR-CA-8: KEK-wrapped local-CA private key (ciphertext only) + public blob. KEK is env-sourced, never in the DB. Referenced by config.ca_config.key_reference = local:<id>.';

CREATE INDEX idx_ca_key_material_config ON runtime.ca_key_material (ca_config_id);

-- Crown-jewel hardening: the restricted runtime role gets only
-- INSERT/SELECT (V11's ALTER DEFAULT PRIVILEGES gave it CRUD; revoke the destructive
-- verbs). Rotation writes a NEW row, so UPDATE/DELETE is never legitimately needed by
-- the app — a compromised app credential cannot delete/corrupt a wrapped CA key.
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON runtime.ca_key_material FROM cp_runtime';
        EXECUTE 'GRANT INSERT, SELECT ON runtime.ca_key_material TO cp_runtime';
    END IF;
END
$grant$;

CREATE OR REPLACE FUNCTION runtime.enforce_ca_key_material_write_once()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.ca_config_id IS DISTINCT FROM OLD.ca_config_id
        OR NEW.wrapped_key IS DISTINCT FROM OLD.wrapped_key
        OR NEW.iv IS DISTINCT FROM OLD.iv
        OR NEW.public_key IS DISTINCT FROM OLD.public_key THEN
        RAISE EXCEPTION 'ca_key_material (ca_config_id/wrapped_key/iv/public_key) is write-once'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER ca_key_material_write_once
    BEFORE UPDATE ON runtime.ca_key_material
    FOR EACH ROW EXECUTE FUNCTION runtime.enforce_ca_key_material_write_once();
