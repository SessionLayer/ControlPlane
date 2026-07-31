-- V30 — external (key-service) CA key material. SessionLayer Control Plane.
--
-- A CA whose private key lives in an external key service (Azure Key Vault
-- first; the shape is backend-agnostic) has no wrapped private key to store at
-- all. Until now ca_key_material assumed 'local' unconditionally:
-- wrapped_key/iv/kek_reference were each individually NOT NULL / CHECKed, with
-- nothing tying the three together as one shape.
--
-- Adds key_location ('local_kek' | 'external') and replaces the three V12
-- column-level CHECKs with one table-level CHECK keyed on it:
--   - 'local_kek' requires exactly the V12 shape, now enforced JOINTLY (strictly
--     stronger than today, where a row could satisfy each CHECK individually
--     while e.g. carrying only two of the three columns as non-null nonsense).
--     The kek_reference "never a private key" guard moves into the same
--     constraint rather than being dropped, so the invariant survives the
--     column-check removal.
--   - 'external' requires wrapped_key/iv/kek_reference all NULL: there is no
--     private key here and the schema says so.
-- public_key stays NOT NULL for both — an external CA's public key is resolved
-- from the key service at adoption and persisted, which is what keeps
-- CaPublicKeyService, CaRotationService.trustedCaKeys and
-- LocalCaFactory.publicAuthorizedKey working unchanged, and keeps "no private
-- material is read" provable from the same SQL projection regardless of
-- key_location.

ALTER TABLE runtime.ca_key_material
    ADD COLUMN key_location text NOT NULL DEFAULT 'local_kek'
        CHECK (key_location IN ('local_kek', 'external'));
COMMENT ON COLUMN runtime.ca_key_material.key_location IS
    'local_kek: wrapped_key/iv/kek_reference hold the KEK-wrapped private key (FR-CA-8). external: the private key lives in a key service (e.g. Azure Key Vault); those three columns are NULL by construction.';

ALTER TABLE runtime.ca_key_material DROP CONSTRAINT IF EXISTS ca_key_material_wrapped_key_check;
ALTER TABLE runtime.ca_key_material DROP CONSTRAINT IF EXISTS ca_key_material_iv_check;
ALTER TABLE runtime.ca_key_material DROP CONSTRAINT IF EXISTS ca_key_material_kek_reference_check;

ALTER TABLE runtime.ca_key_material ALTER COLUMN wrapped_key DROP NOT NULL;
ALTER TABLE runtime.ca_key_material ALTER COLUMN iv DROP NOT NULL;
ALTER TABLE runtime.ca_key_material ALTER COLUMN kek_reference DROP NOT NULL;

ALTER TABLE runtime.ca_key_material
    ADD CONSTRAINT ca_key_material_key_location_shape_check CHECK (
        (key_location = 'local_kek'
            AND wrapped_key IS NOT NULL
            AND iv IS NOT NULL
            AND kek_reference IS NOT NULL
            AND kek_reference NOT LIKE '%PRIVATE KEY%'
            AND octet_length(iv) = 12
            AND octet_length(wrapped_key) > 0
            -- ciphertext-only guard, carried over from V12: reject a
            -- '-----BEGIN' PEM marker written into the blob.
            AND position('\x2d2d2d2d2d424547494e'::bytea in wrapped_key) = 0)
        OR
        (key_location = 'external'
            AND wrapped_key IS NULL
            AND iv IS NULL
            AND kek_reference IS NULL)
    );
COMMENT ON CONSTRAINT ca_key_material_key_location_shape_check ON runtime.ca_key_material IS
    'Ties wrapped_key/iv/kek_reference to key_location as one shape instead of three independent CHECKs (V12 never tied them together).';

-- Write-once provenance (V12/V14): key_location is decided at insert (which row
-- shape a CA is) and, like the columns it gates, may never change afterward.
CREATE OR REPLACE FUNCTION runtime.enforce_ca_key_material_write_once()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.ca_config_id IS DISTINCT FROM OLD.ca_config_id
        OR NEW.wrapped_key IS DISTINCT FROM OLD.wrapped_key
        OR NEW.iv IS DISTINCT FROM OLD.iv
        OR NEW.public_key IS DISTINCT FROM OLD.public_key
        OR NEW.ca_certificate IS DISTINCT FROM OLD.ca_certificate
        OR NEW.key_location IS DISTINCT FROM OLD.key_location THEN
        RAISE EXCEPTION 'ca_key_material (ca_config_id/wrapped_key/iv/public_key/ca_certificate/key_location) is write-once'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- No grant change: cp_runtime's INSERT/SELECT-only grant (V12) is table-level,
-- so it already covers this new column.
