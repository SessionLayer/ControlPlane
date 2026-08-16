-- Expand/contract safe: the previous release's binary only ever writes non-null
-- public_key/fingerprint and only ever plain key types, all of which stay valid.
-- Nothing is dropped and no existing row is rewritten.

ALTER TABLE runtime.node_host_key ALTER COLUMN public_key DROP NOT NULL;
ALTER TABLE runtime.node_host_key ALTER COLUMN fingerprint DROP NOT NULL;

-- The two rsa-sha2-* entries are SIGNATURE-algorithm names rather than host-key type
-- tokens, so no real RSA host key was ever storable under them; they stay only
-- because rows may already carry them.
--
-- Dropped by its exact auto-generated name rather than IF EXISTS: if the name were
-- wrong, IF EXISTS would leave the old constraint in force and this migration would
-- be a lie.
ALTER TABLE runtime.node_host_key DROP CONSTRAINT node_host_key_key_type_check;
ALTER TABLE runtime.node_host_key ADD CONSTRAINT node_host_key_key_type_check
    CHECK (key_type IN ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                        'ecdsa-sha2-nistp521', 'ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512',
                        'ssh-ed25519-cert-v01@openssh.com', 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
                        'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp521-cert-v01@openssh.com',
                        'ssh-rsa-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com',
                        'rsa-sha2-512-cert-v01@openssh.com'));

ALTER TABLE runtime.node_host_key ADD CONSTRAINT node_host_key_pinned_requires_key_and_fingerprint
    CHECK (source <> 'pinned_key' OR (public_key IS NOT NULL AND fingerprint IS NOT NULL));

ALTER TABLE runtime.node_host_key ADD CONSTRAINT node_host_key_host_ca_requires_material
    CHECK (source <> 'host_ca' OR host_cert_ref IS NOT NULL OR public_key IS NOT NULL);

-- UNIQUE (node_id, fingerprint) stops constraining host_ca rows the moment
-- fingerprints may be NULL, because a unique index treats NULLs as distinct. This
-- restores the "record an anchor once" guarantee for the certificate path. Hashed
-- because a full RSA certificate line can exceed the btree index-entry limit.
CREATE UNIQUE INDEX uq_node_host_key_host_ca_cert
    ON runtime.node_host_key (node_id, md5(host_cert_ref))
    WHERE source = 'host_ca' AND host_cert_ref IS NOT NULL;

COMMENT ON COLUMN runtime.node_host_key.public_key IS
    'The anchor''s OpenSSH public-key line. Required for a pinned_key row, which IS that key; NULL for a host_ca row recorded from a certificate line, whose material is host_cert_ref. Public material only.';
COMMENT ON COLUMN runtime.node_host_key.fingerprint IS
    'SHA256: fingerprint of public_key — what an operator compares against the key the node reports. Required for a pinned_key row; NULL for a host_ca row recorded from a certificate line alone, whose trust comes from the CA signature rather than a fingerprint comparison. Never a computed stand-in.';
COMMENT ON COLUMN runtime.node_host_key.key_type IS
    'The anchor''s OpenSSH type token — the first field of the stored line. A host_ca row carries a certificate type (…-cert-v01@openssh.com); a pinned_key row carries a plain key type.';
