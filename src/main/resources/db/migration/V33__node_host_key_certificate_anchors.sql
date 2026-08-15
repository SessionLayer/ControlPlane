-- V33 — make the host-CA certificate anchor storable.
-- SessionLayer Control Plane.
--
-- Registering a node with a hostCertificate could not succeed. The schema was
-- written for the pinned-key shape and applied to both: public_key and fingerprint
-- were NOT NULL, and key_type admitted only the six plain key types. A host-CA
-- anchor has no plain public key and no fingerprint of its own — its trust comes
-- from the CA signature over the certificate — and an OpenSSH certificate line's
-- first token is the certificate type, ssh-ed25519-cert-v01@openssh.com, not
-- ssh-ed25519. So the insert violated three constraints at once, and the anchor the
-- documentation calls PRIMARY was the one that could not be written.
--
-- The fix relaxes the columns where they are genuinely inapplicable rather than
-- manufacturing values to satisfy them. A synthetic fingerprint would be worse than
-- none: the API contract states that a host_ca anchor recorded from a certificate
-- line alone has no fingerprint to compare, and an operator comparing a computed
-- one against what the node reports would find it never matches.
--
-- Expand/contract safe: the previous release's binary only ever writes non-null
-- public_key/fingerprint and only ever plain key types, all of which stay valid.
-- Nothing is dropped and no existing row is rewritten.

ALTER TABLE runtime.node_host_key ALTER COLUMN public_key DROP NOT NULL;
ALTER TABLE runtime.node_host_key ALTER COLUMN fingerprint DROP NOT NULL;

-- Every accepted type plus its OpenSSH certificate form. Two additions beyond the
-- certificate forms: ssh-rsa and its certificate. The original six list
-- rsa-sha2-256/512, which are SIGNATURE-algorithm names rather than host-key type
-- tokens, so no real RSA host key was ever storable — and sshd generates one by
-- default, so an operator pinning /etc/ssh/ssh_host_rsa_key.pub as the admin guide
-- instructs hit the same unhandled insert failure as the certificate path. The two
-- rsa-sha2-* entries stay: rows may already carry them.
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

-- The relaxation is not a licence for a pinned key without one. A pinned_key row
-- IS its public key and the fingerprint an operator compares — the whole anchor is
-- those two values, so it keeps the guarantee the columns used to give globally.
ALTER TABLE runtime.node_host_key ADD CONSTRAINT node_host_key_pinned_requires_key_and_fingerprint
    CHECK (source <> 'pinned_key' OR (public_key IS NOT NULL AND fingerprint IS NOT NULL));

-- A host_ca row still has to anchor something: a certificate, or (as rows written
-- before this migration did) a plain key. All-null is not an anchor.
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
