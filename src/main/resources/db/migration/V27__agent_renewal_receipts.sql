-- V27 — agent renewal replay receipts (idempotent renew retries). SessionLayer CP.
--
-- A lost/late RenewAgentIdentity response makes the Agent retry with the SAME
-- (now-stale) generation after the CP already committed the renewal. Without a
-- receipt, that retry is indistinguishable from a genuine clone racing the old
-- generation and gets auto-locked (permanent outage + false security alert). A real
-- clone cannot reproduce the CSR key (it holds its own keypair), so keying the
-- receipt on (agent, prior generation, CSR public key hash) lets a benign self-retry
-- replay the already-issued cert while clone detection stays intact for a different
-- key. RUNTIME (per-request operational state, mirrors runtime.idempotency_key from
-- V22): bounded by expires_at, no `origin`. cp_runtime auto-gets CRUD via the V11
-- default privileges.

CREATE TABLE runtime.agent_renewal_receipt (
    id                  uuid        PRIMARY KEY,
    agent_id            uuid        NOT NULL REFERENCES runtime.agent_identity (id) ON DELETE CASCADE,
    prior_generation    bigint      NOT NULL,
    csr_public_key_hash text        NOT NULL,
    new_generation      bigint      NOT NULL,
    certificate         bytea       NOT NULL,
    ca_certificate      bytea       NOT NULL,
    not_before          timestamptz NOT NULL,
    not_after           timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    UNIQUE (agent_id, prior_generation, csr_public_key_hash)
);
COMMENT ON TABLE runtime.agent_renewal_receipt IS 'Replay receipt for a completed RenewAgentIdentity call, keyed by (agent, prior generation, CSR public key hash); lets a lost-response retry replay the issued cert instead of tripping clone detection. Bounded by expires_at.';

CREATE INDEX agent_renewal_receipt_expires_idx ON runtime.agent_renewal_receipt (expires_at);
