-- COMMENT ON is not inert file text: Flyway executes it, so these strings live in
-- pg_description on every running cluster and are what an operator reads from
-- \d+ runtime.recording_ref or obj_description(). They are shipped documentation.
--
-- Why a new migration rather than an edit: Flyway checksums the raw migration file,
-- so editing an applied one makes validate-on-migrate fail at startup for every
-- cluster that already ran it, and Testcontainers (always an empty database) cannot
-- see that. V2 states the rule this file follows: "Forward-only: never edit this
-- file after merge; change = a new versioned migration."
--
-- Catalog comments that were already clean are deliberately absent — a no-op
-- restatement is noise.
--
-- Grouped by the migration that last set each comment (only the last one for a
-- given object is live in the catalog).

COMMENT ON TABLE config.node_policy IS
    'CONFIG: NodePolicy — desired node labels + connector + host trust refs.';
COMMENT ON TABLE config.dp_rule IS
    'Data-plane RBAC grant (typed policy-as-data). Evaluated by the application.';
COMMENT ON TABLE config.platform_role IS
    'Platform RBAC role = granular permission set.';
COMMENT ON TABLE config.role_binding IS
    'Binds a subject to a platform_role; scope for recording:replay/export.';
COMMENT ON TABLE config.ca_config IS
    'Per-CA (user|session|host) backend + key reference; multiple rows per kind support rotation overlap (one active). Default ECDSA P-256. Never stores private key material.';
COMMENT ON TABLE config.capability_def IS
    'CONFIG: requestable-capability catalogue.';
COMMENT ON TABLE config.jit_policy IS
    'JIT-requestable targets + 0-3 level approval chain (email/OIDC-group).';
COMMENT ON TABLE config.breakglass_policy IS
    'Break-glass — recording-strict, alert, review, IdP-independent auth path.';
COMMENT ON TABLE config.service_account IS
    'Machine-consumer definition. Issued credentials live in RUNTIME.';

COMMENT ON TABLE runtime.node IS
    'RUNTIME: live node registration; node_policy_name is a snapshot (no FK to config).';
COMMENT ON TABLE runtime.presence IS
    'Node -> owning_gateway,addr,monotonic nonce. Queried before routing.';
COMMENT ON TABLE runtime.agent_identity IS
    'Agent mTLS identity + generation counter. One active per node (partial unique index, V5).';
COMMENT ON TABLE runtime.gateway_identity IS
    'Gateway is a first-class lockable principal; renewable mTLS identity + generation.';
COMMENT ON TABLE runtime.join_token IS
    'Single-use join token. Stores token_hash only, never the raw token.';
COMMENT ON TABLE runtime.jit_request IS
    'JIT state machine + two clocks. jit_policy_id/approval_chain are snapshots.';
COMMENT ON TABLE runtime.ssh_session IS
    'The SSH session entity, named ssh_session because "session" is a reserved word. Holds the decision snapshot: matched_rule_id/name, principal, capabilities, access_model, policy_epoch, grant_expiry.';
COMMENT ON TABLE runtime.recording_ref IS
    '1:1 with ssh_session (UNIQUE session_id). encryption_key_ref is a reference only.';
COMMENT ON TABLE runtime.access_lock IS
    'The access-lock entity, named access_lock because "lock" is a reserved word. API-ONLY runtime resource; the config-vs-runtime boundary keeps it out of config.';
COMMENT ON TABLE runtime.breakglass_activation IS
    'Break-glass activation with mandatory post-hoc review.';
COMMENT ON TABLE runtime.pin IS
    'AuthN-shortcut pin {fp, identity, source-cidr, principals, expiry}. source_cidr validated by runtime.is_ip_or_cidr.';
COMMENT ON TABLE runtime.otp IS
    'Single-use OTP. Stores otp_hash only, never the raw OTP.';

COMMENT ON FUNCTION runtime.audit_event_immutable() IS
    'Append-only guard for runtime.audit_event.';
COMMENT ON FUNCTION runtime.enforce_generation_monotonic() IS
    'Rejects a decreasing generation counter.';
COMMENT ON FUNCTION runtime.enforce_presence_nonce_monotonic() IS
    'Rejects a decreasing presence ownership nonce.';
COMMENT ON FUNCTION runtime.enforce_recording_ref_write_once() IS
    'Makes recording provenance columns write-once.';

COMMENT ON TABLE config.operator_settings IS
    'Singleton cluster settings (KEK ref, default CA backend, retention/WORM/OTP/session-limit defaults, bootstrap self-disable). Cold start reads/writes this. bootstrap_* fields are runtime-managed (operational state, not config).';

COMMENT ON TABLE runtime.audit_event IS
    'Single correlated audit stream. PARTITION BY RANGE(occurred_at) for retention (drop old partitions, no DELETE). Append-only trigger + seq chain order re-applied. Composite PK (id, occurred_at); id alone is globally unique (UUIDv7). Hash-chain cols are application-populated.';
COMMENT ON FUNCTION runtime.audit_prune_before(timestamptz) IS
    'Retention: DETACH+DROP audit_event monthly partitions entirely older than cutoff. Returns dropped partition names.';

COMMENT ON COLUMN runtime.recording_ref.retention_until IS
    'Earliest time this recording may be pruned (governance mode only; compliance is never prunable; legal_hold overrides).';
COMMENT ON COLUMN runtime.recording_ref.legal_hold IS
    'When true the recording is exempt from retention pruning regardless of retention_until.';
COMMENT ON COLUMN runtime.recording_ref.status IS
    'Recording lifecycle — recording -> finalized|truncated|failed.';
COMMENT ON COLUMN runtime.recording_ref.content_digest IS
    'Integrity digest (sha256:<hex>); write-once once set (V8 trigger).';

COMMENT ON TABLE runtime.service_account_credential IS
    'Issued machine-consumer credential (rotatable/revocable). Hash/reference only; service_account_id is a snapshot (no FK to config).';
COMMENT ON TABLE runtime.device_flow IS
    'RFC 8628 device-flow state + 1:1 device_code<->connection anti-phishing binding. Stores hashes only.';
COMMENT ON TABLE runtime.node_host_key IS
    'Enrollment-anchored node host identity (host-CA cert primary, pinned key fallback) so inner-leg host verification is never TOFU. Public material only.';
COMMENT ON TABLE runtime.session_lease IS
    'Durable per-identity concurrency lease (count unreleased leases = live sessions). Enforcement semaphore lives in the application layer.';

COMMENT ON TABLE config.session_limit_policy IS
    'Per-identity session-limit overrides (max concurrent/duration/idle). Cluster defaults live in operator_settings.';

COMMENT ON TABLE runtime.ca_key_material IS
    'KEK-wrapped local-CA private key (ciphertext only) + public blob. KEK is env-sourced, never in the DB. Referenced by config.ca_config.key_reference = local:<id>.';

COMMENT ON TABLE runtime.gateway_enrollment_token IS
    'Single-use, short-TTL Gateway enrollment token (hash only). Shares its JoinMethod shape with Agent enrollment.';
COMMENT ON TABLE runtime.session_signing_token IS
    'Single-use session-signing token bound to {gateway,session,node,principal,exp}. Hash only; atomic single-use.';

COMMENT ON COLUMN runtime.gateway_identity.prev_fingerprint IS
    'SHA-256 fingerprint of the previous-generation mTLS cert; pinned alongside fingerprint at the sign/renew tiers to survive renew-ahead overlap. Public material.';

COMMENT ON TABLE runtime.oidc_login IS
    'Auth-code+PKCE relying-party state. state hash only; verifier/nonce derived (never stored). Single-use. Links a device_flow when purpose=device.';
COMMENT ON COLUMN runtime.device_flow.approver_source_ip IS
    'Anti-phishing: the approving browser IP captured at the CP verification page.';
COMMENT ON COLUMN runtime.device_flow.source_context_match IS
    'Result of correlating the approving browser context with the SSH source IP (deny-only reducer).';
COMMENT ON TABLE runtime.auth_rate_limit IS
    'Durable fixed-window rate-limit counters for OTP-verify + token endpoints (per-source-IP / per-identity bucket).';
COMMENT ON TABLE runtime.consumed_assertion IS
    'RFC 7523: single-use guard for private_key_jwt client-assertion jti (hash only). Blocks assertion replay within its lifetime.';

COMMENT ON COLUMN config.operator_settings.recording_customer_public_key IS
    'Customer PUBLIC key (DER SubjectPublicKeyInfo) the Gateway seals the per-recording data key to. NULL => recording un-provisioned => BeginRecording fails closed. Public material only (the CP never holds the private half).';
COMMENT ON COLUMN config.operator_settings.recording_retention_days IS
    'Recording retention window (object-lock retain-until + recording_ref.retention_until).';
COMMENT ON TABLE runtime.recording_token IS
    'Single-use BeginRecording token bound to {gateway,session,node,principal,exp}. Hash only; atomic single-use. Minted at Authorize ALLOW alongside session_signing_token.';

COMMENT ON COLUMN runtime.agent_identity.prev_fingerprint IS
    'SHA-256 fingerprint of the previous-generation mTLS cert; pinned alongside fingerprint at renew to survive renew-ahead overlap. Public material.';

COMMENT ON TABLE runtime.breakglass_credential IS
    'Registered break-glass FIDO2 sk-ecdsa PUBLIC key (primary IdP-independent path). Public material only; revocable; scoped to allowed_principals + optional node_selector.';
COMMENT ON TABLE runtime.breakglass_offline_code IS
    'Pre-issued single-use break-glass code (IdP-independent fallback). Stores code_hash only; atomic single-use; source-bound; ≥128-bit entropy.';
COMMENT ON TABLE runtime.breakglass_token IS
    'Single-use break-glass Authorize authority, minted at ResolveBreakglass*, bound to {gateway,identity,node,source,exp}. Hash only; atomic single-use.';
COMMENT ON COLUMN runtime.breakglass_activation.identity IS
    'The break-glass operator identity that authenticated (IdP-independent).';
COMMENT ON COLUMN runtime.breakglass_activation.credential_ref IS
    'The resolving credential reference (sk-ecdsa fingerprint or offline-code id); legibility for post-hoc review.';
COMMENT ON COLUMN runtime.jit_request.policy_max_ttl_seconds IS
    'Snapshot of jit_policy.max_ttl_seconds at submit; the grant clock = min(this, cluster ceiling). Prevents a mid-flight policy edit/delete from widening the grant.';

COMMENT ON TABLE runtime.idempotency_key IS
    'Idempotency-Key replay store; first completed response per (principal, method, path, key). RUNTIME, bounded by expires_at.';

COMMENT ON FUNCTION runtime.recording_prunable(timestamptz) IS
    'Recordings eligible for retention pruning (governance + past retention_until + no legal hold + not already pruned). Compliance/legal-held never returned.';
COMMENT ON COLUMN runtime.recording_ref.pruned_at IS
    'When the encrypted object was deleted (retention prune or governance delete). The metadata row is retained (crown-jewels provenance).';
COMMENT ON COLUMN runtime.recording_ref.delete_mode IS
    'How the object was deleted — retention (automated, past retention_until) or governance (privileged, audited erasure).';
COMMENT ON COLUMN runtime.recording_ref.deleted_by IS
    'The recording:delete-privileged actor for a governance delete (NULL for automated retention prune).';
COMMENT ON COLUMN runtime.recording_ref.legal_hold_reason IS
    'Optional reason captured when a legal hold is placed (blocks retention prune + governance delete).';

COMMENT ON COLUMN runtime.recording_ref.object_version_id IS
    'Object-store version id of the finalized ciphertext object; replay/export pin it so a later shadow PUT to the same key is never served. Write-once once set (V24 trigger).';

COMMENT ON COLUMN runtime.ca_key_material.key_location IS
    'local_kek: wrapped_key/iv/kek_reference hold the KEK-wrapped private key. external: the private key lives in a key service (e.g. Azure Key Vault); those three columns are NULL by construction.';
