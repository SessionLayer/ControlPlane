CREATE INDEX idx_presence_owning_gateway ON runtime.presence (owning_gateway);

CREATE INDEX idx_audit_actor        ON runtime.audit_event (actor);
CREATE INDEX idx_audit_subject      ON runtime.audit_event (subject);
CREATE INDEX idx_audit_node         ON runtime.audit_event (node_id);
CREATE INDEX idx_audit_occurred_at  ON runtime.audit_event (occurred_at);
CREATE INDEX idx_audit_source_ip    ON runtime.audit_event (source_ip);
CREATE INDEX idx_audit_access_model ON runtime.audit_event (access_model);
CREATE INDEX idx_audit_correlation  ON runtime.audit_event (correlation_id);
CREATE INDEX idx_audit_session      ON runtime.audit_event (session_id);
CREATE INDEX idx_audit_capabilities ON runtime.audit_event USING gin (capabilities);
CREATE INDEX idx_audit_node_labels  ON runtime.audit_event USING gin (node_labels);
CREATE UNIQUE INDEX uq_audit_seq    ON runtime.audit_event (seq);

CREATE INDEX idx_session_identity     ON runtime.ssh_session (identity);
CREATE INDEX idx_session_node         ON runtime.ssh_session (node_id);
CREATE INDEX idx_session_started_at   ON runtime.ssh_session (started_at);
CREATE INDEX idx_session_access_model ON runtime.ssh_session (access_model);
CREATE INDEX idx_session_gateway      ON runtime.ssh_session (gateway_id);
CREATE INDEX idx_session_jit_request  ON runtime.ssh_session (jit_request_id);
CREATE INDEX idx_session_breakglass   ON runtime.ssh_session (breakglass_activation_id);
CREATE INDEX idx_session_live         ON runtime.ssh_session (node_id) WHERE ended_at IS NULL;

CREATE INDEX idx_lock_expires_at ON runtime.access_lock (expires_at);

-- Postgres does not auto-index foreign-key columns. NB: config.role_binding needs no
-- separate role_id index — the composite UNIQUE (role_id, subject_kind, subject) is
-- role_id-leading and already serves both findByRoleId and the ON DELETE CASCADE lookup.
CREATE INDEX idx_agent_identity_node   ON runtime.agent_identity (node_id);
CREATE INDEX idx_join_token_node       ON runtime.join_token (node_id);
CREATE INDEX idx_jit_request_target    ON runtime.jit_request (target_node_id);

-- A CA kind has several rows during a rotation overlap (incoming/active/outgoing), so
-- uniqueness has to be partial: at most one of them is 'active' at any time.
CREATE UNIQUE INDEX uq_ca_config_active_per_kind
    ON config.ca_config (ca_kind) WHERE rotation_state = 'active';

-- Locked/revoked history rows accumulate per node, so uniqueness has to be partial:
-- one active identity per node, enforced without blocking re-provision.
CREATE UNIQUE INDEX uq_agent_identity_active_per_node
    ON runtime.agent_identity (node_id) WHERE status = 'active';

CREATE INDEX idx_jit_request_state ON runtime.jit_request (state);
CREATE INDEX idx_jit_request_requester ON runtime.jit_request (requester);
CREATE INDEX idx_node_status ON runtime.node (status);
CREATE INDEX idx_join_token_expires ON runtime.join_token (expires_at) WHERE consumed_at IS NULL;
CREATE INDEX idx_otp_expires ON runtime.otp (expires_at) WHERE used = false;
CREATE INDEX idx_pin_identity ON runtime.pin (identity);
