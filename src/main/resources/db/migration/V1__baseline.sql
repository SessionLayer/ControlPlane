-- SessionLayer Control Plane schema, whole.

-- Generated from a database, not hand-merged: a Postgres 17 cluster was migrated
-- through the 36 incremental migrations this file replaces, dumped, and the result
-- diffed back against that cluster until schema, privileges, comments and data were
-- identical. Regenerate the same way rather than editing by hand.

SET check_function_bodies = false;
SET client_min_messages = warning;

CREATE SCHEMA config;

CREATE SCHEMA runtime;

DO $do$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        CREATE ROLE cp_runtime NOLOGIN;
    END IF;
END
$do$;
ALTER ROLE cp_runtime WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '${cpRuntimePassword}';
COMMENT ON ROLE cp_runtime IS 'SessionLayer CP restricted runtime role: CRUD on config/runtime except audit_event (INSERT/SELECT only); no DDL/ownership. Runtime connects as this; Flyway as the owner.';

-- Schema-scoped default ACLs are merged ON TOP of the built-in default, which for
-- functions always includes PUBLIC EXECUTE - so `ALTER DEFAULT PRIVILEGES IN SCHEMA x
-- REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` silently does nothing. Only the
-- schema-less form replaces the built-in default. It has to precede every CREATE
-- FUNCTION below to apply to them.
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE FUNCTION config.enforce_policy_epoch_monotonic() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.epoch < OLD.epoch THEN
        RAISE EXCEPTION 'policy epoch must not decrease (% -> %)', OLD.epoch, NEW.epoch
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION runtime.audit_ensure_partition(month_start date) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'runtime'
    AS $$
DECLARE
    part_name text := format('audit_event_%s', to_char(month_start, 'YYYYMM'));
    start_ts  timestamptz := date_trunc('month', month_start)::timestamptz;
    end_ts    timestamptz := (date_trunc('month', month_start) + interval '1 month')::timestamptz;
BEGIN
    IF to_regclass('runtime.' || part_name) IS NULL THEN
        EXECUTE format(
            'CREATE TABLE runtime.%I PARTITION OF runtime.audit_event FOR VALUES FROM (%L) TO (%L)',
            part_name, start_ts, end_ts);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
            EXECUTE format('REVOKE ALL ON runtime.%I FROM cp_runtime', part_name);
            EXECUTE format('GRANT INSERT, SELECT ON runtime.%I TO cp_runtime', part_name);
        END IF;
    END IF;
    RETURN part_name;
END;
$$;

COMMENT ON FUNCTION runtime.audit_ensure_partition(month_start date) IS 'Create-ahead a monthly audit_event partition (idempotent); locks it to INSERT/SELECT for cp_runtime. SECURITY DEFINER so the restricted role can pre-create without DDL rights.';

CREATE FUNCTION runtime.audit_ensure_partitions(from_month date, num_months integer) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'runtime'
    AS $$
DECLARE
    i integer;
BEGIN
    -- Bound the loop so a caller cannot spam-create millions of partition tables
    -- (catalog-bloat DoS). 60 months is ample create-ahead headroom.
    IF num_months < 0 OR num_months > 60 THEN
        RAISE EXCEPTION 'audit_ensure_partitions: num_months must be between 0 and 60, got %', num_months;
    END IF;
    FOR i IN 0 .. GREATEST(num_months - 1, 0) LOOP
        PERFORM runtime.audit_ensure_partition((date_trunc('month', from_month) + (i || ' months')::interval)::date);
    END LOOP;
    RETURN num_months;
END;
$$;

COMMENT ON FUNCTION runtime.audit_ensure_partitions(from_month date, num_months integer) IS 'Create-ahead num_months monthly audit_event partitions from from_month (idempotent).';

CREATE FUNCTION runtime.audit_event_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'runtime.audit_event is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

COMMENT ON FUNCTION runtime.audit_event_immutable() IS 'Append-only guard for runtime.audit_event.';

CREATE FUNCTION runtime.audit_prune_before(cutoff timestamp with time zone) RETURNS text[]
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'runtime'
    AS $_$
DECLARE
    part     record;
    upper_ts timestamptz;
    dropped  text[] := ARRAY[]::text[];
BEGIN
    FOR part IN
        SELECT c.relname
        FROM pg_inherits inh
        JOIN pg_class c  ON c.oid = inh.inhrelid
        JOIN pg_class p  ON p.oid = inh.inhparent
        JOIN pg_namespace n ON n.oid = p.relnamespace
        WHERE n.nspname = 'runtime' AND p.relname = 'audit_event'
          AND c.relname ~ '^audit_event_[0-9]{6}$'
    LOOP
        upper_ts := (to_date(right(part.relname, 6), 'YYYYMM') + interval '1 month')::timestamptz;
        IF upper_ts <= cutoff THEN
            EXECUTE format('ALTER TABLE runtime.audit_event DETACH PARTITION runtime.%I', part.relname);
            EXECUTE format('DROP TABLE runtime.%I', part.relname);
            dropped := array_append(dropped, part.relname);
        END IF;
    END LOOP;
    RETURN dropped;
END;
$_$;

COMMENT ON FUNCTION runtime.audit_prune_before(cutoff timestamp with time zone) IS 'Retention: DETACH+DROP audit_event monthly partitions entirely older than cutoff. Returns dropped partition names.';

CREATE FUNCTION runtime.enforce_ca_key_material_write_once() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

CREATE FUNCTION runtime.enforce_generation_monotonic() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.generation < OLD.generation THEN
        RAISE EXCEPTION 'generation counter must not decrease (% -> %) for %.% id=%',
            OLD.generation, NEW.generation, TG_TABLE_SCHEMA, TG_TABLE_NAME, OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION runtime.enforce_generation_monotonic() IS 'Rejects a decreasing generation counter.';

CREATE FUNCTION runtime.enforce_presence_nonce_monotonic() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.nonce < OLD.nonce THEN
        RAISE EXCEPTION 'presence nonce must not decrease (% -> %) for node_id=%',
            OLD.nonce, NEW.nonce, OLD.node_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION runtime.enforce_presence_nonce_monotonic() IS 'Rejects a decreasing presence ownership nonce.';

CREATE FUNCTION runtime.enforce_recording_ref_write_once() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.object_key IS DISTINCT FROM OLD.object_key
        OR NEW.encryption_key_ref IS DISTINCT FROM OLD.encryption_key_ref
        OR (OLD.hash_chain_head IS NOT NULL AND NEW.hash_chain_head IS DISTINCT FROM OLD.hash_chain_head)
        OR (OLD.content_digest IS NOT NULL AND NEW.content_digest IS DISTINCT FROM OLD.content_digest)
        OR (OLD.object_version_id IS NOT NULL AND NEW.object_version_id IS DISTINCT FROM OLD.object_version_id) THEN
        RAISE EXCEPTION 'recording_ref provenance (session_id/object_key/encryption_key_ref/hash_chain_head/content_digest/object_version_id) is write-once'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION runtime.enforce_recording_ref_write_once() IS 'Makes recording provenance columns write-once.';

CREATE FUNCTION runtime.is_ip_or_cidr(value text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
    AS $$
BEGIN
    RETURN value::inet IS NOT NULL;
EXCEPTION
    WHEN others THEN
        RETURN false;
END;
$$;

COMMENT ON FUNCTION runtime.is_ip_or_cidr(value text) IS 'Total IP/CIDR-literal validator (::inet, lenient): malformed input -> false (clean CHECK violation), not a cast error.';

CREATE FUNCTION runtime.recording_prunable(cutoff timestamp with time zone) RETURNS TABLE(id uuid, object_key text)
    LANGUAGE sql STABLE
    AS $$
    SELECT r.id, r.object_key
    FROM runtime.recording_ref r
    WHERE r.legal_hold = false
      AND r.worm_mode IS DISTINCT FROM 'compliance'
      AND r.retention_until IS NOT NULL
      AND r.retention_until <= cutoff
      AND r.pruned_at IS NULL;
$$;

COMMENT ON FUNCTION runtime.recording_prunable(cutoff timestamp with time zone) IS 'Recordings eligible for retention pruning (governance + past retention_until + no legal hold + not already pruned). Compliance/legal-held never returned.';

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE config.breakglass_policy (
    id uuid NOT NULL,
    name text NOT NULL,
    recording_strict boolean DEFAULT true NOT NULL,
    alert_target text NOT NULL,
    review_required boolean DEFAULT true NOT NULL,
    auth_path text DEFAULT 'fido2'::text NOT NULL,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT breakglass_policy_auth_path_check CHECK ((auth_path = ANY (ARRAY['fido2'::text, 'offline_code'::text]))),
    CONSTRAINT breakglass_policy_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text])))
);

COMMENT ON TABLE config.breakglass_policy IS 'Break-glass - recording-strict, alert, review, IdP-independent auth path.';

CREATE TABLE config.ca_config (
    id uuid NOT NULL,
    name text NOT NULL,
    ca_kind text NOT NULL,
    backend text NOT NULL,
    key_reference text NOT NULL,
    algorithm text DEFAULT 'ecdsa-p256'::text NOT NULL,
    rotation_state text DEFAULT 'active'::text NOT NULL,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ca_config_algorithm_check CHECK ((algorithm = ANY (ARRAY['ecdsa-p256'::text, 'ecdsa-p384'::text, 'ecdsa-p521'::text, 'ed25519'::text, 'rsa-2048'::text, 'rsa-4096'::text]))),
    CONSTRAINT ca_config_backend_check CHECK ((backend = ANY (ARRAY['local'::text, 'aws_kms'::text, 'azure_keyvault'::text, 'vault'::text]))),
    CONSTRAINT ca_config_ca_kind_check CHECK ((ca_kind = ANY (ARRAY['user'::text, 'session'::text, 'host'::text, 'mtls'::text]))),
    CONSTRAINT ca_config_key_reference_check CHECK (((key_reference !~~ '%PRIVATE KEY%'::text) AND (key_reference !~~ '%BEGIN %'::text))),
    CONSTRAINT ca_config_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text]))),
    CONSTRAINT ca_config_rotation_state_check CHECK ((rotation_state = ANY (ARRAY['incoming'::text, 'active'::text, 'outgoing'::text, 'expired'::text])))
);

COMMENT ON TABLE config.ca_config IS 'Per-CA (user|session|host) backend + key reference; multiple rows per kind support rotation overlap (one active). Default ECDSA P-256. Never stores private key material.';

COMMENT ON COLUMN config.ca_config.ca_kind IS 'user|session|host (SSH CAs) or mtls (the internal CP<->Gateway X.509 CA).';

CREATE TABLE config.capability_def (
    id uuid NOT NULL,
    name text NOT NULL,
    description text,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT capability_def_name_check CHECK ((name = ANY (ARRAY['shell'::text, 'exec'::text, 'sftp'::text, 'scp'::text, 'port_forward_local'::text, 'port_forward_remote'::text, 'agent_forward'::text, 'x11'::text]))),
    CONSTRAINT capability_def_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text])))
);

COMMENT ON TABLE config.capability_def IS 'CONFIG: requestable-capability catalogue.';

CREATE TABLE config.dp_rule (
    id uuid NOT NULL,
    name text NOT NULL,
    identity_selector jsonb NOT NULL,
    node_label_selector jsonb NOT NULL,
    source_ip_condition jsonb,
    principals text[] NOT NULL,
    ttl_seconds integer,
    capabilities text[] DEFAULT ARRAY['shell'::text, 'exec'::text] NOT NULL,
    effect text NOT NULL,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dp_rule_allow_requires_ttl CHECK (((effect <> 'allow'::text) OR (ttl_seconds IS NOT NULL))),
    CONSTRAINT dp_rule_capabilities_check CHECK ((capabilities <@ ARRAY['shell'::text, 'exec'::text, 'sftp'::text, 'scp'::text, 'port_forward_local'::text, 'port_forward_remote'::text, 'agent_forward'::text, 'x11'::text])),
    CONSTRAINT dp_rule_effect_check CHECK ((effect = ANY (ARRAY['allow'::text, 'deny'::text]))),
    CONSTRAINT dp_rule_identity_selector_check CHECK ((jsonb_typeof(identity_selector) = 'object'::text)),
    CONSTRAINT dp_rule_node_label_selector_check CHECK ((jsonb_typeof(node_label_selector) = 'object'::text)),
    CONSTRAINT dp_rule_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text]))),
    CONSTRAINT dp_rule_source_ip_condition_check CHECK (((source_ip_condition IS NULL) OR (jsonb_typeof(source_ip_condition) = 'object'::text))),
    CONSTRAINT dp_rule_ttl_seconds_check CHECK ((ttl_seconds > 0))
);

COMMENT ON TABLE config.dp_rule IS 'Data-plane RBAC grant (typed policy-as-data). Evaluated by the application.';

COMMENT ON COLUMN config.dp_rule.ttl_seconds IS 'The granted access''s lifetime in seconds. Required for an allow, where it bounds the grant; NULL for a deny, which grants nothing and so has no lifetime to bound. The API drops any value sent on a deny rather than storing a number that means nothing. There is no default: an unbounded grant is never inferred from an omitted value.';

CREATE TABLE config.jit_policy (
    id uuid NOT NULL,
    name text NOT NULL,
    target_selector jsonb NOT NULL,
    capabilities text[] DEFAULT ARRAY[]::text[] NOT NULL,
    max_ttl_seconds integer NOT NULL,
    approval_chain jsonb DEFAULT '[]'::jsonb NOT NULL,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT jit_policy_approval_chain_check CHECK (((jsonb_typeof(approval_chain) = 'array'::text) AND (jsonb_array_length(approval_chain) <= 3))),
    CONSTRAINT jit_policy_capabilities_check CHECK ((capabilities <@ ARRAY['shell'::text, 'exec'::text, 'sftp'::text, 'scp'::text, 'port_forward_local'::text, 'port_forward_remote'::text, 'agent_forward'::text, 'x11'::text])),
    CONSTRAINT jit_policy_max_ttl_seconds_check CHECK ((max_ttl_seconds > 0)),
    CONSTRAINT jit_policy_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text]))),
    CONSTRAINT jit_policy_target_selector_check CHECK ((jsonb_typeof(target_selector) = 'object'::text))
);

COMMENT ON TABLE config.jit_policy IS 'JIT-requestable targets + 0-3 level approval chain (email/OIDC-group).';

CREATE TABLE config.node_policy (
    id uuid NOT NULL,
    name text NOT NULL,
    desired_labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    connector_kind text NOT NULL,
    host_pin_ref text,
    host_ca_ref text,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT node_policy_connector_kind_check CHECK ((connector_kind = ANY (ARRAY['agent'::text, 'agentless'::text]))),
    CONSTRAINT node_policy_desired_labels_check CHECK ((jsonb_typeof(desired_labels) = 'object'::text)),
    CONSTRAINT node_policy_host_ca_ref_check CHECK (((host_ca_ref IS NULL) OR (host_ca_ref !~~ '%PRIVATE KEY%'::text))),
    CONSTRAINT node_policy_host_pin_ref_check CHECK (((host_pin_ref IS NULL) OR (host_pin_ref !~~ '%PRIVATE KEY%'::text))),
    CONSTRAINT node_policy_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text])))
);

COMMENT ON TABLE config.node_policy IS 'CONFIG: NodePolicy - desired node labels + connector + host trust refs.';

CREATE TABLE config.operator_settings (
    id uuid NOT NULL,
    singleton boolean DEFAULT true NOT NULL,
    kek_reference text,
    default_ca_backend text DEFAULT 'local'::text NOT NULL,
    audit_retention_days integer DEFAULT 365 NOT NULL,
    default_worm_mode text DEFAULT 'governance'::text NOT NULL,
    otp_ttl_seconds integer DEFAULT 120 NOT NULL,
    default_max_session_seconds integer,
    default_idle_timeout_seconds integer,
    default_max_concurrent_sessions integer,
    bootstrap_admin_subject text,
    bootstrap_credential_hash text,
    bootstrap_completed boolean DEFAULT false NOT NULL,
    bootstrap_completed_at timestamp with time zone,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    recording_customer_public_key bytea,
    recording_key_seal_algorithm text DEFAULT 'ecies_p256'::text NOT NULL,
    recording_key_ref text,
    recording_retention_days integer DEFAULT 365 NOT NULL,
    recording_strict_default boolean DEFAULT true NOT NULL,
    CONSTRAINT operator_settings_audit_retention_days_check CHECK ((audit_retention_days > 0)),
    CONSTRAINT operator_settings_bootstrap_credential_hash_check CHECK (((bootstrap_credential_hash IS NULL) OR (bootstrap_credential_hash !~~ '%PRIVATE KEY%'::text))),
    CONSTRAINT operator_settings_default_ca_backend_check CHECK ((default_ca_backend = ANY (ARRAY['local'::text, 'aws_kms'::text, 'azure_keyvault'::text, 'vault'::text]))),
    CONSTRAINT operator_settings_default_idle_timeout_seconds_check CHECK (((default_idle_timeout_seconds IS NULL) OR (default_idle_timeout_seconds > 0))),
    CONSTRAINT operator_settings_default_max_concurrent_sessions_check CHECK (((default_max_concurrent_sessions IS NULL) OR (default_max_concurrent_sessions > 0))),
    CONSTRAINT operator_settings_default_max_session_seconds_check CHECK (((default_max_session_seconds IS NULL) OR (default_max_session_seconds > 0))),
    CONSTRAINT operator_settings_default_worm_mode_check CHECK ((default_worm_mode = ANY (ARRAY['compliance'::text, 'governance'::text]))),
    CONSTRAINT operator_settings_kek_reference_check CHECK (((kek_reference IS NULL) OR ((kek_reference !~~ '%PRIVATE KEY%'::text) AND (kek_reference !~~ '%BEGIN %'::text)))),
    CONSTRAINT operator_settings_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text]))),
    CONSTRAINT operator_settings_otp_ttl_seconds_check CHECK (((otp_ttl_seconds >= 60) AND (otp_ttl_seconds <= 300))),
    CONSTRAINT operator_settings_recording_key_ref_check CHECK (((recording_key_ref IS NULL) OR ((recording_key_ref !~~ '%PRIVATE KEY%'::text) AND (recording_key_ref !~~ '%BEGIN %'::text)))),
    CONSTRAINT operator_settings_recording_key_seal_algorithm_check CHECK ((recording_key_seal_algorithm = ANY (ARRAY['ecies_p256'::text, 'rsa_oaep_sha256'::text]))),
    CONSTRAINT operator_settings_recording_retention_days_check CHECK ((recording_retention_days >= 1)),
    CONSTRAINT operator_settings_singleton_check CHECK ((singleton = true))
);

COMMENT ON TABLE config.operator_settings IS 'Singleton cluster settings (KEK ref, default CA backend, retention/WORM/OTP/session-limit defaults, bootstrap self-disable). Cold start reads/writes this. bootstrap_* fields are runtime-managed (operational state, not config).';

COMMENT ON COLUMN config.operator_settings.recording_customer_public_key IS 'Customer PUBLIC key (DER SubjectPublicKeyInfo) the Gateway seals the per-recording data key to. NULL => recording un-provisioned => BeginRecording fails closed. Public material only (the CP never holds the private half).';

COMMENT ON COLUMN config.operator_settings.recording_key_seal_algorithm IS 'How the per-recording data key is sealed to the customer key: ecies_p256 (default) | rsa_oaep_sha256.';

COMMENT ON COLUMN config.operator_settings.recording_key_ref IS 'Operator reference to the customer key (persisted into recording_ref.encryption_key_ref; never key material).';

COMMENT ON COLUMN config.operator_settings.recording_retention_days IS 'Recording retention window (object-lock retain-until + recording_ref.retention_until).';

CREATE TABLE config.platform_role (
    id uuid NOT NULL,
    name text NOT NULL,
    permissions text[] NOT NULL,
    description text,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_role_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text]))),
    CONSTRAINT platform_role_permissions_check CHECK ((permissions <@ ARRAY['rbac:read'::text, 'rbac:write'::text, 'node:enroll'::text, 'gateway:enroll'::text, 'gateway:remove'::text, 'node:quarantine'::text, 'node:remove'::text, 'ca:manage'::text, 'ca:rotate'::text, 'request:approve'::text, 'recording:replay'::text, 'recording:export'::text, 'recording:delete'::text, 'recording:key-manage'::text, 'audit:read'::text, 'metrics:read'::text, 'user:manage'::text, 'settings:write'::text, 'lock:read'::text, 'lock:write'::text, 'breakglass:manage'::text]))
);

COMMENT ON TABLE config.platform_role IS 'Platform RBAC role = granular permission set.';

CREATE TABLE config.policy_epoch (
    id uuid NOT NULL,
    singleton boolean DEFAULT true NOT NULL,
    epoch bigint DEFAULT 0 NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT policy_epoch_epoch_check CHECK ((epoch >= 0)),
    CONSTRAINT policy_epoch_singleton_check CHECK ((singleton = true))
);

COMMENT ON TABLE config.policy_epoch IS 'Authoritative monotonic policy epoch (singleton). The application bumps it on config change; decisions snapshot it into ssh_session/audit_event.';

CREATE TABLE config.role_binding (
    id uuid NOT NULL,
    role_id uuid NOT NULL,
    subject_kind text NOT NULL,
    subject text NOT NULL,
    scope jsonb,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT role_binding_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text]))),
    CONSTRAINT role_binding_scope_check CHECK (((scope IS NULL) OR (jsonb_typeof(scope) = 'object'::text))),
    CONSTRAINT role_binding_subject_kind_check CHECK ((subject_kind = ANY (ARRAY['user'::text, 'group'::text])))
);

COMMENT ON TABLE config.role_binding IS 'Binds a subject to a platform_role; scope for recording:replay/export.';

CREATE TABLE config.service_account (
    id uuid NOT NULL,
    name text NOT NULL,
    description text,
    auth_method text DEFAULT 'private_key_jwt'::text NOT NULL,
    key_reference text,
    token_ttl_seconds integer,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT service_account_auth_method_check CHECK ((auth_method = ANY (ARRAY['private_key_jwt'::text, 'mtls'::text, 'client_secret'::text]))),
    CONSTRAINT service_account_key_reference_check CHECK (((key_reference IS NULL) OR (key_reference !~~ '%PRIVATE KEY%'::text))),
    CONSTRAINT service_account_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text]))),
    CONSTRAINT service_account_token_ttl_seconds_check CHECK (((token_ttl_seconds IS NULL) OR (token_ttl_seconds > 0)))
);

COMMENT ON TABLE config.service_account IS 'Machine-consumer definition. Issued credentials live in RUNTIME.';

CREATE TABLE config.session_limit_policy (
    id uuid NOT NULL,
    name text NOT NULL,
    identity_selector jsonb NOT NULL,
    max_concurrent_sessions integer,
    max_session_seconds integer,
    idle_timeout_seconds integer,
    origin text DEFAULT 'default'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT session_limit_policy_identity_selector_check CHECK ((jsonb_typeof(identity_selector) = 'object'::text)),
    CONSTRAINT session_limit_policy_idle_timeout_seconds_check CHECK (((idle_timeout_seconds IS NULL) OR (idle_timeout_seconds > 0))),
    CONSTRAINT session_limit_policy_max_concurrent_sessions_check CHECK (((max_concurrent_sessions IS NULL) OR (max_concurrent_sessions > 0))),
    CONSTRAINT session_limit_policy_max_session_seconds_check CHECK (((max_session_seconds IS NULL) OR (max_session_seconds > 0))),
    CONSTRAINT session_limit_policy_origin_check CHECK ((origin = ANY (ARRAY['api'::text, 'ui'::text, 'default'::text])))
);

COMMENT ON TABLE config.session_limit_policy IS 'Per-identity session-limit overrides (max concurrent/duration/idle). Cluster defaults live in operator_settings.';

CREATE TABLE runtime.access_lock (
    id uuid NOT NULL,
    target_selector jsonb NOT NULL,
    mode text NOT NULL,
    ttl_seconds integer,
    expires_at timestamp with time zone,
    reason text NOT NULL,
    created_by text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT access_lock_mode_check CHECK ((mode = ANY (ARRAY['strict'::text, 'best_effort'::text]))),
    CONSTRAINT access_lock_target_selector_check CHECK ((jsonb_typeof(target_selector) = 'object'::text)),
    CONSTRAINT access_lock_ttl_seconds_check CHECK (((ttl_seconds IS NULL) OR (ttl_seconds > 0)))
);

COMMENT ON TABLE runtime.access_lock IS 'The access-lock entity, named access_lock because "lock" is a reserved word. API-ONLY runtime resource; the config-vs-runtime boundary keeps it out of config.';

CREATE TABLE runtime.agent_identity (
    id uuid NOT NULL,
    node_id uuid NOT NULL,
    mtls_identity_ref text NOT NULL,
    fingerprint text,
    generation bigint DEFAULT 0 NOT NULL,
    join_method text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    issued_at timestamp with time zone,
    not_after timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    status_reason text,
    status_changed_by text,
    status_changed_at timestamp with time zone,
    prev_fingerprint text,
    CONSTRAINT agent_identity_generation_check CHECK ((generation >= 0)),
    CONSTRAINT agent_identity_join_method_check CHECK ((join_method = ANY (ARRAY['token'::text, 'oidc'::text, 'mtls'::text]))),
    CONSTRAINT agent_identity_mtls_identity_ref_check CHECK ((mtls_identity_ref !~~ '%PRIVATE KEY%'::text)),
    CONSTRAINT agent_identity_status_check CHECK ((status = ANY (ARRAY['active'::text, 'locked'::text, 'revoked'::text]))),
    CONSTRAINT agent_identity_validity_ordered CHECK (((not_after IS NULL) OR (issued_at IS NULL) OR (not_after > issued_at)))
);

COMMENT ON TABLE runtime.agent_identity IS 'Agent mTLS identity + generation counter. One active per node, enforced by the partial unique index uq_agent_identity_active_per_node.';

COMMENT ON COLUMN runtime.agent_identity.status_reason IS 'Why the identity reached its status (lock/revoke reason, e.g. generation mismatch).';

COMMENT ON COLUMN runtime.agent_identity.prev_fingerprint IS 'SHA-256 fingerprint of the previous-generation mTLS cert; pinned alongside fingerprint at renew to survive renew-ahead overlap. Public material.';

CREATE TABLE runtime.agent_renewal_receipt (
    id uuid NOT NULL,
    agent_id uuid NOT NULL,
    prior_generation bigint NOT NULL,
    csr_public_key_hash text NOT NULL,
    new_generation bigint NOT NULL,
    certificate bytea NOT NULL,
    ca_certificate bytea NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

COMMENT ON TABLE runtime.agent_renewal_receipt IS 'Replay receipt for a completed RenewAgentIdentity call, keyed by (agent, prior generation, CSR public key hash); lets a lost-response retry replay the issued cert instead of tripping clone detection. Bounded by expires_at.';

CREATE TABLE runtime.audit_event (
    id uuid NOT NULL,
    seq bigint NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    actor text NOT NULL,
    subject text,
    action text NOT NULL,
    outcome text NOT NULL,
    correlation_id uuid,
    session_id uuid,
    node_id uuid,
    node_labels jsonb,
    source_ip text,
    access_model text,
    capabilities text[],
    detail jsonb,
    prev_hash text,
    record_hash text,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_event_access_model_check CHECK (((access_model IS NULL) OR (access_model = ANY (ARRAY['standing'::text, 'jit'::text, 'breakglass'::text])))),
    CONSTRAINT audit_event_capabilities_check CHECK (((capabilities IS NULL) OR (capabilities <@ ARRAY['shell'::text, 'exec'::text, 'sftp'::text, 'scp'::text, 'port_forward_local'::text, 'port_forward_remote'::text, 'agent_forward'::text, 'x11'::text]))),
    CONSTRAINT audit_event_detail_check CHECK (((detail IS NULL) OR (jsonb_typeof(detail) = 'object'::text))),
    CONSTRAINT audit_event_node_labels_check CHECK (((node_labels IS NULL) OR (jsonb_typeof(node_labels) = 'object'::text))),
    CONSTRAINT audit_event_outcome_check CHECK ((outcome = ANY (ARRAY['success'::text, 'failure'::text, 'denied'::text, 'error'::text]))),
    CONSTRAINT audit_event_source_ip_check CHECK (((source_ip IS NULL) OR runtime.is_ip_or_cidr(source_ip)))
)
PARTITION BY RANGE (occurred_at);

COMMENT ON TABLE runtime.audit_event IS 'Single correlated audit stream. PARTITION BY RANGE(occurred_at) for retention (drop old partitions, no DELETE). Append-only trigger + seq chain order re-applied. Composite PK (id, occurred_at); id alone is globally unique (UUIDv7). Hash-chain cols are application-populated.';

CREATE TABLE runtime.audit_event_default (
    id uuid NOT NULL,
    seq bigint NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    actor text NOT NULL,
    subject text,
    action text NOT NULL,
    outcome text NOT NULL,
    correlation_id uuid,
    session_id uuid,
    node_id uuid,
    node_labels jsonb,
    source_ip text,
    access_model text,
    capabilities text[],
    detail jsonb,
    prev_hash text,
    record_hash text,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_event_access_model_check CHECK (((access_model IS NULL) OR (access_model = ANY (ARRAY['standing'::text, 'jit'::text, 'breakglass'::text])))),
    CONSTRAINT audit_event_capabilities_check CHECK (((capabilities IS NULL) OR (capabilities <@ ARRAY['shell'::text, 'exec'::text, 'sftp'::text, 'scp'::text, 'port_forward_local'::text, 'port_forward_remote'::text, 'agent_forward'::text, 'x11'::text]))),
    CONSTRAINT audit_event_detail_check CHECK (((detail IS NULL) OR (jsonb_typeof(detail) = 'object'::text))),
    CONSTRAINT audit_event_node_labels_check CHECK (((node_labels IS NULL) OR (jsonb_typeof(node_labels) = 'object'::text))),
    CONSTRAINT audit_event_outcome_check CHECK ((outcome = ANY (ARRAY['success'::text, 'failure'::text, 'denied'::text, 'error'::text]))),
    CONSTRAINT audit_event_source_ip_check CHECK (((source_ip IS NULL) OR runtime.is_ip_or_cidr(source_ip)))
);

COMMENT ON TABLE runtime.audit_event_default IS 'Catch-all audit partition: guarantees an append-only insert never fails for a missing range. Keep empty by create-ahead; not dropped by audit_prune_before.';

ALTER TABLE runtime.audit_event ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME runtime.audit_event_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE runtime.auth_rate_limit (
    bucket text NOT NULL,
    window_start timestamp with time zone NOT NULL,
    count integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_rate_limit_count_check CHECK ((count >= 0))
);

COMMENT ON TABLE runtime.auth_rate_limit IS 'Durable fixed-window rate-limit counters for OTP-verify + token endpoints (per-source-IP / per-identity bucket).';

CREATE TABLE runtime.breakglass_activation (
    id uuid NOT NULL,
    principal text NOT NULL,
    reason text NOT NULL,
    alert_ref text,
    breakglass_policy_id uuid,
    breakglass_policy_name text,
    review_status text DEFAULT 'pending'::text NOT NULL,
    reviewer text,
    activated_at timestamp with time zone NOT NULL,
    reviewed_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    identity text,
    source_ip text,
    target_node_id uuid,
    credential_ref text,
    CONSTRAINT breakglass_activation_review_status_check CHECK ((review_status = ANY (ARRAY['pending'::text, 'reviewed'::text]))),
    CONSTRAINT breakglass_activation_source_ip_check CHECK (((source_ip IS NULL) OR runtime.is_ip_or_cidr(source_ip)))
);

COMMENT ON TABLE runtime.breakglass_activation IS 'Break-glass activation with mandatory post-hoc review.';

COMMENT ON COLUMN runtime.breakglass_activation.identity IS 'The break-glass operator identity that authenticated (IdP-independent).';

COMMENT ON COLUMN runtime.breakglass_activation.credential_ref IS 'The resolving credential reference (sk-ecdsa fingerprint or offline-code id); legibility for post-hoc review.';

CREATE TABLE runtime.breakglass_credential (
    id uuid NOT NULL,
    key_fingerprint text NOT NULL,
    public_key bytea NOT NULL,
    sk_application text,
    identity text NOT NULL,
    allowed_principals text[] DEFAULT ARRAY[]::text[] NOT NULL,
    node_selector jsonb,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_by text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT breakglass_credential_node_selector_check CHECK (((node_selector IS NULL) OR (jsonb_typeof(node_selector) = 'object'::text)))
);

COMMENT ON TABLE runtime.breakglass_credential IS 'Registered break-glass FIDO2 sk-ecdsa PUBLIC key (primary IdP-independent path). Public material only; revocable; scoped to allowed_principals + optional node_selector.';

CREATE TABLE runtime.breakglass_offline_code (
    id uuid NOT NULL,
    code_hash text NOT NULL,
    identity text NOT NULL,
    allowed_principals text[] DEFAULT ARRAY[]::text[] NOT NULL,
    node_selector jsonb,
    source_cidr text,
    expires_at timestamp with time zone NOT NULL,
    used boolean DEFAULT false NOT NULL,
    used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_by text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT breakglass_offline_code_code_hash_check CHECK ((code_hash !~~ '%PRIVATE KEY%'::text)),
    CONSTRAINT breakglass_offline_code_node_selector_check CHECK (((node_selector IS NULL) OR (jsonb_typeof(node_selector) = 'object'::text))),
    CONSTRAINT breakglass_offline_code_source_cidr_check CHECK (((source_cidr IS NULL) OR runtime.is_ip_or_cidr(source_cidr)))
);

COMMENT ON TABLE runtime.breakglass_offline_code IS 'Pre-issued single-use break-glass code (IdP-independent fallback). Stores code_hash only; atomic single-use; source-bound; ≥128-bit entropy.';

CREATE TABLE runtime.breakglass_token (
    id uuid NOT NULL,
    token_hash text NOT NULL,
    gateway_id uuid NOT NULL,
    identity text NOT NULL,
    node_id uuid,
    allowed_principals text[] DEFAULT ARRAY[]::text[] NOT NULL,
    source_address text,
    expires_at timestamp with time zone NOT NULL,
    used boolean DEFAULT false NOT NULL,
    used_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT breakglass_token_source_address_check CHECK (((source_address IS NULL) OR runtime.is_ip_or_cidr(source_address)))
);

COMMENT ON TABLE runtime.breakglass_token IS 'Single-use break-glass Authorize authority, minted at ResolveBreakglass*, bound to {gateway,identity,node,source,exp}. Hash only; atomic single-use.';

CREATE TABLE runtime.ca_key_material (
    id uuid NOT NULL,
    ca_config_id uuid NOT NULL,
    ca_config_name text NOT NULL,
    wrap_algorithm text DEFAULT 'AES-256-GCM'::text NOT NULL,
    kek_reference text,
    wrapped_key bytea,
    iv bytea,
    public_key bytea NOT NULL,
    key_type text DEFAULT 'ecdsa-sha2-nistp256'::text NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    ca_certificate bytea,
    key_location text DEFAULT 'local_kek'::text NOT NULL,
    CONSTRAINT ca_key_material_key_location_check CHECK ((key_location = ANY (ARRAY['local_kek'::text, 'external'::text]))),
    CONSTRAINT ca_key_material_key_location_shape_check CHECK ((((key_location = 'local_kek'::text) AND (wrapped_key IS NOT NULL) AND (iv IS NOT NULL) AND (kek_reference IS NOT NULL) AND (kek_reference !~~ '%PRIVATE KEY%'::text) AND (octet_length(iv) = 12) AND (octet_length(wrapped_key) > 0) AND (POSITION(('\x2d2d2d2d2d424547494e'::bytea) IN (wrapped_key)) = 0)) OR ((key_location = 'external'::text) AND (wrapped_key IS NULL) AND (iv IS NULL) AND (kek_reference IS NULL)))),
    CONSTRAINT ca_key_material_wrap_algorithm_check CHECK ((wrap_algorithm = 'AES-256-GCM'::text))
);

COMMENT ON TABLE runtime.ca_key_material IS 'KEK-wrapped local-CA private key (ciphertext only) + public blob. KEK is env-sourced, never in the DB. Referenced by config.ca_config.key_reference = local:<id>.';

COMMENT ON COLUMN runtime.ca_key_material.ca_certificate IS 'X.509 CA certificate (DER) for X.509 CA rows (mtls); NULL for SSH CAs. Public material.';

COMMENT ON COLUMN runtime.ca_key_material.key_location IS 'local_kek: wrapped_key/iv/kek_reference hold the KEK-wrapped private key. external: the private key lives in a key service (e.g. Azure Key Vault); those three columns are NULL by construction.';

COMMENT ON CONSTRAINT ca_key_material_key_location_shape_check ON runtime.ca_key_material IS 'Ties wrapped_key/iv/kek_reference to key_location as one shape instead of three independent CHECKs.';

CREATE TABLE runtime.consumed_assertion (
    jti_hash text NOT NULL,
    subject text NOT NULL,
    not_after timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT consumed_assertion_jti_hash_check CHECK ((jti_hash !~~ '%PRIVATE KEY%'::text))
);

COMMENT ON TABLE runtime.consumed_assertion IS 'RFC 7523: single-use guard for private_key_jwt client-assertion jti (hash only). Blocks assertion replay within its lifetime.';

CREATE TABLE runtime.device_flow (
    id uuid NOT NULL,
    device_code_hash text NOT NULL,
    user_code_hash text NOT NULL,
    identity text,
    status text DEFAULT 'pending'::text NOT NULL,
    connection_binding text,
    source_ip text,
    interval_seconds integer DEFAULT 5 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_polled_at timestamp with time zone,
    authorized_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    approver_source_ip text,
    approver_context jsonb,
    source_context_match boolean,
    CONSTRAINT device_flow_approver_context_check CHECK (((approver_context IS NULL) OR (jsonb_typeof(approver_context) = 'object'::text))),
    CONSTRAINT device_flow_approver_source_ip_check CHECK (((approver_source_ip IS NULL) OR runtime.is_ip_or_cidr(approver_source_ip))),
    CONSTRAINT device_flow_interval_seconds_check CHECK ((interval_seconds > 0)),
    CONSTRAINT device_flow_source_ip_check CHECK (((source_ip IS NULL) OR runtime.is_ip_or_cidr(source_ip))),
    CONSTRAINT device_flow_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'authorized'::text, 'denied'::text, 'expired'::text])))
);

COMMENT ON TABLE runtime.device_flow IS 'RFC 8628 device-flow state + 1:1 device_code<->connection anti-phishing binding. Stores hashes only.';

COMMENT ON COLUMN runtime.device_flow.approver_source_ip IS 'Anti-phishing: the approving browser IP captured at the CP verification page.';

COMMENT ON COLUMN runtime.device_flow.source_context_match IS 'Result of correlating the approving browser context with the SSH source IP (deny-only reducer).';

CREATE TABLE runtime.gateway_enrollment_token (
    id uuid NOT NULL,
    token_hash text NOT NULL,
    gateway_name text NOT NULL,
    single_use boolean DEFAULT true NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_by text,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE runtime.gateway_enrollment_token IS 'Single-use, short-TTL Gateway enrollment token (hash only). Shares its JoinMethod shape with Agent enrollment.';

CREATE TABLE runtime.gateway_identity (
    id uuid NOT NULL,
    name text NOT NULL,
    mtls_identity_ref text NOT NULL,
    fingerprint text,
    generation bigint DEFAULT 0 NOT NULL,
    join_method text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    issued_at timestamp with time zone,
    not_after timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    status_reason text,
    status_changed_by text,
    status_changed_at timestamp with time zone,
    prev_fingerprint text,
    CONSTRAINT gateway_identity_generation_check CHECK ((generation >= 0)),
    CONSTRAINT gateway_identity_join_method_check CHECK ((join_method = ANY (ARRAY['token'::text, 'oidc'::text, 'mtls'::text]))),
    CONSTRAINT gateway_identity_mtls_identity_ref_check CHECK ((mtls_identity_ref !~~ '%PRIVATE KEY%'::text)),
    CONSTRAINT gateway_identity_status_check CHECK ((status = ANY (ARRAY['active'::text, 'locked'::text, 'revoked'::text]))),
    CONSTRAINT gateway_identity_validity_ordered CHECK (((not_after IS NULL) OR (issued_at IS NULL) OR (not_after > issued_at)))
);

COMMENT ON TABLE runtime.gateway_identity IS 'Gateway is a first-class lockable principal; renewable mTLS identity + generation.';

COMMENT ON COLUMN runtime.gateway_identity.prev_fingerprint IS 'SHA-256 fingerprint of the previous-generation mTLS cert; pinned alongside fingerprint at the sign/renew tiers to survive renew-ahead overlap. Public material.';

CREATE TABLE runtime.idempotency_key (
    id uuid NOT NULL,
    principal text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    idempotency_key text NOT NULL,
    request_fingerprint text NOT NULL,
    response_status integer NOT NULL,
    response_body text,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT idempotency_key_response_status_check CHECK (((response_status >= 100) AND (response_status <= 599)))
);

COMMENT ON TABLE runtime.idempotency_key IS 'Idempotency-Key replay store; first completed response per (principal, method, path, key). RUNTIME, bounded by expires_at.';

CREATE TABLE runtime.jit_request (
    id uuid NOT NULL,
    requester text NOT NULL,
    target_node_id uuid,
    target_node_name text,
    target_selector jsonb,
    principal text NOT NULL,
    capabilities text[] DEFAULT ARRAY[]::text[] NOT NULL,
    reason text NOT NULL,
    state text DEFAULT 'REQUESTED'::text NOT NULL,
    jit_policy_id uuid,
    jit_policy_name text,
    approval_chain jsonb DEFAULT '[]'::jsonb NOT NULL,
    approvals jsonb DEFAULT '[]'::jsonb NOT NULL,
    approval_deadline timestamp with time zone,
    grant_expires_at timestamp with time zone,
    requested_at timestamp with time zone NOT NULL,
    decided_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_by text,
    decision_reason text,
    policy_max_ttl_seconds integer,
    CONSTRAINT jit_request_approval_chain_check CHECK (((jsonb_typeof(approval_chain) = 'array'::text) AND (jsonb_array_length(approval_chain) <= 3))),
    CONSTRAINT jit_request_approvals_check CHECK (((jsonb_typeof(approvals) = 'array'::text) AND (jsonb_array_length(approvals) <= 16))),
    CONSTRAINT jit_request_capabilities_check CHECK ((capabilities <@ ARRAY['shell'::text, 'exec'::text, 'sftp'::text, 'scp'::text, 'port_forward_local'::text, 'port_forward_remote'::text, 'agent_forward'::text, 'x11'::text])),
    CONSTRAINT jit_request_policy_max_ttl_seconds_check CHECK (((policy_max_ttl_seconds IS NULL) OR (policy_max_ttl_seconds > 0))),
    CONSTRAINT jit_request_state_check CHECK ((state = ANY (ARRAY['REQUESTED'::text, 'PENDING_APPROVAL'::text, 'APPROVED'::text, 'DENIED'::text, 'EXPIRED'::text, 'ACTIVE'::text, 'REVOKED'::text]))),
    CONSTRAINT jit_request_target_selector_check CHECK (((target_selector IS NULL) OR (jsonb_typeof(target_selector) = 'object'::text)))
);

COMMENT ON TABLE runtime.jit_request IS 'JIT state machine + two clocks. jit_policy_id/approval_chain are snapshots.';

COMMENT ON COLUMN runtime.jit_request.decided_by IS 'The approver/denier actor (distinct from the requester in `reason`).';

COMMENT ON COLUMN runtime.jit_request.policy_max_ttl_seconds IS 'Snapshot of jit_policy.max_ttl_seconds at submit; the grant clock = min(this, cluster ceiling). Prevents a mid-flight policy edit/delete from widening the grant.';

CREATE TABLE runtime.join_token (
    id uuid NOT NULL,
    token_hash text NOT NULL,
    scope jsonb NOT NULL,
    join_method text NOT NULL,
    node_id uuid,
    single_use boolean DEFAULT true NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_by text,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT join_token_join_method_check CHECK ((join_method = ANY (ARRAY['token'::text, 'oidc'::text, 'mtls'::text]))),
    CONSTRAINT join_token_scope_check CHECK ((jsonb_typeof(scope) = 'object'::text))
);

COMMENT ON TABLE runtime.join_token IS 'Single-use join token. Stores token_hash only, never the raw token.';

CREATE TABLE runtime.node (
    id uuid NOT NULL,
    name text NOT NULL,
    node_policy_name text,
    resolved_labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    connector_kind text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    health text DEFAULT 'unknown'::text NOT NULL,
    owning_gateway text,
    address text,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    status_reason text,
    status_changed_by text,
    status_changed_at timestamp with time zone,
    CONSTRAINT node_agentless_requires_address CHECK (((connector_kind = 'agent'::text) OR (address IS NOT NULL))),
    CONSTRAINT node_connector_kind_check CHECK ((connector_kind = ANY (ARRAY['agent'::text, 'agentless'::text]))),
    CONSTRAINT node_health_check CHECK ((health = ANY (ARRAY['unknown'::text, 'healthy'::text, 'unhealthy'::text, 'unreachable'::text]))),
    CONSTRAINT node_resolved_labels_check CHECK ((jsonb_typeof(resolved_labels) = 'object'::text)),
    CONSTRAINT node_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'quarantined'::text, 'removed'::text])))
);

COMMENT ON TABLE runtime.node IS 'RUNTIME: live node registration; node_policy_name is a snapshot (no FK to config).';

COMMENT ON COLUMN runtime.node.health IS 'DEPRECATED - not read and not written. Retained for the expand/contract window only; new rows take the DEFAULT and the value never changes afterwards. The API derives health at read time: unhealthy when the node has no runtime.node_host_key anchor (the Gateway never TOFUs, so every session aborts); otherwise, for an agent-connected node, healthy/unreachable from the freshness of its runtime.presence claim and unknown when no Gateway has ever claimed it; agentless nodes are always unknown (no continuous liveness signal, no probe).';

COMMENT ON COLUMN runtime.node.owning_gateway IS 'DEPRECATED - not read and not written. Retained for the expand/contract window only. The API derives the owner at read time from runtime.presence.owning_gateway, and only while that claim is fresh by the HA staleness window - the same rule connect-time routing applies, so the two answers cannot disagree.';

COMMENT ON COLUMN runtime.node.status_reason IS 'Why the node reached its current status (quarantine/remove reason).';

CREATE TABLE runtime.node_host_key (
    id uuid NOT NULL,
    node_id uuid NOT NULL,
    key_type text NOT NULL,
    public_key text,
    fingerprint text,
    host_cert_ref text,
    source text DEFAULT 'pinned_key'::text NOT NULL,
    verified_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT node_host_key_host_ca_requires_material CHECK (((source <> 'host_ca'::text) OR (host_cert_ref IS NOT NULL) OR (public_key IS NOT NULL))),
    CONSTRAINT node_host_key_host_cert_ref_check CHECK (((host_cert_ref IS NULL) OR (host_cert_ref !~~ '%PRIVATE KEY%'::text))),
    CONSTRAINT node_host_key_key_type_check CHECK ((key_type = ANY (ARRAY['ssh-ed25519'::text, 'ecdsa-sha2-nistp256'::text, 'ecdsa-sha2-nistp384'::text, 'ecdsa-sha2-nistp521'::text, 'ssh-rsa'::text, 'rsa-sha2-256'::text, 'rsa-sha2-512'::text, 'ssh-ed25519-cert-v01@openssh.com'::text, 'ecdsa-sha2-nistp256-cert-v01@openssh.com'::text, 'ecdsa-sha2-nistp384-cert-v01@openssh.com'::text, 'ecdsa-sha2-nistp521-cert-v01@openssh.com'::text, 'ssh-rsa-cert-v01@openssh.com'::text, 'rsa-sha2-256-cert-v01@openssh.com'::text, 'rsa-sha2-512-cert-v01@openssh.com'::text]))),
    CONSTRAINT node_host_key_pinned_requires_key_and_fingerprint CHECK (((source <> 'pinned_key'::text) OR ((public_key IS NOT NULL) AND (fingerprint IS NOT NULL)))),
    CONSTRAINT node_host_key_public_key_check CHECK ((public_key !~~ '%PRIVATE KEY%'::text)),
    CONSTRAINT node_host_key_source_check CHECK ((source = ANY (ARRAY['host_ca'::text, 'pinned_key'::text])))
);

COMMENT ON TABLE runtime.node_host_key IS 'Enrollment-anchored node host identity (host-CA cert primary, pinned key fallback) so inner-leg host verification is never TOFU. Public material only.';

COMMENT ON COLUMN runtime.node_host_key.key_type IS 'The anchor''s OpenSSH type token - the first field of the stored line. A host_ca row carries a certificate type (…-cert-v01@openssh.com); a pinned_key row carries a plain key type.';

COMMENT ON COLUMN runtime.node_host_key.public_key IS 'The anchor''s OpenSSH public-key line. Required for a pinned_key row, which IS that key; NULL for a host_ca row recorded from a certificate line, whose material is host_cert_ref. Public material only.';

COMMENT ON COLUMN runtime.node_host_key.fingerprint IS 'SHA256: fingerprint of public_key - what an operator compares against the key the node reports. Required for a pinned_key row; NULL for a host_ca row recorded from a certificate line alone, whose trust comes from the CA signature rather than a fingerprint comparison. Never a computed stand-in.';

CREATE TABLE runtime.oidc_login (
    id uuid NOT NULL,
    state_hash text NOT NULL,
    purpose text DEFAULT 'web_login'::text NOT NULL,
    device_flow_id uuid,
    source_ip text,
    status text DEFAULT 'pending'::text NOT NULL,
    resolved_identity text,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oidc_login_purpose_check CHECK ((purpose = ANY (ARRAY['web_login'::text, 'device'::text]))),
    CONSTRAINT oidc_login_source_ip_check CHECK (((source_ip IS NULL) OR runtime.is_ip_or_cidr(source_ip))),
    CONSTRAINT oidc_login_state_hash_check CHECK ((state_hash !~~ '%PRIVATE KEY%'::text)),
    CONSTRAINT oidc_login_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'completed'::text, 'failed'::text, 'expired'::text])))
);

COMMENT ON TABLE runtime.oidc_login IS 'Auth-code+PKCE relying-party state. state hash only; verifier/nonce derived (never stored). Single-use. Links a device_flow when purpose=device.';

CREATE TABLE runtime.otp (
    id uuid NOT NULL,
    otp_hash text NOT NULL,
    identity text NOT NULL,
    allowed_principals text[] NOT NULL,
    source_cidr text,
    expires_at timestamp with time zone NOT NULL,
    used boolean DEFAULT false NOT NULL,
    used_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT otp_source_cidr_check CHECK (((source_cidr IS NULL) OR runtime.is_ip_or_cidr(source_cidr)))
);

COMMENT ON TABLE runtime.otp IS 'Single-use OTP. Stores otp_hash only, never the raw OTP.';

CREATE TABLE runtime.pin (
    id uuid NOT NULL,
    fingerprint text NOT NULL,
    identity text NOT NULL,
    source_cidr text,
    principals text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pin_source_cidr_check CHECK (((source_cidr IS NULL) OR runtime.is_ip_or_cidr(source_cidr)))
);

COMMENT ON TABLE runtime.pin IS 'AuthN-shortcut pin {fp, identity, source-cidr, principals, expiry}. source_cidr validated by runtime.is_ip_or_cidr.';

CREATE TABLE runtime.presence (
    node_id uuid NOT NULL,
    owning_gateway text NOT NULL,
    gateway_addr text NOT NULL,
    nonce bigint NOT NULL,
    nonce_id uuid NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE runtime.presence IS 'Node -> owning_gateway,addr,monotonic nonce. Queried before routing.';

CREATE TABLE runtime.recording_ref (
    id uuid NOT NULL,
    session_id uuid NOT NULL,
    object_key text NOT NULL,
    encryption_key_ref text NOT NULL,
    hash_chain_head text,
    worm_mode text,
    size_bytes bigint,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    retention_until timestamp with time zone,
    legal_hold boolean DEFAULT false NOT NULL,
    status text DEFAULT 'recording'::text NOT NULL,
    format text DEFAULT 'asciicast-v2'::text NOT NULL,
    content_digest text,
    pruned_at timestamp with time zone,
    delete_mode text,
    deleted_by text,
    legal_hold_reason text,
    object_version_id text,
    CONSTRAINT recording_ref_content_digest_check CHECK (((content_digest IS NULL) OR (content_digest ~ '^sha256:[0-9a-f]{64}$'::text))),
    CONSTRAINT recording_ref_delete_mode_check CHECK (((delete_mode IS NULL) OR (delete_mode = ANY (ARRAY['retention'::text, 'governance'::text])))),
    CONSTRAINT recording_ref_encryption_key_ref_check CHECK (((encryption_key_ref !~~ '%PRIVATE KEY%'::text) AND (encryption_key_ref !~~ '%BEGIN %'::text))),
    CONSTRAINT recording_ref_format_check CHECK ((format = 'asciicast-v2'::text)),
    CONSTRAINT recording_ref_size_bytes_check CHECK (((size_bytes IS NULL) OR (size_bytes >= 0))),
    CONSTRAINT recording_ref_status_check CHECK ((status = ANY (ARRAY['recording'::text, 'finalized'::text, 'truncated'::text, 'failed'::text]))),
    CONSTRAINT recording_ref_worm_mode_check CHECK (((worm_mode IS NULL) OR (worm_mode = ANY (ARRAY['compliance'::text, 'governance'::text]))))
);

COMMENT ON TABLE runtime.recording_ref IS '1:1 with ssh_session (UNIQUE session_id). encryption_key_ref is a reference only.';

COMMENT ON COLUMN runtime.recording_ref.retention_until IS 'Earliest time this recording may be pruned (governance mode only; compliance is never prunable; legal_hold overrides).';

COMMENT ON COLUMN runtime.recording_ref.legal_hold IS 'When true the recording is exempt from retention pruning regardless of retention_until.';

COMMENT ON COLUMN runtime.recording_ref.status IS 'Recording lifecycle - recording -> finalized|truncated|failed.';

COMMENT ON COLUMN runtime.recording_ref.content_digest IS 'Integrity digest (sha256:<hex>); write-once once set (recording_ref_write_once trigger).';

COMMENT ON COLUMN runtime.recording_ref.pruned_at IS 'When the encrypted object was deleted (retention prune or governance delete). The metadata row is retained (crown-jewels provenance).';

COMMENT ON COLUMN runtime.recording_ref.delete_mode IS 'How the object was deleted - retention (automated, past retention_until) or governance (privileged, audited erasure).';

COMMENT ON COLUMN runtime.recording_ref.deleted_by IS 'The recording:delete-privileged actor for a governance delete (NULL for automated retention prune).';

COMMENT ON COLUMN runtime.recording_ref.legal_hold_reason IS 'Optional reason captured when a legal hold is placed (blocks retention prune + governance delete).';

COMMENT ON COLUMN runtime.recording_ref.object_version_id IS 'Object-store version id of the finalized ciphertext object; replay/export pin it so a later shadow PUT to the same key is never served. Write-once once set (recording_ref_write_once trigger).';

CREATE TABLE runtime.recording_token (
    id uuid NOT NULL,
    token_hash text NOT NULL,
    gateway_id uuid NOT NULL,
    session_id uuid NOT NULL,
    node_id uuid,
    principal text NOT NULL,
    source_address text,
    expires_at timestamp with time zone NOT NULL,
    used boolean DEFAULT false NOT NULL,
    used_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT recording_token_source_address_check CHECK (((source_address IS NULL) OR runtime.is_ip_or_cidr(source_address)))
);

COMMENT ON TABLE runtime.recording_token IS 'Single-use BeginRecording token bound to {gateway,session,node,principal,exp}. Hash only; atomic single-use. Minted at Authorize ALLOW alongside session_signing_token.';

CREATE TABLE runtime.service_account_credential (
    id uuid NOT NULL,
    service_account_id uuid NOT NULL,
    service_account_name text NOT NULL,
    credential_type text NOT NULL,
    secret_hash text NOT NULL,
    fingerprint text,
    status text DEFAULT 'active'::text NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    not_after timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_reason text,
    revoked_by text,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sac_validity_ordered CHECK (((not_after IS NULL) OR (not_after > issued_at))),
    CONSTRAINT service_account_credential_credential_type_check CHECK ((credential_type = ANY (ARRAY['private_key_jwt'::text, 'mtls'::text, 'client_secret'::text]))),
    CONSTRAINT service_account_credential_secret_hash_check CHECK (((secret_hash !~~ '%PRIVATE KEY%'::text) AND (secret_hash !~~ '%BEGIN %'::text))),
    CONSTRAINT service_account_credential_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text])))
);

COMMENT ON TABLE runtime.service_account_credential IS 'Issued machine-consumer credential (rotatable/revocable). Hash/reference only; service_account_id is a snapshot (no FK to config).';

CREATE TABLE runtime.session_lease (
    id uuid NOT NULL,
    identity text NOT NULL,
    session_id uuid,
    gateway_name text,
    acquired_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    released_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE runtime.session_lease IS 'Durable per-identity concurrency lease (count unreleased leases = live sessions). Enforcement semaphore lives in the application layer.';

CREATE TABLE runtime.session_signing_token (
    id uuid NOT NULL,
    token_hash text NOT NULL,
    gateway_id uuid NOT NULL,
    session_id uuid NOT NULL,
    node_id uuid,
    principal text NOT NULL,
    capabilities text[] DEFAULT ARRAY['shell'::text, 'exec'::text] NOT NULL,
    source_address text,
    expires_at timestamp with time zone NOT NULL,
    used boolean DEFAULT false NOT NULL,
    used_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT session_signing_token_capabilities_check CHECK ((capabilities <@ ARRAY['shell'::text, 'exec'::text, 'sftp'::text, 'scp'::text, 'port_forward_local'::text, 'port_forward_remote'::text, 'agent_forward'::text, 'x11'::text])),
    CONSTRAINT session_signing_token_source_address_check CHECK (((source_address IS NULL) OR runtime.is_ip_or_cidr(source_address)))
);

COMMENT ON TABLE runtime.session_signing_token IS 'Single-use session-signing token bound to {gateway,session,node,principal,exp}. Hash only; atomic single-use.';

CREATE TABLE runtime.ssh_session (
    id uuid NOT NULL,
    identity text NOT NULL,
    node_id uuid,
    node_name text,
    principal text NOT NULL,
    gateway_id uuid,
    gateway_name text,
    access_model text NOT NULL,
    capabilities text[] DEFAULT ARRAY[]::text[] NOT NULL,
    matched_rule_id uuid,
    matched_rule_name text,
    jit_request_id uuid,
    breakglass_activation_id uuid,
    policy_epoch bigint,
    grant_expiry timestamp with time zone,
    started_at timestamp with time zone NOT NULL,
    ended_at timestamp with time zone,
    end_reason text,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ssh_session_access_model_check CHECK ((access_model = ANY (ARRAY['standing'::text, 'jit'::text, 'breakglass'::text]))),
    CONSTRAINT ssh_session_capabilities_check CHECK ((capabilities <@ ARRAY['shell'::text, 'exec'::text, 'sftp'::text, 'scp'::text, 'port_forward_local'::text, 'port_forward_remote'::text, 'agent_forward'::text, 'x11'::text]))
);

COMMENT ON TABLE runtime.ssh_session IS 'The SSH session entity, named ssh_session because "session" is a reserved word. Holds the decision snapshot: matched_rule_id/name, principal, capabilities, access_model, policy_epoch, grant_expiry.';

COMMENT ON COLUMN runtime.ssh_session.end_reason IS 'Why the session ended, as an advisory diagnostic - the authoritative "why" for a teardown lives in the decision/lock audit chain. The values the Control Plane writes are: closed (orderly, including a cleanly sealed recording), expired (grant expiry), idle_timeout, locked (a Lock tore it down), error, truncated (the recording did not seal cleanly) and gateway_removed (its Gateway identity was removed out from under it). Not constrained: a CHECK here would fail the session-end write rather than lose a row of documentation.';

ALTER TABLE ONLY runtime.audit_event ATTACH PARTITION runtime.audit_event_default DEFAULT;

ALTER TABLE ONLY config.breakglass_policy
    ADD CONSTRAINT breakglass_policy_name_key UNIQUE (name);

ALTER TABLE ONLY config.breakglass_policy
    ADD CONSTRAINT breakglass_policy_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.ca_config
    ADD CONSTRAINT ca_config_name_key UNIQUE (name);

ALTER TABLE ONLY config.ca_config
    ADD CONSTRAINT ca_config_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.capability_def
    ADD CONSTRAINT capability_def_name_key UNIQUE (name);

ALTER TABLE ONLY config.capability_def
    ADD CONSTRAINT capability_def_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.dp_rule
    ADD CONSTRAINT dp_rule_name_key UNIQUE (name);

ALTER TABLE ONLY config.dp_rule
    ADD CONSTRAINT dp_rule_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.jit_policy
    ADD CONSTRAINT jit_policy_name_key UNIQUE (name);

ALTER TABLE ONLY config.jit_policy
    ADD CONSTRAINT jit_policy_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.node_policy
    ADD CONSTRAINT node_policy_name_key UNIQUE (name);

ALTER TABLE ONLY config.node_policy
    ADD CONSTRAINT node_policy_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.operator_settings
    ADD CONSTRAINT operator_settings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.operator_settings
    ADD CONSTRAINT operator_settings_singleton_key UNIQUE (singleton);

ALTER TABLE ONLY config.platform_role
    ADD CONSTRAINT platform_role_name_key UNIQUE (name);

ALTER TABLE ONLY config.platform_role
    ADD CONSTRAINT platform_role_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.policy_epoch
    ADD CONSTRAINT policy_epoch_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.policy_epoch
    ADD CONSTRAINT policy_epoch_singleton_key UNIQUE (singleton);

ALTER TABLE ONLY config.role_binding
    ADD CONSTRAINT role_binding_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.role_binding
    ADD CONSTRAINT role_binding_role_id_subject_kind_subject_key UNIQUE (role_id, subject_kind, subject);

ALTER TABLE ONLY config.service_account
    ADD CONSTRAINT service_account_name_key UNIQUE (name);

ALTER TABLE ONLY config.service_account
    ADD CONSTRAINT service_account_pkey PRIMARY KEY (id);

ALTER TABLE ONLY config.session_limit_policy
    ADD CONSTRAINT session_limit_policy_name_key UNIQUE (name);

ALTER TABLE ONLY config.session_limit_policy
    ADD CONSTRAINT session_limit_policy_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.access_lock
    ADD CONSTRAINT access_lock_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.agent_identity
    ADD CONSTRAINT agent_identity_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.agent_renewal_receipt
    ADD CONSTRAINT agent_renewal_receipt_agent_id_prior_generation_csr_public__key UNIQUE (agent_id, prior_generation, csr_public_key_hash);

ALTER TABLE ONLY runtime.agent_renewal_receipt
    ADD CONSTRAINT agent_renewal_receipt_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.audit_event
    ADD CONSTRAINT audit_event_pkey PRIMARY KEY (id, occurred_at);

ALTER TABLE ONLY runtime.audit_event_default
    ADD CONSTRAINT audit_event_default_pkey PRIMARY KEY (id, occurred_at);

ALTER TABLE ONLY runtime.auth_rate_limit
    ADD CONSTRAINT auth_rate_limit_pkey PRIMARY KEY (bucket);

ALTER TABLE ONLY runtime.breakglass_activation
    ADD CONSTRAINT breakglass_activation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.breakglass_credential
    ADD CONSTRAINT breakglass_credential_key_fingerprint_key UNIQUE (key_fingerprint);

ALTER TABLE ONLY runtime.breakglass_credential
    ADD CONSTRAINT breakglass_credential_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.breakglass_offline_code
    ADD CONSTRAINT breakglass_offline_code_code_hash_key UNIQUE (code_hash);

ALTER TABLE ONLY runtime.breakglass_offline_code
    ADD CONSTRAINT breakglass_offline_code_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.breakglass_token
    ADD CONSTRAINT breakglass_token_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.breakglass_token
    ADD CONSTRAINT breakglass_token_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY runtime.ca_key_material
    ADD CONSTRAINT ca_key_material_ca_config_id_key UNIQUE (ca_config_id);

ALTER TABLE ONLY runtime.ca_key_material
    ADD CONSTRAINT ca_key_material_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.consumed_assertion
    ADD CONSTRAINT consumed_assertion_pkey PRIMARY KEY (jti_hash);

ALTER TABLE ONLY runtime.device_flow
    ADD CONSTRAINT device_flow_device_code_hash_key UNIQUE (device_code_hash);

ALTER TABLE ONLY runtime.device_flow
    ADD CONSTRAINT device_flow_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.gateway_enrollment_token
    ADD CONSTRAINT gateway_enrollment_token_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.gateway_enrollment_token
    ADD CONSTRAINT gateway_enrollment_token_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY runtime.gateway_identity
    ADD CONSTRAINT gateway_identity_name_key UNIQUE (name);

ALTER TABLE ONLY runtime.gateway_identity
    ADD CONSTRAINT gateway_identity_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.idempotency_key
    ADD CONSTRAINT idempotency_key_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.idempotency_key
    ADD CONSTRAINT idempotency_key_principal_method_path_idempotency_key_key UNIQUE (principal, method, path, idempotency_key);

ALTER TABLE ONLY runtime.jit_request
    ADD CONSTRAINT jit_request_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.join_token
    ADD CONSTRAINT join_token_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.join_token
    ADD CONSTRAINT join_token_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY runtime.node_host_key
    ADD CONSTRAINT node_host_key_node_id_fingerprint_key UNIQUE (node_id, fingerprint);

ALTER TABLE ONLY runtime.node_host_key
    ADD CONSTRAINT node_host_key_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.node
    ADD CONSTRAINT node_name_key UNIQUE (name);

ALTER TABLE ONLY runtime.node
    ADD CONSTRAINT node_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.oidc_login
    ADD CONSTRAINT oidc_login_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.oidc_login
    ADD CONSTRAINT oidc_login_state_hash_key UNIQUE (state_hash);

ALTER TABLE ONLY runtime.otp
    ADD CONSTRAINT otp_otp_hash_key UNIQUE (otp_hash);

ALTER TABLE ONLY runtime.otp
    ADD CONSTRAINT otp_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.pin
    ADD CONSTRAINT pin_fingerprint_identity_key UNIQUE (fingerprint, identity);

ALTER TABLE ONLY runtime.pin
    ADD CONSTRAINT pin_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.presence
    ADD CONSTRAINT presence_pkey PRIMARY KEY (node_id);

ALTER TABLE ONLY runtime.recording_ref
    ADD CONSTRAINT recording_ref_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.recording_ref
    ADD CONSTRAINT recording_ref_session_id_key UNIQUE (session_id);

ALTER TABLE ONLY runtime.recording_token
    ADD CONSTRAINT recording_token_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.recording_token
    ADD CONSTRAINT recording_token_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY runtime.service_account_credential
    ADD CONSTRAINT service_account_credential_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.session_lease
    ADD CONSTRAINT session_lease_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.session_signing_token
    ADD CONSTRAINT session_signing_token_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runtime.session_signing_token
    ADD CONSTRAINT session_signing_token_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY runtime.ssh_session
    ADD CONSTRAINT ssh_session_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX uq_ca_config_active_per_kind ON config.ca_config USING btree (ca_kind) WHERE (rotation_state = 'active'::text);

CREATE UNIQUE INDEX uq_ca_config_incoming_per_kind ON config.ca_config USING btree (ca_kind) WHERE (rotation_state = 'incoming'::text);

CREATE INDEX agent_renewal_receipt_expires_idx ON runtime.agent_renewal_receipt USING btree (expires_at);

CREATE INDEX idx_audit_access_model ON ONLY runtime.audit_event USING btree (access_model);

CREATE INDEX audit_event_default_access_model_idx ON runtime.audit_event_default USING btree (access_model);

CREATE INDEX idx_audit_actor ON ONLY runtime.audit_event USING btree (actor);

CREATE INDEX audit_event_default_actor_idx ON runtime.audit_event_default USING btree (actor);

CREATE INDEX idx_audit_capabilities ON ONLY runtime.audit_event USING gin (capabilities);

CREATE INDEX audit_event_default_capabilities_idx ON runtime.audit_event_default USING gin (capabilities);

CREATE INDEX idx_audit_correlation ON ONLY runtime.audit_event USING btree (correlation_id);

CREATE INDEX audit_event_default_correlation_id_idx ON runtime.audit_event_default USING btree (correlation_id);

CREATE INDEX idx_audit_node ON ONLY runtime.audit_event USING btree (node_id);

CREATE INDEX audit_event_default_node_id_idx ON runtime.audit_event_default USING btree (node_id);

CREATE INDEX idx_audit_node_labels ON ONLY runtime.audit_event USING gin (node_labels);

CREATE INDEX audit_event_default_node_labels_idx ON runtime.audit_event_default USING gin (node_labels);

CREATE INDEX idx_audit_occurred_at ON ONLY runtime.audit_event USING btree (occurred_at);

CREATE INDEX audit_event_default_occurred_at_idx ON runtime.audit_event_default USING btree (occurred_at);

CREATE INDEX idx_audit_chain_head ON ONLY runtime.audit_event USING btree (seq DESC) WHERE (record_hash IS NOT NULL);

CREATE INDEX audit_event_default_seq_idx ON runtime.audit_event_default USING btree (seq DESC) WHERE (record_hash IS NOT NULL);

CREATE UNIQUE INDEX uq_audit_seq ON ONLY runtime.audit_event USING btree (seq, occurred_at);

CREATE UNIQUE INDEX audit_event_default_seq_occurred_at_idx ON runtime.audit_event_default USING btree (seq, occurred_at);

CREATE INDEX idx_audit_session ON ONLY runtime.audit_event USING btree (session_id);

CREATE INDEX audit_event_default_session_id_idx ON runtime.audit_event_default USING btree (session_id);

CREATE INDEX idx_audit_source_ip ON ONLY runtime.audit_event USING btree (source_ip);

CREATE INDEX audit_event_default_source_ip_idx ON runtime.audit_event_default USING btree (source_ip);

CREATE INDEX idx_audit_subject ON ONLY runtime.audit_event USING btree (subject);

CREATE INDEX audit_event_default_subject_idx ON runtime.audit_event_default USING btree (subject);

CREATE INDEX idempotency_key_expires_idx ON runtime.idempotency_key USING btree (expires_at);

CREATE INDEX idx_agent_identity_node ON runtime.agent_identity USING btree (node_id);

CREATE INDEX idx_breakglass_credential_identity ON runtime.breakglass_credential USING btree (identity);

CREATE INDEX idx_breakglass_offline_code_identity ON runtime.breakglass_offline_code USING btree (identity);

CREATE INDEX idx_breakglass_token_gateway ON runtime.breakglass_token USING btree (gateway_id);

CREATE INDEX idx_ca_key_material_config ON runtime.ca_key_material USING btree (ca_config_id);

CREATE INDEX idx_consumed_assertion_not_after ON runtime.consumed_assertion USING btree (not_after);

CREATE INDEX idx_device_flow_expires ON runtime.device_flow USING btree (expires_at) WHERE (status = 'pending'::text);

CREATE INDEX idx_gateway_enrollment_token_gateway ON runtime.gateway_enrollment_token USING btree (gateway_name);

CREATE INDEX idx_jit_request_requester ON runtime.jit_request USING btree (requester);

CREATE INDEX idx_jit_request_state ON runtime.jit_request USING btree (state);

CREATE INDEX idx_jit_request_target ON runtime.jit_request USING btree (target_node_id);

CREATE INDEX idx_jit_request_usable ON runtime.jit_request USING btree (requester, target_node_id, principal, grant_expires_at) WHERE (state = ANY (ARRAY['APPROVED'::text, 'ACTIVE'::text]));

COMMENT ON INDEX runtime.idx_jit_request_usable IS 'Backs JitRequestRepository.findUsableGrant: a point lookup instead of a per-requester scan.';

CREATE INDEX idx_join_token_expires ON runtime.join_token USING btree (expires_at) WHERE (consumed_at IS NULL);

CREATE INDEX idx_join_token_node ON runtime.join_token USING btree (node_id);

CREATE INDEX idx_lock_expires_at ON runtime.access_lock USING btree (expires_at);

CREATE INDEX idx_node_host_key_node ON runtime.node_host_key USING btree (node_id);

CREATE INDEX idx_node_status ON runtime.node USING btree (status);

CREATE INDEX idx_oidc_login_device_flow ON runtime.oidc_login USING btree (device_flow_id);

CREATE INDEX idx_oidc_login_expires ON runtime.oidc_login USING btree (expires_at) WHERE (status = 'pending'::text);

CREATE INDEX idx_otp_expires ON runtime.otp USING btree (expires_at) WHERE (used = false);

CREATE INDEX idx_pin_identity ON runtime.pin USING btree (identity);

CREATE INDEX idx_presence_owning_gateway ON runtime.presence USING btree (owning_gateway);

CREATE INDEX idx_recording_retention ON runtime.recording_ref USING btree (retention_until) WHERE (legal_hold = false);

CREATE INDEX idx_recording_token_gateway ON runtime.recording_token USING btree (gateway_id);

CREATE INDEX idx_sac_service_account ON runtime.service_account_credential USING btree (service_account_id);

CREATE INDEX idx_session_access_model ON runtime.ssh_session USING btree (access_model);

CREATE INDEX idx_session_breakglass ON runtime.ssh_session USING btree (breakglass_activation_id);

CREATE INDEX idx_session_gateway ON runtime.ssh_session USING btree (gateway_id);

CREATE INDEX idx_session_identity ON runtime.ssh_session USING btree (identity);

CREATE INDEX idx_session_jit_request ON runtime.ssh_session USING btree (jit_request_id);

CREATE INDEX idx_session_lease_live ON runtime.session_lease USING btree (identity) WHERE (released_at IS NULL);

CREATE INDEX idx_session_lease_session ON runtime.session_lease USING btree (session_id);

CREATE INDEX idx_session_live ON runtime.ssh_session USING btree (node_id) WHERE (ended_at IS NULL);

CREATE INDEX idx_session_node ON runtime.ssh_session USING btree (node_id);

CREATE INDEX idx_session_signing_token_gateway ON runtime.session_signing_token USING btree (gateway_id);

CREATE INDEX idx_session_started_at ON runtime.ssh_session USING btree (started_at);

CREATE INDEX ix_ssh_session_active_identity ON runtime.ssh_session USING btree (identity) WHERE (ended_at IS NULL);

CREATE UNIQUE INDEX uq_agent_identity_active_per_node ON runtime.agent_identity USING btree (node_id) WHERE (status = 'active'::text);

CREATE UNIQUE INDEX uq_node_host_key_host_ca_cert ON runtime.node_host_key USING btree (node_id, md5(host_cert_ref)) WHERE ((source = 'host_ca'::text) AND (host_cert_ref IS NOT NULL));

CREATE UNIQUE INDEX uq_sac_active_secret_hash ON runtime.service_account_credential USING btree (secret_hash) WHERE (status = 'active'::text);

ALTER INDEX runtime.idx_audit_access_model ATTACH PARTITION runtime.audit_event_default_access_model_idx;

ALTER INDEX runtime.idx_audit_actor ATTACH PARTITION runtime.audit_event_default_actor_idx;

ALTER INDEX runtime.idx_audit_capabilities ATTACH PARTITION runtime.audit_event_default_capabilities_idx;

ALTER INDEX runtime.idx_audit_correlation ATTACH PARTITION runtime.audit_event_default_correlation_id_idx;

ALTER INDEX runtime.idx_audit_node ATTACH PARTITION runtime.audit_event_default_node_id_idx;

ALTER INDEX runtime.idx_audit_node_labels ATTACH PARTITION runtime.audit_event_default_node_labels_idx;

ALTER INDEX runtime.idx_audit_occurred_at ATTACH PARTITION runtime.audit_event_default_occurred_at_idx;

ALTER INDEX runtime.audit_event_pkey ATTACH PARTITION runtime.audit_event_default_pkey;

ALTER INDEX runtime.idx_audit_chain_head ATTACH PARTITION runtime.audit_event_default_seq_idx;

ALTER INDEX runtime.uq_audit_seq ATTACH PARTITION runtime.audit_event_default_seq_occurred_at_idx;

ALTER INDEX runtime.idx_audit_session ATTACH PARTITION runtime.audit_event_default_session_id_idx;

ALTER INDEX runtime.idx_audit_source_ip ATTACH PARTITION runtime.audit_event_default_source_ip_idx;

ALTER INDEX runtime.idx_audit_subject ATTACH PARTITION runtime.audit_event_default_subject_idx;

CREATE TRIGGER policy_epoch_monotonic BEFORE UPDATE ON config.policy_epoch FOR EACH ROW EXECUTE FUNCTION config.enforce_policy_epoch_monotonic();

CREATE TRIGGER agent_identity_generation_monotonic BEFORE UPDATE ON runtime.agent_identity FOR EACH ROW EXECUTE FUNCTION runtime.enforce_generation_monotonic();

CREATE TRIGGER audit_event_no_truncate BEFORE TRUNCATE ON runtime.audit_event FOR EACH STATEMENT EXECUTE FUNCTION runtime.audit_event_immutable();

CREATE TRIGGER audit_event_no_update_delete BEFORE DELETE OR UPDATE ON runtime.audit_event FOR EACH ROW EXECUTE FUNCTION runtime.audit_event_immutable();

CREATE TRIGGER ca_key_material_write_once BEFORE UPDATE ON runtime.ca_key_material FOR EACH ROW EXECUTE FUNCTION runtime.enforce_ca_key_material_write_once();

CREATE TRIGGER gateway_identity_generation_monotonic BEFORE UPDATE ON runtime.gateway_identity FOR EACH ROW EXECUTE FUNCTION runtime.enforce_generation_monotonic();

CREATE TRIGGER presence_nonce_monotonic BEFORE UPDATE ON runtime.presence FOR EACH ROW EXECUTE FUNCTION runtime.enforce_presence_nonce_monotonic();

CREATE TRIGGER recording_ref_write_once BEFORE UPDATE ON runtime.recording_ref FOR EACH ROW EXECUTE FUNCTION runtime.enforce_recording_ref_write_once();

ALTER TABLE ONLY config.role_binding
    ADD CONSTRAINT role_binding_role_id_fkey FOREIGN KEY (role_id) REFERENCES config.platform_role(id) ON DELETE CASCADE;

ALTER TABLE ONLY runtime.agent_identity
    ADD CONSTRAINT agent_identity_node_id_fkey FOREIGN KEY (node_id) REFERENCES runtime.node(id) ON DELETE CASCADE;

ALTER TABLE ONLY runtime.agent_renewal_receipt
    ADD CONSTRAINT agent_renewal_receipt_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES runtime.agent_identity(id) ON DELETE CASCADE;

ALTER TABLE ONLY runtime.jit_request
    ADD CONSTRAINT jit_request_target_node_id_fkey FOREIGN KEY (target_node_id) REFERENCES runtime.node(id) ON DELETE SET NULL;

ALTER TABLE ONLY runtime.join_token
    ADD CONSTRAINT join_token_node_id_fkey FOREIGN KEY (node_id) REFERENCES runtime.node(id) ON DELETE SET NULL;

ALTER TABLE ONLY runtime.node_host_key
    ADD CONSTRAINT node_host_key_node_id_fkey FOREIGN KEY (node_id) REFERENCES runtime.node(id) ON DELETE CASCADE;

ALTER TABLE ONLY runtime.oidc_login
    ADD CONSTRAINT oidc_login_device_flow_id_fkey FOREIGN KEY (device_flow_id) REFERENCES runtime.device_flow(id) ON DELETE CASCADE;

ALTER TABLE ONLY runtime.presence
    ADD CONSTRAINT presence_node_id_fkey FOREIGN KEY (node_id) REFERENCES runtime.node(id) ON DELETE CASCADE;

ALTER TABLE ONLY runtime.recording_ref
    ADD CONSTRAINT recording_ref_session_id_fkey FOREIGN KEY (session_id) REFERENCES runtime.ssh_session(id) ON DELETE RESTRICT;

ALTER TABLE ONLY runtime.session_lease
    ADD CONSTRAINT session_lease_session_id_fkey FOREIGN KEY (session_id) REFERENCES runtime.ssh_session(id) ON DELETE SET NULL;

ALTER TABLE ONLY runtime.ssh_session
    ADD CONSTRAINT ssh_session_breakglass_activation_fk FOREIGN KEY (breakglass_activation_id) REFERENCES runtime.breakglass_activation(id) ON DELETE SET NULL;

ALTER TABLE ONLY runtime.ssh_session
    ADD CONSTRAINT ssh_session_gateway_id_fkey FOREIGN KEY (gateway_id) REFERENCES runtime.gateway_identity(id) ON DELETE SET NULL;

ALTER TABLE ONLY runtime.ssh_session
    ADD CONSTRAINT ssh_session_jit_request_id_fkey FOREIGN KEY (jit_request_id) REFERENCES runtime.jit_request(id) ON DELETE SET NULL;

ALTER TABLE ONLY runtime.ssh_session
    ADD CONSTRAINT ssh_session_node_id_fkey FOREIGN KEY (node_id) REFERENCES runtime.node(id) ON DELETE SET NULL;

GRANT USAGE ON SCHEMA config TO cp_runtime;

GRANT USAGE ON SCHEMA runtime TO cp_runtime;

REVOKE ALL ON FUNCTION config.enforce_policy_epoch_monotonic() FROM PUBLIC;

REVOKE ALL ON FUNCTION runtime.audit_ensure_partition(month_start date) FROM PUBLIC;
GRANT ALL ON FUNCTION runtime.audit_ensure_partition(month_start date) TO cp_runtime;

REVOKE ALL ON FUNCTION runtime.audit_ensure_partitions(from_month date, num_months integer) FROM PUBLIC;
GRANT ALL ON FUNCTION runtime.audit_ensure_partitions(from_month date, num_months integer) TO cp_runtime;

REVOKE ALL ON FUNCTION runtime.audit_event_immutable() FROM PUBLIC;

REVOKE ALL ON FUNCTION runtime.audit_prune_before(cutoff timestamp with time zone) FROM PUBLIC;

REVOKE ALL ON FUNCTION runtime.enforce_ca_key_material_write_once() FROM PUBLIC;

REVOKE ALL ON FUNCTION runtime.enforce_generation_monotonic() FROM PUBLIC;

REVOKE ALL ON FUNCTION runtime.enforce_presence_nonce_monotonic() FROM PUBLIC;

REVOKE ALL ON FUNCTION runtime.enforce_recording_ref_write_once() FROM PUBLIC;

REVOKE ALL ON FUNCTION runtime.is_ip_or_cidr(value text) FROM PUBLIC;
GRANT ALL ON FUNCTION runtime.is_ip_or_cidr(value text) TO cp_runtime;

REVOKE ALL ON FUNCTION runtime.recording_prunable(cutoff timestamp with time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION runtime.recording_prunable(cutoff timestamp with time zone) TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.breakglass_policy TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.ca_config TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.capability_def TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.dp_rule TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.jit_policy TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.node_policy TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.operator_settings TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.platform_role TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.policy_epoch TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.role_binding TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.service_account TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE config.session_limit_policy TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.access_lock TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.agent_identity TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.agent_renewal_receipt TO cp_runtime;

GRANT SELECT,INSERT ON TABLE runtime.audit_event TO cp_runtime;

GRANT SELECT,INSERT ON TABLE runtime.audit_event_default TO cp_runtime;

GRANT SELECT,USAGE ON SEQUENCE runtime.audit_event_seq_seq TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.auth_rate_limit TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.breakglass_activation TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.breakglass_credential TO cp_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE runtime.breakglass_offline_code TO cp_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE runtime.breakglass_token TO cp_runtime;

GRANT SELECT,INSERT ON TABLE runtime.ca_key_material TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.consumed_assertion TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.device_flow TO cp_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE runtime.gateway_enrollment_token TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.gateway_identity TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.idempotency_key TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.jit_request TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.join_token TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.node TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.node_host_key TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.oidc_login TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.otp TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.pin TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.presence TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.recording_ref TO cp_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE runtime.recording_token TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.service_account_credential TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.session_lease TO cp_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE runtime.session_signing_token TO cp_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE runtime.ssh_session TO cp_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA config GRANT SELECT,USAGE ON SEQUENCES TO cp_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA config GRANT SELECT,INSERT,DELETE,UPDATE ON TABLES TO cp_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA runtime GRANT SELECT,USAGE ON SEQUENCES TO cp_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA runtime GRANT SELECT,INSERT,DELETE,UPDATE ON TABLES TO cp_runtime;

DO $fh$
BEGIN
    IF to_regclass('public.flyway_schema_history') IS NOT NULL THEN
        EXECUTE 'GRANT SELECT ON public.flyway_schema_history TO cp_runtime';
    END IF;
END
$fh$;

-- Create-ahead, not a frozen list: partition bounds are relative to the install date,
-- so a dumped set of audit_event_YYYYMM tables would be stale for every cluster
-- installed after this file was generated. 6 months back + ~13 ahead covers
-- back-dated events and gives the scheduled job headroom.
SELECT runtime.audit_ensure_partitions((date_trunc('month', now()) - interval '6 months')::date, 19);
