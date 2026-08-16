DROP TABLE runtime.audit_event;

CREATE TABLE runtime.audit_event (
    id             uuid        NOT NULL,
    seq            bigint      GENERATED ALWAYS AS IDENTITY,
    occurred_at    timestamptz NOT NULL,
    actor          text        NOT NULL,
    subject        text,
    action         text        NOT NULL,
    outcome        text        NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'error')),
    correlation_id uuid,
    session_id     uuid,
    node_id        uuid,
    node_labels    jsonb       CHECK (node_labels IS NULL OR jsonb_typeof(node_labels) = 'object'),
    source_ip      text        CHECK (source_ip IS NULL OR runtime.is_ip_or_cidr(source_ip)),
    access_model   text        CHECK (access_model IS NULL OR access_model IN ('standing', 'jit', 'breakglass')),
    capabilities   text[]      CHECK (capabilities IS NULL OR capabilities <@ ARRAY['shell', 'exec',
                                   'sftp', 'scp', 'port_forward_local', 'port_forward_remote',
                                   'agent_forward', 'x11']::text[]),
    detail         jsonb       CHECK (detail IS NULL OR jsonb_typeof(detail) = 'object'),
    prev_hash      text,
    record_hash    text,
    version        bigint      NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- Composite PK: Postgres requires the partition key (occurred_at) in the PK.
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE runtime.audit_event IS 'Design §12.2 / FR-AUD-9: single correlated audit stream. PARTITION BY RANGE(occurred_at) for FR-AUD-6 retention (drop old partitions, no DELETE). Append-only trigger + seq chain order re-applied. Composite PK (id, occurred_at); id alone is globally unique (UUIDv7). Hash-chain cols are application-populated.';

-- BEFORE ROW triggers on a partitioned parent are cloned to every current and future
-- partition automatically (PG 13+), so a stray UPDATE/DELETE on any partition — via the
-- parent or directly — is rejected.
CREATE TRIGGER audit_event_no_update_delete
    BEFORE UPDATE OR DELETE ON runtime.audit_event
    FOR EACH ROW EXECUTE FUNCTION runtime.audit_event_immutable();
-- TRUNCATE fires only on the table named; TRUNCATE of the parent cascades to partitions.
CREATE TRIGGER audit_event_no_truncate
    BEFORE TRUNCATE ON runtime.audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION runtime.audit_event_immutable();

CREATE UNIQUE INDEX uq_audit_seq        ON runtime.audit_event (seq, occurred_at);
CREATE INDEX idx_audit_actor            ON runtime.audit_event (actor);
CREATE INDEX idx_audit_subject          ON runtime.audit_event (subject);
CREATE INDEX idx_audit_node             ON runtime.audit_event (node_id);
CREATE INDEX idx_audit_occurred_at      ON runtime.audit_event (occurred_at);
CREATE INDEX idx_audit_source_ip        ON runtime.audit_event (source_ip);
CREATE INDEX idx_audit_access_model     ON runtime.audit_event (access_model);
CREATE INDEX idx_audit_correlation      ON runtime.audit_event (correlation_id);
CREATE INDEX idx_audit_session          ON runtime.audit_event (session_id);
CREATE INDEX idx_audit_capabilities     ON runtime.audit_event USING gin (capabilities);
CREATE INDEX idx_audit_node_labels      ON runtime.audit_event USING gin (node_labels);

CREATE OR REPLACE FUNCTION runtime.audit_ensure_partition(month_start date)
    RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, runtime AS $$
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
COMMENT ON FUNCTION runtime.audit_ensure_partition(date) IS 'Create-ahead a monthly audit_event partition (idempotent); locks it to INSERT/SELECT for cp_runtime. SECURITY DEFINER so the restricted role can pre-create without DDL rights.';

CREATE OR REPLACE FUNCTION runtime.audit_ensure_partitions(from_month date, num_months integer)
    RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, runtime AS $$
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
COMMENT ON FUNCTION runtime.audit_ensure_partitions(date, integer) IS 'Create-ahead num_months monthly audit_event partitions from from_month (idempotent).';

-- SECURITY DEFINER (owner) so the runtime role can trigger retention without holding
-- DROP; authorization for it is the app layer's settings:write check.
CREATE OR REPLACE FUNCTION runtime.audit_prune_before(cutoff timestamptz)
    RETURNS text[]
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, runtime AS $$
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
$$;
COMMENT ON FUNCTION runtime.audit_prune_before(timestamptz) IS 'FR-AUD-6 retention: DETACH+DROP audit_event monthly partitions entirely older than cutoff. Returns dropped partition names.';

CREATE TABLE runtime.audit_event_default PARTITION OF runtime.audit_event DEFAULT;
COMMENT ON TABLE runtime.audit_event_default IS 'Catch-all audit partition: guarantees an append-only insert never fails for a missing range. Keep empty by create-ahead; not dropped by audit_prune_before.';

-- 6 months back + ~13 ahead: covers back-dated events and create-ahead headroom.
SELECT runtime.audit_ensure_partitions((date_trunc('month', now()) - interval '6 months')::date, 19);
