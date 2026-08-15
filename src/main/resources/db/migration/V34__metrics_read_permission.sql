-- V34 — metrics:read joins the closed platform-permission vocabulary.
-- SessionLayer Control Plane.
--
-- /actuator/prometheus and /actuator/metrics were authenticated but not
-- authorized: any token the platform had ever issued could read the whole meter
-- set — fleet-wide live-session counts, authorization error rates, CA-signer
-- activity, session-limit denials — including a token minted for a service account
-- with no role binding at all.
--
-- A member of its own rather than a reuse of audit:read, deliberately: a Prometheus
-- scraper holding audit:read could read the entire audit trail, which is a worse
-- exposure than the one being closed.
--
-- Extends the CHECK exactly as V18/V20/V23/V28/V29 did (drop + recreate; existing
-- roles stay a subset). The CHECK and PlatformPermissions.ALL must stay in
-- lockstep, because BootstrapService.ensureAdminRole() inserts platform-admin
-- carrying ALL — a divergence makes first-admin bootstrap violate this constraint
-- at boot. MigrationIntegrityIT asserts the lockstep.
ALTER TABLE config.platform_role DROP CONSTRAINT platform_role_permissions_check;
ALTER TABLE config.platform_role
    ADD CONSTRAINT platform_role_permissions_check
    CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll', 'gateway:enroll',
        'gateway:remove', 'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
        'recording:key-manage', 'audit:read', 'metrics:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[]);

-- The back-fill reconciles the seeded role against the WHOLE vocabulary, not
-- against this migration's one addition. That is the behaviour being inherited from
-- V29, and it is the point rather than the shape: V18, V20, V23 and V28 each
-- widened the CHECK and granted nothing, so an upgraded deployment's platform admin
-- silently lacked every new verb until V29 reconciled the full set in one pass.
-- Listing only 'metrics:read' here would grant it correctly today and put the NEXT
-- vocabulary migration straight back into that position.
--
-- Scoped to origin = 'default', i.e. the row the bootstrap seeded and no one has
-- edited through /v1/roles (origin flips to 'api' on any API write). Restoring a
-- permission an operator deliberately removed would be the worse failure; such a
-- deployment grants the verb through /v1/roles like any other, and BootstrapService
-- warns at boot when the seeded row is missing vocabulary.
--
-- Idempotent by construction: a role already holding the whole vocabulary is not
-- matched, so a re-run is a no-op. The widened CHECK above runs first, so this
-- UPDATE would itself fail loudly if the two lists ever diverged.
UPDATE config.platform_role
SET permissions = ARRAY(SELECT DISTINCT p FROM unnest(permissions
        || ARRAY['rbac:read', 'rbac:write', 'node:enroll', 'gateway:enroll',
            'gateway:remove', 'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
            'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
            'recording:key-manage', 'audit:read', 'metrics:read', 'user:manage', 'settings:write',
            'lock:read', 'lock:write', 'breakglass:manage']::text[]) AS p ORDER BY p),
    version = version + 1,
    updated_at = now()
WHERE name = 'platform-admin'
  AND origin = 'default'
  AND NOT (ARRAY['rbac:read', 'rbac:write', 'node:enroll', 'gateway:enroll',
        'gateway:remove', 'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
        'recording:key-manage', 'audit:read', 'metrics:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[] <@ permissions);
