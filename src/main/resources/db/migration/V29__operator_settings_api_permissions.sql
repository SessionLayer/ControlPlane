-- 1. recording:key-manage gates PUT /v1/operator-settings/recording-customer-key,
--    which provisions the customer public key every recording is sealed to. It is
--    deliberately NOT settings:write and NOT ca:manage. Its holder can point future
--    recordings at a key whose private half they control, which is a privilege of a
--    different kind from data-plane grant administration -- folding it into
--    settings:write would hand every config administrator the ability to break the
--    property that the platform cannot read its own recordings.
--
-- 2. gateway:remove gates DELETE /v1/gateways/{gatewayId}. Removing a Gateway
--    identity is destructive in a way enrolling one is not: a removed identity is
--    refused immediately by ConnectAuthorizationService.requireActiveGateway and by
--    the lock-feed and presence paths, so the deletion stops that Gateway
--    authorizing sessions at once.
--
-- 3. The back-fill. BootstrapService.ensureAdminRole() creates platform-admin only
--    when it is absent, and runAtStartup() returns early once bootstrap_completed is
--    set, so an already-bootstrapped deployment's admin role is never revisited.
--    Every vocabulary-extending migration since V18 (lock:read/lock:write), V20
--    (breakglass:manage), V23 (recording:delete) and V28 (gateway:enroll) widened the
--    CHECK without granting the new verb to the seeded role, so an upgraded
--    deployment's platform admin silently lacks them -- most visibly, it cannot
--    enroll a Gateway. Append every missing entry once, here.
--
--    Scoped to origin = 'default', i.e. the row the bootstrap seeded and no one has
--    edited through /v1/roles. A role an operator has curated (origin flips to 'api'
--    on any API write) is left alone: restoring a permission that was deliberately
--    removed would be the worse failure. Such a deployment grants the verb through
--    /v1/roles like any other, and BootstrapService warns at boot when the seeded row
--    is missing vocabulary.
--
-- 4. config.ca_config.algorithm gains ecdsa-p521. CaKeyType implements P-256, P-384
--    and P-521, but the CHECK admitted only the first two of those -- a fully working
--    algorithm was unreachable. The CHECK is WIDENED and never narrowed: it still
--    admits ed25519/rsa-2048/rsa-4096, which CaKeyType cannot assemble, because a row
--    carrying one may already exist on a real deployment and a narrowing migration
--    would fail at startup on exactly the deployment that has the problem.
--    CaConfigService is the stricter gate and rejects an unassemblable algorithm with
--    a 422 before anything is stored.
--
-- The CHECK and PlatformPermissions.ALL must stay in lockstep or the first-admin
-- bootstrap breaks; MigrationIntegrityIT asserts both that lockstep and the back-fill.
ALTER TABLE config.platform_role DROP CONSTRAINT platform_role_permissions_check;
ALTER TABLE config.platform_role
    ADD CONSTRAINT platform_role_permissions_check
    CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll', 'gateway:enroll',
        'gateway:remove', 'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
        'recording:key-manage', 'audit:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[]);

-- Idempotent by construction: a role already holding the whole vocabulary is not
-- matched, so a re-run is a no-op. The widened CHECK above runs first, so this
-- UPDATE would itself fail loudly if the two lists ever diverged.
UPDATE config.platform_role
SET permissions = ARRAY(SELECT DISTINCT p FROM unnest(permissions
        || ARRAY['rbac:read', 'rbac:write', 'node:enroll', 'gateway:enroll',
            'gateway:remove', 'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
            'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
            'recording:key-manage', 'audit:read', 'user:manage', 'settings:write',
            'lock:read', 'lock:write', 'breakglass:manage']::text[]) AS p ORDER BY p),
    version = version + 1,
    updated_at = now()
WHERE name = 'platform-admin'
  AND origin = 'default'
  AND NOT (ARRAY['rbac:read', 'rbac:write', 'node:enroll', 'gateway:enroll',
        'gateway:remove', 'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
        'recording:key-manage', 'audit:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[] <@ permissions);

ALTER TABLE config.ca_config DROP CONSTRAINT ca_config_algorithm_check;
ALTER TABLE config.ca_config
    ADD CONSTRAINT ca_config_algorithm_check
    CHECK (algorithm IN ('ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521', 'ed25519', 'rsa-2048', 'rsa-4096'));
