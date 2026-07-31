-- V28 — The gateway:enroll permission.
-- SessionLayer Control Plane. Forward-only, additive; V1-V27 unchanged.
--
-- config.platform_role gains gateway:enroll (Design §4.B; FR-JOIN-3): the verb
-- gating the Gateway enrollment-token API and the internal mTLS trust-anchor
-- export, so installing a Gateway needs an API credential rather than the raw
-- psql the install guide required (which the hardening guide tells the same
-- operator to lock away). It is deliberately distinct from ca:manage — exporting
-- the public trust anchor is not CA administration.
--
-- Extends the closed vocabulary CHECK the same way V18/V20/V23 did (drop +
-- recreate; existing roles stay a subset). The first-admin bootstrap role carries
-- every PlatformPermissions.ALL entry, so this CHECK and that set must stay in
-- lockstep or bootstrap breaks.
ALTER TABLE config.platform_role DROP CONSTRAINT platform_role_permissions_check;
ALTER TABLE config.platform_role
    ADD CONSTRAINT platform_role_permissions_check
    CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll', 'gateway:enroll',
        'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
        'audit:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[]);
