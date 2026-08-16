-- metrics:read is a member of its own rather than a reuse of audit:read,
-- deliberately: a Prometheus scraper holding audit:read could read the entire audit
-- trail, which is a worse exposure than the one being closed.
ALTER TABLE config.platform_role DROP CONSTRAINT platform_role_permissions_check;
ALTER TABLE config.platform_role
    ADD CONSTRAINT platform_role_permissions_check
    CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll', 'gateway:enroll',
        'gateway:remove', 'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
        'recording:key-manage', 'audit:read', 'metrics:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[]);

-- The back-fill reconciles the seeded role against the WHOLE vocabulary, not against
-- this migration's one addition. Listing only 'metrics:read' here would grant it
-- correctly today and put the NEXT vocabulary migration straight back into the
-- position V18, V20, V23 and V28 were in: widening the CHECK and granting nothing.
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
