ALTER TABLE config.platform_role DROP CONSTRAINT platform_role_permissions_check;
ALTER TABLE config.platform_role
    ADD CONSTRAINT platform_role_permissions_check
    CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll', 'gateway:enroll',
        'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
        'audit:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[]);
