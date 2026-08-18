-- The values, traced from every writer:
--
--   closed, expired, idle_timeout, locked, error   grpc/AuthorizationService.endReason
--   truncated, error, closed                       recording/RecordingRegistrationService.sessionEndReason
--   gateway_removed                                gateway/GatewayDirectoryService (raw UPDATE)
--
-- Deliberately NOT a CHECK constraint. A value written by a path neither reader found
-- would then fail its INSERT, and failing session-end recording to enforce a
-- documentation claim trades a durable forensic record for tidiness.

COMMENT ON COLUMN runtime.ssh_session.end_reason IS
    'Why the session ended, as an advisory diagnostic - the authoritative "why" for a teardown lives in the decision/lock audit chain. The values the Control Plane writes are: closed (orderly, including a cleanly sealed recording), expired (grant expiry), idle_timeout, locked (a Lock tore it down), error, truncated (the recording did not seal cleanly) and gateway_removed (its Gateway identity was removed out from under it). Not constrained: a CHECK here would fail the session-end write rather than lose a row of documentation.';
