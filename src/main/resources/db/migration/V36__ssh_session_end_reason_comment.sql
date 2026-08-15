-- V36 — restate runtime.ssh_session.end_reason with the values actually written.
-- SessionLayer Control Plane.
--
-- The column comment offered "lock|expiry|quarantine|client|..." and NOT ONE of
-- those four is ever written. The real set, traced from every writer:
--
--   closed, expired, idle_timeout, locked, error   grpc/AuthorizationService.endReason
--   truncated, error, closed                       recording/RecordingRegistrationService.sessionEndReason
--   gateway_removed                                gateway/GatewayDirectoryService (raw UPDATE)
--
-- So an operator filtering sessions on 'lock' or 'expiry' — the values the catalog
-- told them to expect — matched nothing and had no way to see why. COMMENT ON is
-- executed into pg_description, so this string is what \d+ runtime.ssh_session
-- shows on every running cluster: shipped documentation, and it was wrong.
--
-- Deliberately NOT a CHECK constraint. A value written by a path neither reader
-- found would then fail its INSERT, and failing session-end recording to enforce a
-- documentation claim trades a durable forensic record for tidiness. The comment
-- therefore states what the Control Plane writes rather than claiming a closed
-- vocabulary nothing enforces.
--
-- Metadata only: no table, column, constraint or index is created, altered or
-- dropped, and no row is read or written.

COMMENT ON COLUMN runtime.ssh_session.end_reason IS
    'Why the session ended, as an advisory diagnostic — the authoritative "why" for a teardown lives in the decision/lock audit chain. The values the Control Plane writes are: closed (orderly, including a cleanly sealed recording), expired (grant expiry), idle_timeout, locked (a Lock tore it down), error, truncated (the recording did not seal cleanly) and gateway_removed (its Gateway identity was removed out from under it). Not constrained: a CHECK here would fail the session-end write rather than lose a row of documentation.';
