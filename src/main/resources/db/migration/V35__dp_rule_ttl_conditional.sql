-- V35 — config.dp_rule.ttl_seconds is required for an allow and absent for a deny.
-- SessionLayer Control Plane.
--
-- ttl_seconds was NOT NULL for every rule, but only an allow has a lifetime to
-- bound: a deny grants nothing and is in force until the rule is changed. Operators
-- writing a deny had to invent a number, and omitting it produced a bare framework
-- 400 that named no field at all.
--
-- Written so that EVERY row that exists today already satisfies it. Existing deny
-- rules carry real values (some as small as 1) because the column demanded one, and
-- a migration that failed on them would break startup on exactly the deployments
-- that have the problem. So the CHECK permits a deny row to carry a positive value
-- OR no value, and only constrains an allow — which must still carry a positive
-- one, exactly as before.
ALTER TABLE config.dp_rule ALTER COLUMN ttl_seconds DROP NOT NULL;

-- The old inline CHECK (ttl_seconds > 0) is NULL-tolerant already: a NULL makes it
-- evaluate to NULL, which a CHECK treats as satisfied. It stays as the positivity
-- rule; this constraint adds the effect-conditional requirement it never expressed.
ALTER TABLE config.dp_rule ADD CONSTRAINT dp_rule_allow_requires_ttl
    CHECK (effect <> 'allow' OR ttl_seconds IS NOT NULL);

COMMENT ON COLUMN config.dp_rule.ttl_seconds IS
    'The granted access''s lifetime in seconds. Required for an allow, where it bounds the grant; NULL for a deny, which grants nothing and so has no lifetime to bound. The API drops any value sent on a deny rather than storing a number that means nothing. There is no default: an unbounded grant is never inferred from an omitted value.';
