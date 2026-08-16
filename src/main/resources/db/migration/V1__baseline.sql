-- Intentionally a no-op. Its only job is to prove Flyway runs end-to-end at
-- startup (creating flyway_schema_history and recording version 1). The real
-- schema (config-vs-runtime entities) lands in V2 and later. Do NOT add
-- application tables here.
SELECT 1;
