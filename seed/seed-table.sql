-- Seed the demo Iceberg table once, as its owner alice (a "writer"). Not root/admin: no
-- Keycloak user maps to Polaris's root, and a non-writer can't create.
--   q alice -f /seed/seed-table.sql      (q is defined in README.md, "Run it")
CREATE SCHEMA IF NOT EXISTS iceberg.db;

CREATE TABLE IF NOT EXISTS iceberg.db.t1 AS SELECT 1 AS x;
