-- Seed the demo Iceberg table once, as its owner alice (a "writer"). Not root/admin: the
-- idp-shim refuses to mint a token for the internal admin, and a non-writer can't create.
--   docker compose exec -T trino trino --user alice -f /seed/seed-table.sql
CREATE SCHEMA IF NOT EXISTS iceberg.db;

CREATE TABLE IF NOT EXISTS iceberg.db.t1 AS SELECT 1 AS x;
