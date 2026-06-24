-- Seed the demo Iceberg table once, during Stage A, while OPA is allow-all.
-- Run via the Trino CLI as --user admin:
--   docker compose exec -T trino trino --user admin -f /seed/seed-table.sql
CREATE SCHEMA IF NOT EXISTS iceberg.db;

CREATE TABLE IF NOT EXISTS iceberg.db.t1 AS SELECT 1 AS x;
