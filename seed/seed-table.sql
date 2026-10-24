-- Seed the demo Iceberg table once, as alice, a member of jgi: jgi's space is the schema
-- iceberg.jgi, and its members write there with no registration.
--   q alice -f /seed/seed-table.sql      (q is defined in README.md, "Run it")
CREATE SCHEMA IF NOT EXISTS iceberg.jgi;

CREATE TABLE IF NOT EXISTS iceberg.jgi.t1 AS SELECT 1 AS x;
