"""
seed/check-index-narrowing.py — the dataset index's narrowing drops nothing OPA would show.

Governance offers OPA only entries whose viewing grants name one of the person's groups
(governance/app.py `_index_rows`). For every person in any group, plus one in none, this
compares those rows with OPA's decision over every live entry, and exits 1 on any difference.
Run in the governance container:

    docker compose exec governance python /seed/check-index-narrowing.py
"""
import sys

sys.path.insert(0, "/app")
import app  # noqa: E402  (governance's own module: the same code path the index uses)

app.connect_pool()
with app.db() as cur:
    cur.execute("SELECT DISTINCT member FROM group_members")
    subjects = sorted(r["member"] for r in cur.fetchall()) + ["no-groups-at-all"]
    cur.execute("SELECT id FROM datasets WHERE status = 'live'")
    files = [r["id"] for r in cur.fetchall()]
    cur.execute("SELECT id FROM table_entries WHERE status = 'live'")
    tables = [r["id"] for r in cur.fetchall()]
    cur.execute("SELECT id FROM collections")
    collections = [r["id"] for r in cur.fetchall()]

bad = 0
for s in subjects:
    full = {("files", i) for i in app.opa("discover", {"subject": s, "datasets": files})["visible"]}
    full |= {("table", i) for i in app.opa("decide", {"subject": s, "tables": tables,
                                                      "namespaces": []}, package="tables")["tables"]}
    full |= {("collection", i) for i in app.opa("discover", {"subject": s, "collections": collections},
                                                package="collections")["visible"]}
    narrowed = {(r["kind"], r["id"]) for r in app._index_rows(s)}
    if full != narrowed:
        bad += 1
        print(f"{s}: OPA alone shows {sorted(full - narrowed)}, narrowing adds {sorted(narrowed - full)}")
print(f"{len(subjects)} people, {len(files)} file datasets, {len(tables)} tables, {len(collections)} collections: "
      f"{'narrowing matches OPA' if not bad else f'{bad} differ'}")
sys.exit(1 if bad else 0)
