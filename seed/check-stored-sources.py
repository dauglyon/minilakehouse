"""
seed/check-stored-sources.py — stored sources match what carried() works out from scratch
(docs/PLAN-2026-10-24.md item 3e). For every stored row whose version is current, it works the
sources out again without the store and exits 1 on any difference. A row whose entry had to be
listed again in between (a credential expired since its last listing) is skipped and counted.
Run in the governance container, best after the other checks have made decisions:

    docker compose exec governance python /seed/check-stored-sources.py
"""
import sys

sys.path.insert(0, "/app")
import app  # noqa: E402  (governance's own module: the lookup OPA's rules get)

app.connect_pool()


def version(cur, ds):
    cur.execute("SELECT COALESCE((SELECT version FROM sources_version WHERE dataset = %s), 0) AS v", (ds,))
    return cur.fetchone()["v"]


with app.db() as cur:
    cur.execute("SELECT e.dataset, e.direct, e.sources FROM entry_sources e "
                "LEFT JOIN sources_version v ON v.dataset = e.dataset WHERE e.version = COALESCE(v.version, 0)")
    rows = cur.fetchall()
bad = skipped = 0
for r in rows:
    with app.db() as cur:
        before = version(cur, r["dataset"])
    fresh = app.carried(r["dataset"], r["direct"], stored=False)
    with app.db() as cur:
        if version(cur, r["dataset"]) != before:
            skipped += 1
            continue
    if sorted(fresh, key=lambda c: c["id"]) != sorted(r["sources"], key=lambda c: c["id"]):
        bad += 1
        print(f"{r['dataset']} direct={r['direct']}: stored {r['sources']}, worked out {fresh}")
print(f"{len(rows)} stored, {skipped} listed again in between: "
      f"{'every stored row matches' if not bad else f'{bad} differ'}")
sys.exit(1 if bad else 0)
