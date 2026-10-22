"""
index_table — the per-person dataset index, an Iceberg table whose files governance builds
when they are asked for.

The gate answers the catalog's load request for `<catalog>.governance.datasets` by calling
governance's POST /index/load with the person's own token. Governance works out that person's
rows (every live dataset and table they may see, decided by OPA), builds an Iceberg table
holding them in memory under s3://governance-index/<subject>/<version>/, and returns its
metadata with a short-lived storage credential bound to the person. The engine then reads the
table's files from governance's S3-style endpoint (GET/HEAD /governance-index/<key>), which
checks each request's SigV4 signature and serves a person only their own prefix.

Nothing is written to storage. The version is a hash of the rows, so a changed row set gets
new file paths: a cache keyed by path can never return stale rows or someone else's.
"""
import calendar
import hashlib
import hmac
import io
import json
import re
import secrets
import threading
import time
from collections import OrderedDict
from urllib.parse import parse_qsl, quote

import pyarrow as pa
from pyiceberg.catalog.sql import SqlCatalog
from pyiceberg.io import FileIO
from pyiceberg.schema import Schema
from pyiceberg.types import BooleanType, NestedField, StringType

BUCKET = "governance-index"
SCHEMA = Schema(
    NestedField(1, "id", StringType(), required=False),
    NestedField(2, "kind", StringType(), required=False),       # table | files
    NestedField(3, "description", StringType(), required=False),
    NestedField(4, "steward", StringType(), required=False),
    NestedField(5, "can_read", BooleanType(), required=False),
)
MAX_TABLES = 256          # built tables kept, least recently loaded evicted first
CREDENTIAL_TTL = 900      # seconds a storage credential from /index/load stays valid
CLOCK_SKEW = 900          # seconds a signed request's date may differ from now

_lock = threading.Lock()
_files = {}               # s3 path -> bytes, for every built table
_tables = OrderedDict()   # (subject, version) -> {"metadata-location", "metadata"}
_keys = {}                # access key -> (secret, session token, subject, expires)


class _Out(io.BytesIO):
    def __init__(self, path):
        super().__init__()
        self._path = path

    def close(self):
        if not self.closed:
            with _lock:
                _files[self._path] = self.getvalue()
        super().close()


class _File:
    def __init__(self, location):
        self.location = location

    def __len__(self):
        return len(_files.get(self.location, b""))

    def exists(self):
        return self.location in _files

    def open(self, seekable=True):
        return io.BytesIO(_files[self.location])

    def create(self, overwrite=False):
        return _Out(self.location)

    def to_input_file(self):
        return self


class MemIO(FileIO):
    """pyiceberg FileIO over the in-memory store, so building a table writes nothing."""

    def new_input(self, location):
        return _File(location)

    def new_output(self, location):
        return _File(location)

    def delete(self, location):
        with _lock:
            _files.pop(getattr(location, "location", location), None)


def build(subject, rows):
    """The person's index table for these rows: its metadata location and metadata, built
    once per (subject, row set) and kept until evicted."""
    version = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()[:16]
    key = (subject, version)
    with _lock:
        if key in _tables:
            _tables.move_to_end(key)
            return _tables[key]
    catalog = SqlCatalog("index", uri="sqlite:///:memory:", warehouse=f"s3://{BUCKET}",
                         **{"py-io-impl": f"{__name__}.MemIO"})
    catalog.create_namespace("governance")
    table = catalog.create_table("governance.datasets", schema=SCHEMA,
                                 location=f"s3://{BUCKET}/{subject}/{version}")
    if rows:
        table.append(pa.Table.from_pylist(rows, schema=SCHEMA.as_arrow()))
    built = {"metadata-location": table.metadata_location,
             "metadata": json.loads(table.metadata.model_dump_json())}
    with _lock:
        _tables[key] = built
        while len(_tables) > MAX_TABLES:
            (old_subject, old_version), _ = _tables.popitem(last=False)
            prefix = f"s3://{BUCKET}/{old_subject}/{old_version}/"
            for path in [p for p in _files if p.startswith(prefix)]:
                del _files[path]
    return built


def mint(subject):
    """A storage credential that reads only the subject's prefix, for CREDENTIAL_TTL."""
    now = time.time()
    access, secret, token = ("GIX" + secrets.token_hex(8).upper(), secrets.token_urlsafe(30),
                             secrets.token_urlsafe(32))
    with _lock:
        for k in [k for k, v in _keys.items() if v[3] < now]:
            del _keys[k]
        _keys[access] = (secret, token, subject, now + CREDENTIAL_TTL)
    return {"s3.access-key-id": access, "s3.secret-access-key": secret, "s3.session-token": token,
            "s3.session-token-expires-at-ms": str(int((now + CREDENTIAL_TTL) * 1000))}


_AUTH_RE = re.compile(r"AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/s3/aws4_request,\s*"
                      r"SignedHeaders=([a-z0-9;-]+),\s*Signature=([0-9a-f]{64})$")


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def verify(method, raw_path, raw_query, headers):
    """The subject whose credential signed this S3 request (SigV4, header form), or None."""
    m = _AUTH_RE.match(headers.get("Authorization", ""))
    if not m:
        return None
    access, date, region, signed, signature = m.groups()
    with _lock:
        entry = _keys.get(access)
    if entry is None or entry[3] < time.time():
        return None
    secret, token, subject, _ = entry
    amz_date = headers.get("x-amz-date", "")
    if not hmac.compare_digest(headers.get("x-amz-security-token", ""), token) \
            or not amz_date.startswith(date):
        return None
    try:
        skew = abs(time.time() - calendar.timegm(time.strptime(amz_date, "%Y%m%dT%H%M%SZ")))
    except ValueError:
        return None
    if skew > CLOCK_SKEW or "host" not in signed.split(";"):
        return None
    canonical_headers = "".join(f"{h}:{' '.join(headers.get(h, '').split())}\n"
                                for h in signed.split(";"))
    canonical_query = "&".join(sorted(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
                                      for k, v in parse_qsl(raw_query, keep_blank_values=True)))
    request = "\n".join([method, raw_path, canonical_query, canonical_headers, signed,
                         headers.get("x-amz-content-sha256", "UNSIGNED-PAYLOAD")])
    scope = f"{date}/{region}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                         hashlib.sha256(request.encode()).hexdigest()])
    k = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret).encode(), date), region), "s3"), "aws4_request")
    expected = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    return subject if hmac.compare_digest(expected, signature) else None


def read(path):
    with _lock:
        return _files.get(path)
