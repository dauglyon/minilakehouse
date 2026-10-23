"""
index_table — the tables of the `governance` namespace, Iceberg tables whose files governance
builds per person when they are asked for: `datasets` (every live dataset and table the
person may see, decided by OPA), `sessions` (their sessions), `lineage` (what each of their
sessions read and wrote) and `derivations` (what they declared; PROVENANCE.md 5).

The gate answers the catalog's load request for `<catalog>.governance.<table>` by calling
governance's POST /index/load with the person's own token. Governance works out that person's
rows, builds an Iceberg table holding them in memory under
s3://governance-index/<subject>/<table>/<version>/, and returns its metadata with a short-lived
storage credential bound to the person. The engine then reads the table's files from
governance's S3-style endpoint (GET/HEAD /governance-index/<key>), which checks each request's
SigV4 signature and serves a person only their own prefix.

Nothing is written to storage. The version is a hash of the rows, so a changed row set gets
new file paths: a cache keyed by path can never return stale rows or someone else's.

`derivations` also accepts an engine's append (commit): the engine puts its data and manifest
files through the same endpoint, under the person's own table, and commits through the gate.
commit() applies the commit to the table the person last loaded, reads the rows it appends,
and hands them to the caller's check, which stores them or refuses the commit.
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

import uuid

import pyarrow as pa
import pyarrow.parquet as pq
from pydantic import TypeAdapter, ValidationError
from pyiceberg.catalog.sql import SqlCatalog
from pyiceberg.exceptions import CommitFailedException
from pyiceberg.io import FileIO
from pyiceberg.manifest import DataFileContent, ManifestContent, ManifestEntryStatus
from pyiceberg.schema import Schema
from pyiceberg.table.metadata import TableMetadataUtil
from pyiceberg.table.snapshots import Operation
from pyiceberg.table.statistics import StatisticsFile
from pyiceberg.table.update import (AddSnapshotUpdate, RemoveStatisticsUpdate, SetSnapshotRefUpdate,
                                    SetStatisticsUpdate, TableRequirement, TableUpdate,
                                    update_table_metadata)
from pyiceberg.types import BooleanType, NestedField, StringType, TimestamptzType

BUCKET = "governance-index"


def _schema(*columns):
    return Schema(*(NestedField(i, name, typ(), required=False)
                    for i, (name, typ) in enumerate(columns, start=1)))


TABLES = {
    "datasets": _schema(("id", StringType), ("kind", StringType),   # kind: table | files
                        ("description", StringType), ("steward", StringType),
                        ("can_read", BooleanType)),
    "sessions": _schema(("name", StringType), ("started", TimestamptzType),
                        ("last_used", TimestamptzType), ("current", BooleanType)),
    "lineage": _schema(("source", StringType), ("source_type", StringType),     # table | files
                       ("target", StringType), ("target_type", StringType),
                       ("session", StringType), ("event_time", TimestamptzType),
                       ("direct", BooleanType)),   # false: arrived through a read
    "derivations": _schema(("source", StringType), ("source_type", StringType),  # + external
                           ("target", StringType), ("used", BooleanType)),
}
WRITABLE = {"derivations"}
# The updates an append makes: a snapshot, the branch moved to it, and the statistics an engine
# may attach afterwards.
_APPEND_UPDATES = (AddSnapshotUpdate, SetSnapshotRefUpdate, SetStatisticsUpdate,
                   RemoveStatisticsUpdate)
_REQUIREMENT = TypeAdapter(TableRequirement)
_UPDATE = TypeAdapter(TableUpdate)


def _update(u):
    # pyiceberg 0.10's SetStatisticsUpdate reads `statistics` as an object before validating
    # it, so one parsed from JSON fails; Trino sends one with every insert.
    if isinstance(u, dict) and u.get("action") == "set-statistics" and isinstance(u.get("statistics"), dict):
        return SetStatisticsUpdate(statistics=StatisticsFile.model_validate(u["statistics"]))
    return _UPDATE.validate_python(u)


MAX_UPLOAD = 64 * 1024 * 1024   # bytes a person may hold in uploads, open multipart parts included
MAX_OPEN_UPLOADS = 8            # multipart uploads a person may have open, oldest dropped first
MAX_TABLES = 256          # built tables kept, least recently loaded evicted first
CREDENTIAL_TTL = 900      # seconds a storage credential from /index/load stays valid
CLOCK_SKEW = 900          # seconds a signed request's date may differ from now

_lock = threading.Lock()
_files = {}               # s3 path -> bytes, for every built table
_tables = OrderedDict()   # (subject, table, version) -> {"metadata-location", "metadata"}
_keys = {}                # access key -> (secret, session token, subject, expires)
_current = {}             # (subject, table) -> the table the person last loaded or committed
_uploaded = {}            # subject -> paths of the objects they uploaded
_open = {}                # subject -> {upload id: (key, {part number: bytes})}, oldest first


class S3Error(Exception):
    """An upload refused with an S3 error: HTTP status and code."""

    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


class Refused(Exception):
    """A commit refused with an Iceberg REST error: HTTP status, error type, message."""

    def __init__(self, status, kind, message):
        super().__init__(message)
        self.status, self.kind, self.message = status, kind, message


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


def build(subject, name, rows):
    """The person's table `name` (a key of TABLES) holding these rows: its metadata location
    and metadata, built once per (subject, table, row set) and kept until evicted."""
    version = hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()[:16]
    key = (subject, name, version)
    with _lock:
        if key in _tables:
            _tables.move_to_end(key)
            _current[(subject, name)] = _tables[key]
            return _tables[key]
    schema = TABLES[name]
    catalog = SqlCatalog("index", uri="sqlite:///:memory:", warehouse=f"s3://{BUCKET}",
                         **{"py-io-impl": f"{__name__}.MemIO"})
    catalog.create_namespace("governance")
    table = catalog.create_table(f"governance.{name}", schema=schema,
                                 location=f"s3://{BUCKET}/{subject}/{name}/{version}")
    if rows:
        table.append(pa.Table.from_pylist(rows, schema=schema.as_arrow()))
    built = {"metadata-location": table.metadata_location,
             "metadata": json.loads(table.metadata.model_dump_json())}
    with _lock:
        _tables[key] = built
        _current[(subject, name)] = built
        while len(_tables) > MAX_TABLES:
            (old_subject, old_name, old_version), _ = _tables.popitem(last=False)
            prefix = f"s3://{BUCKET}/{old_subject}/{old_name}/{old_version}/"
            for path in [p for p in _files if p.startswith(prefix)]:
                del _files[path]
    return built


def commit(subject, name, body, check):
    """Apply an engine's commit (an Iceberg REST UpdateTableRequest) to the person's table
    `name`, as last loaded or committed. The updates may only append; the requirements must
    hold, so a commit against a table that has changed since it was loaded is refused the
    standard way. check(rows) gets the rows the new snapshots add and raises Refused to refuse
    the commit. Returns the committed table."""
    with _lock:
        base_built = _current.get((subject, name))
    if base_built is None:
        raise Refused(409, "CommitFailedException", f"governance.{name} changed; load it again")
    base = TableMetadataUtil.parse_obj(base_built["metadata"])
    try:
        requirements = [_REQUIREMENT.validate_python(r) for r in body.get("requirements") or []]
        updates = tuple(_update(u) for u in body.get("updates") or [])
    except (ValidationError, AttributeError, KeyError, TypeError) as e:
        raise Refused(400, "BadRequestException", f"not an Iceberg commit: {e}") from e
    if not all(isinstance(u, _APPEND_UPDATES) for u in updates):
        raise Refused(400, "BadRequestException", f"governance.{name} accepts only inserted rows")
    try:
        for r in requirements:
            r.validate(base)
    except CommitFailedException as e:
        raise Refused(409, "CommitFailedException", str(e)) from e
    new = update_table_metadata(base, updates)
    # Every file the commit names must be the person's own upload to this table: the in-memory
    # store holds everyone's tables, and rows read from another person's file would come back
    # to this person in a refusal's message.
    own = f"s3://{BUCKET}/{subject}/{name}/"

    def check_path(path):
        if not path.startswith(own):
            raise Refused(400, "BadRequestException", f"governance.{name} reads only files under {own}")
        return path

    io, rows = MemIO(), []
    for snapshot in new.snapshots:
        if base.snapshot_by_id(snapshot.snapshot_id) is not None:
            continue
        if snapshot.summary is None or snapshot.summary.operation != Operation.APPEND:
            raise Refused(400, "BadRequestException", f"governance.{name} accepts only inserted rows")
        check_path(snapshot.manifest_list)
        for manifest in snapshot.manifests(io):
            if manifest.added_snapshot_id != snapshot.snapshot_id:
                continue   # carried over from an earlier snapshot
            if manifest.content != ManifestContent.DATA:
                raise Refused(400, "BadRequestException", f"governance.{name} accepts only inserted rows")
            check_path(manifest.manifest_path)
            for entry in manifest.fetch_manifest_entry(io):
                if entry.status != ManifestEntryStatus.ADDED:
                    continue
                if entry.data_file.content != DataFileContent.DATA:
                    raise Refused(400, "BadRequestException", f"governance.{name} accepts only inserted rows")
                data = read(check_path(entry.data_file.file_path))
                if data is None:
                    raise Refused(400, "BadRequestException", f"missing data file {entry.data_file.file_path}")
                rows += pq.read_table(pa.BufferReader(data)).to_pylist()
    check(rows)
    location = f"{new.location}/metadata/{uuid.uuid4()}.metadata.json"
    text = new.model_dump_json()
    built = {"metadata-location": location, "metadata": json.loads(text)}
    with _lock:
        _files[location] = text.encode()
        _current[(subject, name)] = built
    return built


def writable_key(subject, key):
    """Whether the person may put an object at this key: under one of their own tables. Only
    WRITABLE tables accept the commit that would use it; an upload for another is kept so that
    the commit, not the upload, carries the refusal the person sees."""
    parts = key.split("/")
    return len(parts) > 2 and parts[0] == subject and parts[1] in TABLES


def _held(subject):
    """Bytes the person's uploads hold: their stored objects and open multipart parts. The
    caller holds _lock."""
    paths = _uploaded.setdefault(subject, set())
    paths.intersection_update(_files)   # deleted, or evicted with the table they were under
    return (sum(len(_files[p]) for p in paths)
            + sum(len(b) for _, parts in _open.get(subject, {}).values() for b in parts.values()))


def _store(subject, key, data):
    """Store an uploaded object; the caller holds _lock and has counted it against the quota.
    A key that already holds a file is refused: engines write every file once under a new name,
    and governance's own files must stay as built."""
    path = f"s3://{BUCKET}/{key}"
    if path in _files:
        raise S3Error(403, "AccessDenied")
    _files[path] = data
    _uploaded.setdefault(subject, set()).add(path)


def put(subject, key, data):
    with _lock:
        if _held(subject) + len(data) > MAX_UPLOAD:
            raise S3Error(400, "EntityTooLarge")
        _store(subject, key, data)


def start_upload(subject, key):
    upload = secrets.token_hex(16)
    with _lock:
        mine = _open.setdefault(subject, OrderedDict())
        mine[upload] = (key, {})
        while len(mine) > MAX_OPEN_UPLOADS:
            mine.popitem(last=False)
    return upload


def _upload(subject, upload, key):
    state = _open.get(subject, {}).get(upload)
    if state is None or state[0] != key:
        raise S3Error(404, "NoSuchUpload")
    return state[1]


def put_part(subject, upload, key, number, data):
    with _lock:
        parts = _upload(subject, upload, key)
        if _held(subject) - len(parts.get(number, b"")) + len(data) > MAX_UPLOAD:
            raise S3Error(400, "EntityTooLarge")
        parts[number] = data


def complete_upload(subject, upload, key, numbers):
    """Store the parts, in the order named, as one object; returns it."""
    with _lock:
        parts = _upload(subject, upload, key)
        if not numbers or any(n not in parts for n in numbers):
            raise S3Error(400, "InvalidPart")
        # Strictly increasing, as S3 requires: a repeated part would be joined again each time
        # it is named, past the quota.
        if numbers != sorted(set(numbers)):
            raise S3Error(400, "InvalidPartOrder")
        size = sum(len(parts[n]) for n in numbers)
        if _held(subject) - sum(len(b) for b in parts.values()) + size > MAX_UPLOAD:
            raise S3Error(400, "EntityTooLarge")
        data = b"".join(parts[n] for n in numbers)
        del _open[subject][upload]   # its parts' bytes now count as the object
        _store(subject, key, data)
    return data


def abort_upload(subject, upload, key):
    with _lock:
        _upload(subject, upload, key)
        del _open[subject][upload]


def delete(key):
    """Remove an uploaded object. Files of a built or committed table are kept: an engine
    deletes only the files of a write it abandoned."""
    path = f"s3://{BUCKET}/{key}"
    with _lock:
        built = any(path.startswith(t["metadata"]["location"] + "/") for t in _tables.values())
        if not built:
            _files.pop(path, None)


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
