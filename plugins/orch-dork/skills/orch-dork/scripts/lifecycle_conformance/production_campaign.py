"""Read one production campaign's durable report; grant only derived closure.

campaign.build_coverage_checklist enumerates the current source and registry
obligations and ships every one PENDING.  The fixed gate reaches six of its
twelve requirements only through this reader, and this reader grants a fact
only because that fact's bound obligation rows are closed by sealed evidence
whose digests are recomputed here from bytes.  Nothing here is authority:
campaign credit, release, qualification and promotion are always False, and an
incomplete reading is preserved as faithfully as a complete one.

Why the durable pattern and not live custody.  The producer is a separate child
process (the production execution bridge) and the consumer is a later, different
interpreter (the gate reader at qualification).  The in-process custody shape
release_execution uses, an opaque return value the gate still holds, cannot
survive a child-process boundary.  This module therefore re-derives from durable
originals the way live_attempt_consumption re-derives from its on-disk chain:
the obligation table is rebuilt from the retained generation, every sealed file
is re-read through an owner-verified descriptor, every closed row's digest is
recomputed from the bytes on disk, and the whole reading is compared against the
supplied report.  validate_production_campaign rebuilds before it compares, so a
supplied report cannot reseal itself.

The nine fact names are not a second copy of the gate's mapping.  The fact set
is read at verify time from completion_gate.FACT_COMPONENTS, and the grant loop
iterates that gate-derived set evaluating row closure; no fact is ever returned
from a literal.  FACT_ROW_ANCHORS is the one declared policy here: per fact, the
obligation row classes whose closure constitutes that fact.  It is policy, not
expectation, and verify refuses rather than narrows whenever it stops matching
the gate: the key set must equal the gate-derived fact set exactly, every
declared class must resolve to at least one rebuilt row, and exactly one fact
may be anchored to the whole table.  A renamed derivation identity, a dropped
registry kind, an added or removed gate fact, or a second capstone all fail
closed instead of silently earning a grant.

No digest over store content is the trust anchor, because store content and the
generation are both available to a forger.  report_sha256 covers the canonical
report body so a writer and reader agree on transport integrity only.  Every
closed row requires its own sealed evidence file, and a row's registered base
digest is never sufficient on its own, because any holder of the generation can
recompute a base digest.  That same objection retires every purely
content-derived closure: sha256 over a record the forger authors is no better
than the base digest it replaced.  The trust anchor is therefore the one input
that is neither in the store nor in the generation.

The campaign anchor.  verify_production_campaign requires a caller-retained
anchor the producing campaign minted and the reader never reads from disk, in
the shape live_attempt_consumption already relies on: consumption.create_store
mints secrets.token_hex(32) and the root holds the returned receipt outside the
store, so a replaced store fails against a retained original.  Here the producer
mints the key once when it creates the store, keys an HMAC-SHA256 over every
evidence record and over the report body, hands the anchor back to the root out
of band, and the root passes it in at verify time.  A forger with the complete
generation - sources, runtime, registry and the whole rebuilt obligation table -
cannot produce a single record this reader accepts, because the key never
appears in anything the forger can read.  Nothing here is secret by obscurity:
the field set and digest relations below are published precisely because only
the key carries the force.

What the store-root restriction does and does not do.  It refuses any entry
beside the report and the evidence directory, and this reader additionally
refuses a sealed file whose bytes contain this reading's own key verbatim.
That is a filename rule plus one exact-substring rule, and it is the whole of
it: an independent review parked the key in a record's free-text observed and
case fields and the store still verified, which the earlier wording of this
docstring wrongly described as prevented.  The case field is now the
repository's own derived case identity and carries no caller text at all, and
observed is bounded printable text, but a producer that encodes or splits a key
across observations defeats any check a reader can make.  Key custody is
therefore the producing lane's obligation and is not established here.  Do not
read these checks as protecting the key; read them as refusing the accidental
and verbatim cases only.

What the anchor does and does not settle.  Against the forger the reviewer
demonstrated - one who holds the generation and writes the store - the anchor is
decisive: a root that passes the anchor its producer returned refuses every
forged store, because the forger cannot MAC under a key it never saw.  No reader
can, however, tell a producer's key from a key the caller minted for itself by
reading the store, any more than consumption.read_store can authenticate a
receipt the caller fabricated.  Custody of the anchor is therefore the root's,
exactly as it already is there.

The self-minted anchor is open and is not closable here.  A caller that mints a
key and an execution identity can author a complete store from the generation
alone and be granted every fact, because nothing in this reader binds the anchor
to anything outside the store.  Closing it requires a second party that knows
what was dispatched.  This reader therefore publishes, in its reading and
bound into the keyed report MAC, the exact values that party must compare:
execution_sha256 over the whole execution identity, its component
execution_dispatch_sha256, execution_pid, execution_started_ns and
execution_nonce, and store_sha256 over the store instance read.  Until that
comparison exists at the gate, a reading from this module proves only that
whoever holds the anchor authored this store.

The gate cross-check, stated per component so it can be implemented.  An
earlier wording told the gate to take "the dispatch seal, pid and start time"
from its own dispatch record, and that instruction cannot be carried out: it
omits the nonce, which is the fourth component inside execution_sha256, and it
asks for a start time the gate cannot reproduce.  /proc/<pid>/stat resolves
starttime to USER_HZ - 10ms on this host - while a one-nanosecond difference
changes the digest completely, and /proc/<pid> is gone once the child is
reaped.  A gate that "checks" started_ns can therefore only accept the number
the child wrote, which is the trust move the check exists to prevent.  Each
component must instead name the side it comes from:

    dispatch_sha256   the gate own dispatch record.  Equality required.
    nonce             minted BY THE GATE before the spawn and passed to the
                      child.  Equality required.  A child-chosen nonce is not
                      checkable and must be refused.
    pid               the pid the kernel assigned the child the gate itself
                      spawned, read from the spawn, never from the anchor.
                      Equality required.
    started_ns        NOT reproduced.  The gate records its own pre-spawn and
                      post-reap timestamps and requires the anchor value to lie
                      within that bracket.  It is a bound, not an equality.

This does leave the gate supplying two of the four components, so the digest by
itself no longer proves the child chose anything: it proves the gate is looking
at the run it dispatched.  What keeps the check from being the gate talking to
itself is the key, not the digest.  The child mints the MAC key and returns the
anchor over a channel the gate created - an inherited socketpair or pipe, never
a file, argv or environment variable a third party can read or write.  The gate
therefore knows that whoever sealed this store held a key that came back from
the process it spawned, over a channel only that process held.  execution_sha256
names that run; the key is the proof of possession.  A caller that mints its own
anchor fails because its key never came out of a gate-spawned child, not because
its digest is wrong.

The gate must also refuse replay.  store_sha256 binds a location, and inode
reuse at one path is deterministic here (measured 400/400 on ext4), so a
genuine anchor and its store can be presented twice.  The gate records each
execution_sha256 it has accepted and refuses a repeat, which is the same
one-shot rule completion_gate already applies to its fresh kinds.

Two limits stay open and are not closed by any of the above.  The gate own
dispatch record must be at least as protected as the anchor, or a forger
rewrites that instead; and the four components are published here as a complete
preimage, so the gate must take each one from the side named above rather than
from the reading it is checking.  Until the gate implements this, the honest
reading of this module is the one it already returns: facts derived, no credit
and no authorization granted.

Durable store-root contract.  The evidence driver writes it, this reader and the
gate branch read it, and the gate record carries exactly this layout:

    store_root/                   directory, this user or root, not group or
                                  other writable, opened O_NOFOLLOW
        report.json               sealed regular file, single link, not group or
                                  other writable, at most MAX_REPORT_BYTES:
                                  canonical JSON, the closed field set below
        evidence/                 directory with the same ownership rules
            <row_sha256>.json     one sealed record per closed row, named for
                                  the sha256 of its row identity, so a row can
                                  hold at most one evidence file by construction

and nothing else: a store root holding any further entry is refused.  See the
custody paragraph above for what that does and does not achieve.  The evidence
directory is the only place closure is asserted: one sealed file per closed
row and no file for a pending one, so the store's size tracks the evidence
that exists rather than the size of the table.

The retained anchor field set is exactly:

    {"schema": ANCHOR_SCHEMA, "key": <64 hex>, "execution": {...}}
    execution = {"dispatch_sha256": <64 hex>, "pid": int, "started_ns": int,
                 "nonce": <64 hex>}

where dispatch_sha256 is the production_execution child dispatch's content seal,
pid and started_ns bind the process that actually ran, and nonce distinguishes
two runs of one dispatch.  started_ns is CLOCK_REALTIME, because the reader is a
later interpreter and a monotonic clock is not comparable across processes; it
must fall between 2020-01-01 and this reader's own clock plus a bounded skew.
pid must exceed 1, and neither 64-hex field may be one repeated character or
equal the other.  These refuse the degenerate placeholders an identity-free
caller reaches for first; they are shape rules and cannot establish that the
identity is real.  The reader does not re-derive the child's own seal, which
belongs to that lane, and the gate cross-check described above is what makes
the identity mean anything.

The report field set is exactly:

    schema, report_sha256, campaign_mac, status, generation, store_sha256,
    execution_sha256, obligation_table_sha256, closure_sha256,
    obligation_counts, completion_facts, campaign_credit, release_authorized,
    qualification_authorized, promotion_authorized

    generation = {"sources_sha256", "runtime_sha256", "registry_sha256"}

Why the report carries digests of the obligation table and the closure rather
than the table itself.  It used to carry one entry per rebuilt row, which made
the report's floor size a function of the table rather than of the evidence.
Over this repository's real generation that table has 18,672 rows and the
floor was 2,504,096 bytes with nothing closed, against a 1 MiB cap: every
honest campaign refused on extent before a single fact was evaluated, and no
smaller legitimate generation exists because the 203 sources are already
exactly the runtime allowlist.  The embedded rows also contributed nothing the
reader did not already hold.  It rebuilds the table from the generation, and
it recomputes every closing digest from the sealed bytes on disk, so each
embedded row had to equal a value the reader derived independently or be
refused; a row could only agree or fail.  The two digests keep exactly what
the rows established - that the producer was writing about this table and
knew which rows its evidence closes - in 64 hex characters each:

    obligation_table_sha256   canonical digest of {row_id: {"kind",
                              "record_sha256"}} over the whole rebuilt table.
                              The reader recomputes it from the table it built
                              from the generation, so a report sealed against a
                              different table refuses instead of being
                              reinterpreted against this one.
    closure_sha256            canonical digest of {row_id: <sha256 of that
                              row's sealed evidence file bytes>} over exactly
                              the rows this store closes.  The reader derives
                              that map from the evidence directory and requires
                              equality, so a producer that does not know which
                              rows it closed cannot seal a report.

Both are inside the keyed MAC, so neither can be adjusted to fit a store the
producer did not author.  Closure is now derived from sealed bytes alone: a row
is closed exactly when the store holds a sealed, row-bound, MACed record for
it, and the report asserts closure only through closure_sha256 rather than by
listing rows.  MAX_REPORT_BYTES is correspondingly a resource ceiling on one
read - the whole report measures 1,332 bytes over the real generation - rather
than a limit on how large a campaign may be.

What the byte cap must no longer be asked to do.  Before this change the cap
was, accidentally, the only thing preventing a caller-minted anchor from
obtaining all nine facts at full scale: the forgery was demonstrable only with
MAX_REPORT_BYTES patched 64x upward, because an honest report did not fit
either.  That was never a defence - it refused the honest producer and the
forger identically, and it would have evaporated the moment anyone raised the
number.  The self-minted anchor is refused by the gate cross-check described
above and by nothing else, which is what this module has always published in
its own reading and what the gate publishes as anchor_custody.  Scaling the
report down does not widen that gap, because the forger's cost was never the
bytes: a caller holding the generation could always author a store of any size.

store_sha256 is the canonical digest of {"path", "dev", "ino"} for the store
root the reader opened, so a sealed store is bound to the LOCATION it was
written at: a byte-identical clone refuses at a new path, and one execution
identity cannot seal two campaigns because their store identities differ.  It
is a location, not an instance.  Deleting a store and recreating it at the same
path reproduces path, dev and ino exactly - inode reuse measured 400/400 at one
path on ext4 - so the digest cannot distinguish the original store from a later
one built in its place, and st_dev is not stable across remounts.  Instance
freshness is the gate replay rule above, not this digest.
execution_sha256 is the canonical digest of the anchor's execution identity,
sealed here so the value the gate cross-check consumes is inside the keyed MAC
rather than merely reported alongside it.

and the report's obligation_table_sha256 must equal the rebuilt table's digest
exactly: no renamed, added or dropped row survives verify, because any such
change moves that digest.  campaign_mac is the keyed MAC over the report body
excluding report_sha256 and campaign_mac.  An evidence record is

    {"schema": EVIDENCE_SCHEMA, "row": <row id>, "row_sha256": <64 hex>,
     "base_record_sha256": null | <64 hex>, "record_sha256": <64 hex>,
     "record": {"case": <str>, "observed": <str>, "execution": {...}},
     "evidence_mac": <64 hex>}

where row_sha256 is the sha256 of the row identity, base_record_sha256 equals
the rebuilt row's own registered record digest when it has one and is null
otherwise, record_sha256 is the canonical digest of record, and the file's bytes
hash to the value this row contributes to closure_sha256.  A record whose row
the rebuilt table does not contain is refused, so an orphan cannot close
anything.  The record payload is no longer an opaque
dict.  case is completion_gate.case_identity over {"row", "execution_sha256"},
so it is derived rather than chosen: a record cannot name a different row than
the one it closes, cannot repeat one case across the table, and carries no
caller text.  observed is bounded printable text, and execution repeats the
anchor's identity, so a record cannot describe a run that never happened.
evidence_mac is the keyed MAC over the record body excluding itself, and it is
the reason none of this can be authored from the generation.  Orphans are
refused: every sealed record must belong to a row the report closes.

This module writes nothing.  There is no reset, no retry, and no alternate-store
discovery; the writer lane owns the sealed files.  The four phase receipts and
the finalized execution record belong to the production-execution lane, and the
gate dispatch branch and runtime allowlist entry belong to the wiring lane.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from types import MappingProxyType
import os
import re
import stat
import time
import weakref

from lifecycle_conformance import reference_values as rv
from lifecycle_conformance.values import (
    LifecycleContractError,
    canonical_digest,
    canonical_json,
)


SCHEMA = "orch-dork/issue170-production-campaign/v1"
EVIDENCE_SCHEMA = "orch-dork/issue170-production-campaign-evidence/v1"
ANCHOR_SCHEMA = "orch-dork/issue170-production-campaign-anchor/v1"
CHECKLIST_SCHEMA = "orch-dork/integrated-coverage-checklist/v1"
COMPLETE_STATUS = "PRODUCTION_CAMPAIGN_VERIFIED"
INCOMPLETE_STATUS = "PRODUCTION_CAMPAIGN_INCOMPLETE"
PENDING_ROW = "PENDING"
CLOSED_ROW = "CLOSED"
COMPONENT = "production_campaign"
REPORT_NAME = "report.json"
EVIDENCE_DIR = "evidence"
EVIDENCE_SUFFIX = ".json"
# The report carries digests, never the obligation table, so its size does not
# grow with the table.  Measured over the real 18,672-row generation the whole
# report is 1,332 bytes, so this bound is a resource ceiling on one read and
# never a limit on how large a campaign may be.  It is deliberately tight: the
# previous 1 MiB was sized for a report that embedded every row, and a report
# that tries to do that again cannot fit here.
MAX_REPORT_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_EVIDENCE_FILES = 65536
MAX_ROWS = 65536
MAX_SOURCES = 8192
MAX_REGISTRY_ITEMS = 8192
MAX_IDENTIFIER = 512
MAX_OBSERVATION = 4096
MAX_STORE_PATH = 4096
# Above every Linux pid_max ceiling, so the bound is a shape rule and not a
# host-specific one; pid 1 is init and is excluded separately below.
MAX_PID = 4 * 1024 * 1024
# 2020-01-01T00:00:00Z in CLOCK_REALTIME nanoseconds.  No run of this campaign
# predates the repository, and no run happens in the reader's future.
EPOCH_FLOOR_NS = 1577836800 * 1000000000
MAX_CLOCK_SKEW_NS = 300 * 1000000000
REPORT_FIELDS = frozenset({
    "schema", "report_sha256", "campaign_mac", "status", "generation",
    "store_sha256", "execution_sha256", "obligation_table_sha256",
    "closure_sha256", "obligation_counts", "completion_facts",
    "campaign_credit", "release_authorized", "qualification_authorized",
    "promotion_authorized",
})
EVIDENCE_FIELDS = frozenset({
    "schema", "row", "row_sha256", "base_record_sha256", "record_sha256",
    "record", "evidence_mac",
})
RECORD_FIELDS = frozenset({"case", "observed", "execution"})
ANCHOR_FIELDS = frozenset({"schema", "key", "execution"})
EXECUTION_FIELDS = frozenset({"dispatch_sha256", "pid", "started_ns", "nonce"})
GENERATION_FIELDS = frozenset({"sources", "runtime", "registry_components"})
# The exact preimage of report["store_sha256"], published so the producing lane
# seals the same three values the reader recomputes from the directory it opens.
STORE_IDENTITY_FIELDS = frozenset({"path", "dev", "ino"})
# The store holds exactly these two entries; an anchor parked beside the
# evidence it anchors would defeat the whole point of retaining it elsewhere.
STORE_ENTRIES = frozenset({REPORT_NAME, EVIDENCE_DIR})
_REPORT_GENERATION_FIELDS = frozenset({
    "sources_sha256", "runtime_sha256", "registry_sha256"})
_SHA = re.compile(r"[0-9a-f]{64}")
_EVIDENCE_NAME = re.compile(r"([0-9a-f]{64})\.json")
# An observation is human-readable text: printable ASCII, tab and newline.  It
# does not stop a producer encoding a secret, which is why key custody is the
# producing lane's obligation and is stated as such in the module docstring.
_OBSERVED = re.compile(r"[\x20-\x7e\n\t]+")
# Row-class vocabulary: one fixed derivation identity, one table kind, or the
# whole rebuilt table for the single capstone fact.
_DERIVATION = "derivation:"
_KIND = "kind:"
_TABLE = "obligation_table"
# Declared policy: which obligation row classes constitute each gate fact.
# verify refuses on any drift against completion_gate.FACT_COMPONENTS.
_FACT_ROW_ANCHORS = {
    "production_graph_complete": (
        _DERIVATION + "reachable_states_and_interleavings",
        _KIND + "lifecycle_stage"),
    "production_injection_complete": (
        _DERIVATION + "site_state_cartesian",
        _KIND + "injection_sites", _KIND + "injection_schedule"),
    "host_model_mapping_complete": (
        _KIND + "replays", _KIND + "host_fixtures", _KIND + "host_mcp_fixtures"),
    "public_pass_partitions_complete": (
        _DERIVATION + "semantic_pass_branches", _KIND + "return_site"),
    "legacy_public_pairs_complete": (
        _DERIVATION + "complete_module_and_pair_scope", _KIND + "symbol_role"),
    "external_boundaries_exact": (
        _DERIVATION + "host_execution_custody", _KIND + "host_mcp_fixtures"),
    "negative_gap_matrix_complete": (
        _DERIVATION + "independent_mutation_gate",),
    "shard_union_complete": (
        _DERIVATION + "deterministic_shard_union",),
    "coverage_union_complete": (_TABLE,),
}
# Exported read-only: an in-process remap cannot quietly re-point a fact at a
# class of rows its real derivation never covered.
FACT_ROW_ANCHORS = MappingProxyType(_FACT_ROW_ANCHORS)
_AUTHORITY = object()
_ISSUED = {}


@dataclass(frozen=True)
class ValidatedProductionCampaign:
    """One reader-issued result; construction alone grants nothing."""

    report: rv.FrozenValue
    _authority: object


def _require(condition, reason):
    if condition is not True:
        raise LifecycleContractError("production_campaign:" + reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _mac(key, body):
    """Keyed MAC over one canonical body; the reader's only unforgeable step."""
    return hmac.new(key, canonical_json(body).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _mac_equal(supplied, expected, label):
    """Compare two MACs whole and in constant time.

    Every hex position is load-bearing.  A comparison that stops early, or that
    compares a prefix, reduces the forgery target from 256 bits to whatever it
    still reads, which is an offline and parallelisable search.  The suite pins
    this by perturbing each of the 64 positions in turn, and structurally by
    requiring this function to reach hmac.compare_digest with no slicing.
    """
    _text(supplied, _SHA, label + "_shape")
    _require(hmac.compare_digest(supplied, expected), label)


def _text(value, pattern, label):
    _require(type(value) is str and pattern.fullmatch(value) is not None, label)


def _shape(value, fields, label):
    _require(type(value) is dict and set(value) == set(fields), label)


def _fingerprint(value):
    if type(value) is ValidatedProductionCampaign:
        return (value.report.digest(), id(value._authority))
    return None


def _campaign_anchor(anchor):
    """Validate the caller-retained anchor; it is never read from the store."""
    _require(type(anchor) is rv.FrozenValue, "anchor_required")
    plain = anchor.to_plain()
    _shape(plain, ANCHOR_FIELDS, "anchor_shape")
    _require(plain["schema"] == ANCHOR_SCHEMA, "anchor_schema")
    _text(plain["key"], _SHA, "anchor_key")
    execution = plain["execution"]
    _shape(execution, EXECUTION_FIELDS, "anchor_execution_shape")
    _text(execution["dispatch_sha256"], _SHA, "anchor_execution_dispatch")
    _text(execution["nonce"], _SHA, "anchor_execution_nonce")
    # A digest of one repeated character is not a dispatch seal, and a nonce
    # equal to the seal distinguishes no run from any other.  These are shape
    # rules: the reader cannot re-derive the child's seal, so they refuse the
    # degenerate placeholders an identity-free caller reaches for first.
    for field in ("dispatch_sha256", "nonce"):
        _require(len(set(execution[field])) > 1,
                 "anchor_execution_" + field + "_degenerate")
    _require(execution["dispatch_sha256"] != execution["nonce"],
             "anchor_execution_distinct")
    pid = execution["pid"]
    # pid 1 is init and is never a dispatched production_execution child.
    _require(type(pid) is int and 1 < pid <= MAX_PID, "anchor_execution_pid")
    started = execution["started_ns"]
    # CLOCK_REALTIME, because a later interpreter on this host is the only
    # reader: a monotonic clock is not comparable across processes or boots.
    _require(type(started) is int
             and EPOCH_FLOOR_NS <= started <= time.time_ns() + MAX_CLOCK_SKEW_NS,
             "anchor_execution_started_ns")
    return bytes.fromhex(plain["key"]), plain["key"], execution


def _store_identity(root_fd, store_root):
    """Identify the one store instance this reading is about.

    The producer seals this into the report body, so a byte-identical copy of a
    sealed store refuses at a second location instead of replaying its facts.
    """
    info = os.fstat(root_fd)
    path = os.path.realpath(store_root)
    _require(type(path) is str and os.path.isabs(path)
             and 0 < len(path) <= MAX_STORE_PATH, "store_path_shape")
    try:
        named = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise LifecycleContractError(
            "production_campaign:store_path_unavailable") from error
    # The resolved name must be the very directory the descriptor holds open.
    _require((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino),
             "store_path_binding")
    return {"path": path, "dev": info.st_dev, "ino": info.st_ino}


def _refuse_key_material(raw, key_hex, label):
    """Refuse a sealed file that carries this reading's own key verbatim.

    The reader holds the key, so it can say exactly this and nothing wider: an
    encoded or split key is undetectable here.  Key custody belongs to the
    producing lane; this only stops the key being readable in store bytes.
    """
    text = raw.decode("utf-8", "replace")
    _require(key_hex not in text and key_hex.upper() not in text,
             label + "_key_material")

def _issue(value, granted):
    """Retain what verify actually derived, so issuance alone grants nothing."""
    identity = id(value)
    _ISSUED[identity] = (weakref.ref(value, lambda _: _ISSUED.pop(identity, None)),
                         os.getpid(), _fingerprint(value), tuple(granted))
    return value


def _issued(value):
    record = _ISSUED.get(id(value))
    _require(record is not None and record[0]() is value
             and record[1] == os.getpid() and record[2] == _fingerprint(value),
             "issued_object_binding")
    return record[3]


if hasattr(os, "register_at_fork"):
    # A forked child inherits object identities but not this reader's issuance.
    os.register_at_fork(after_in_child=_ISSUED.clear)


def _decode(raw, max_bytes, label):
    """Strict JSON object decode: duplicate keys and non-canonical values fail."""

    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, label + ":duplicate_key")
            result[key] = value
        return result

    _require(type(raw) is bytes and 0 < len(raw) <= max_bytes, label + ":extent")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        canonical_json(value)
    except LifecycleContractError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise LifecycleContractError(
            "production_campaign:" + label + ":invalid_json") from error
    _require(type(value) is dict, label + ":not_object")
    return value


def _open_directory(name, label, dir_fd=None):
    """Open one directory the reading user owns and nobody else may write."""
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError as error:
        raise LifecycleContractError(
            "production_campaign:" + label + "_unavailable") from error
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISDIR(info.st_mode), label + "_not_directory")
        _require(info.st_uid in (0, os.getuid()), label + "_not_owned")
        _require(not stat.S_IMODE(info.st_mode) & 0o022, label + "_writable")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_sealed(root_fd, name, max_bytes, label):
    """One owner-verified read of a sealed regular file under root_fd."""
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=root_fd)
    except OSError as error:
        raise LifecycleContractError(
            "production_campaign:" + label + "_unavailable") from error
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), label + "_not_regular_file")
        _require(before.st_uid in (0, os.getuid()), label + "_not_owned")
        _require(not stat.S_IMODE(before.st_mode) & 0o022, label + "_writable")
        _require(before.st_nlink == 1, label + "_shared_name")
        _require(0 < before.st_size <= max_bytes, label + "_extent")
        raw = os.pread(descriptor, before.st_size + 1, 0)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        _require(len(raw) == before.st_size
                 and (before.st_mode, before.st_size, before.st_mtime_ns,
                      before.st_ctime_ns)
                 == (after.st_mode, after.st_size, after.st_mtime_ns,
                     after.st_ctime_ns)
                 and (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino),
                 label + "_changed")
        return raw
    finally:
        os.close(descriptor)


def _generation_rows(generation):
    """Rebuild the obligation table from the retained generation originals."""
    from lifecycle_conformance import campaign

    _require(type(generation) is rv.FrozenValue, "generation_required")
    plain = generation.to_plain()
    _shape(plain, GENERATION_FIELDS, "generation_shape")
    sources, registry = plain["sources"], plain["registry_components"]
    _require(type(sources) is dict and 0 < len(sources) <= MAX_SOURCES,
             "generation_sources")
    for path, body in sources.items():
        _require(type(path) is str and 0 < len(path) <= MAX_IDENTIFIER
                 and type(body) is str, "generation_source_entry")
    _require(type(registry) is dict and bool(registry), "generation_registry")
    for kind, items in registry.items():
        _require(type(kind) is str and bool(kind), "generation_registry_kind")
        _require(type(items) is dict and 0 < len(items) <= MAX_REGISTRY_ITEMS,
                 "generation_registry_items")
        for item in items:
            _require(type(item) is str and 0 < len(item) <= MAX_IDENTIFIER,
                     "generation_registry_item")
    checklist = campaign.build_coverage_checklist(sources, registry)
    _require(type(checklist) is rv.FrozenValue, "checklist_type")
    built = checklist.to_plain()
    _require(built["schema"] == CHECKLIST_SCHEMA, "checklist_schema")
    rows = built["obligations"]
    _require(type(rows) is dict and 0 < len(rows) <= MAX_ROWS, "obligation_table")
    for row_id, row in rows.items():
        _require(type(row_id) is str and 0 < len(row_id) <= MAX_IDENTIFIER,
                 "obligation_identity")
        _require(type(row) is dict and type(row.get("kind")) is str
                 and bool(row["kind"]) and row.get("status") == PENDING_ROW,
                 "obligation_row_shape")
        base = row.get("record_sha256")
        if base is not None:
            _text(base, _SHA, "obligation_base_digest")
    return rows


def _gate_facts():
    """The fact set the fixed gate maps to this component, read from the gate."""
    from lifecycle_conformance import completion_gate

    mapping = completion_gate.FACT_COMPONENTS
    _require(type(mapping) is dict and bool(mapping), "gate_fact_mapping")
    facts = frozenset(fact for fact, components in mapping.items()
                      if COMPONENT in tuple(components))
    _require(bool(facts), "gate_component_facts")
    return facts


def _anchor_plan(rows):
    """Resolve declared row classes to concrete rebuilt rows; refuse any drift."""
    facts = _gate_facts()
    _require(set(FACT_ROW_ANCHORS) == set(facts), "anchor_fact_binding")
    by_kind = {}
    for row_id, row in rows.items():
        by_kind.setdefault(row["kind"], set()).add(row_id)
    every = frozenset(rows)
    plan, capstones = {}, []
    for fact in sorted(facts):
        classes = FACT_ROW_ANCHORS[fact]
        _require(type(classes) is tuple and bool(classes), "anchor_classes")
        anchored = set()
        for declared in classes:
            if declared == _TABLE:
                anchored |= set(every)
            elif declared.startswith(_DERIVATION):
                _require(declared in rows, "anchor_row_missing:" + fact)
                anchored.add(declared)
            elif declared.startswith(_KIND):
                matched = by_kind.get(declared[len(_KIND):])
                _require(matched is not None and bool(matched),
                         "anchor_kind_empty:" + fact)
                anchored |= matched
            else:
                _require(False, "anchor_class_invalid:" + fact)
        _require(bool(anchored), "anchor_rows_empty:" + fact)
        if frozenset(anchored) == every:
            capstones.append(fact)
        plan[fact] = frozenset(anchored)
    # Exactly one fact may require the whole table, so a reshaped policy cannot
    # quietly turn every fact into a capstone or drop the union requirement.
    _require(len(capstones) == 1, "anchor_capstone_cardinality")
    return plan


def _evidence_record_body(record, row_id, execution, execution_sha256):
    """The payload must describe one executed case under the anchored run."""
    from lifecycle_conformance import completion_gate

    _shape(record, RECORD_FIELDS, "evidence_record_shape")
    case = record["case"]
    _require(type(case) is str and 0 < len(case) <= MAX_IDENTIFIER,
             "evidence_record_case")
    # The case is the repository's own derived case identity for this row under
    # this run, not free text.  A record therefore cannot name a different row
    # than the one it closes, cannot repeat one case across the table, and
    # cannot carry a caller-chosen payload in this field at all.
    _require(case == completion_gate.case_identity(
        COMPONENT, {"row": row_id, "execution_sha256": execution_sha256}),
        "evidence_record_case_binding")
    observed = record["observed"]
    _require(type(observed) is str and 0 < len(observed) <= MAX_OBSERVATION,
             "evidence_record_observed")
    # An observation is readable text.  This bounds the field; it does not and
    # cannot stop a producer encoding a secret into it, which is why key
    # custody is stated as the producing lane's obligation, not this check's.
    _require(_OBSERVED.fullmatch(observed) is not None,
             "evidence_record_observed_charset")
    # The record repeats the anchored execution identity, so a payload cannot
    # describe a different run, or no run at all, and still close its row.
    _require(record["execution"] == execution, "evidence_record_execution")


def _evidence_records(root_fd, rows, key, key_hex, execution, execution_sha256):
    """Read every sealed evidence record; bind each to exactly one rebuilt row."""
    by_row_digest = {_sha(row_id.encode("utf-8")): row_id for row_id in rows}
    _require(len(by_row_digest) == len(rows), "row_identity_collision")
    try:
        evidence_fd = _open_directory(EVIDENCE_DIR, "evidence_dir", dir_fd=root_fd)
    except LifecycleContractError:
        raise
    try:
        names = sorted(os.listdir(evidence_fd))
        _require(len(names) <= MAX_EVIDENCE_FILES, "evidence_inventory")
        found = {}
        for name in names:
            match = _EVIDENCE_NAME.fullmatch(name)
            _require(match is not None, "evidence_name_shape")
            row_digest = match.group(1)
            row_id = by_row_digest.get(row_digest)
            _require(row_id is not None, "evidence_row_unknown")
            label = "evidence_" + row_digest[:8]
            raw = _read_sealed(evidence_fd, name, MAX_EVIDENCE_BYTES, label)
            _refuse_key_material(raw, key_hex, label)
            record = _decode(raw, MAX_EVIDENCE_BYTES, label)
            _shape(record, EVIDENCE_FIELDS, "evidence_fields")
            _require(record["schema"] == EVIDENCE_SCHEMA, "evidence_schema")
            _require(record["row"] == row_id, "evidence_row_binding")
            _require(record["row_sha256"] == row_digest, "evidence_row_digest")
            _require(type(record["record"]) is dict, "evidence_record_object")
            _evidence_record_body(record["record"], row_id, execution,
                                  execution_sha256)
            _text(record["record_sha256"], _SHA, "evidence_record_digest")
            _require(record["record_sha256"] == canonical_digest(record["record"]),
                     "evidence_record_binding")
            base = rows[row_id].get("record_sha256")
            _require(record["base_record_sha256"] == base,
                     "evidence_base_binding")
            # The keyed MAC over the whole record body is what a generation
            # holder cannot produce: every other field above is derivable.
            body = {field: record[field] for field in sorted(record)
                    if field != "evidence_mac"}
            _mac_equal(record["evidence_mac"], _mac(key, body), "evidence_mac")
            # row_sha256 is the file name, so a row holds at most one record.
            _require(row_id not in found, "evidence_duplicate_row")
            found[row_id] = _sha(raw)
        return found
    finally:
        os.close(evidence_fd)


def _obligation_table_digest(rows):
    """Seal the rebuilt table itself, so the report names the table it closed.

    The report no longer carries the rows.  It carries this digest, and the
    reader recomputes it from the table it rebuilt independently from the
    generation.  That keeps the property the embedded rows were there for - a
    report cannot silently be about a different table - without the report
    growing with the table.
    """
    return canonical_digest({row_id: {"kind": row["kind"],
                                      "record_sha256": row.get("record_sha256")}
                             for row_id, row in rows.items()})


def _closed_rows(rows, evidence):
    """Derive the closed set from sealed evidence alone.

    Every closure here comes from bytes on disk: a row is closed exactly when
    the store holds a sealed record, bound to that row, MACed under the anchor
    key, and belonging to a row the rebuilt table contains.  _evidence_records
    has already established all four before this runs, and it refuses any
    record whose row the table does not contain, so an orphan cannot reach
    here.  The closing digest is the sha256 of the sealed file's own bytes,
    recomputed by the reader rather than read from any report.
    """
    # No check belongs here.  The old orphan rule compared a report's row
    # statuses against the evidence directory, and both sides of that
    # comparison are now derived by this reader from the same bytes, so the
    # rule could no longer fail and a check that cannot fail is not a
    # property.  What it protected is carried in two live places instead:
    # _evidence_records refuses a record for a row the table does not contain
    # (evidence_row_unknown), and the report must seal this exact closure
    # (closure_binding), so a store holding evidence its report does not claim
    # is still refused.
    return {row_id: evidence[row_id] for row_id in sorted(evidence)}


def _store_inventory(root_fd):
    """Nothing may sit beside the report and the evidence directory.

    Absence is left to the specific readers below, which name what is missing.
    This check exists so the retained anchor cannot be parked in the very store
    it is supposed to anchor, where any reader of the store would hold the key.
    """
    extra = frozenset(os.listdir(root_fd)) - STORE_ENTRIES
    _require(not extra, "store_inventory")


def verify_production_campaign(store_root, *, generation, anchor):
    """Derive the campaign facts from durable originals; grant nothing else."""
    anchor_key, key_hex, execution = _campaign_anchor(anchor)
    # Computed once, here, from the validated anchor.  Every later use - the
    # per-record case identity, the report binding and the published field -
    # reads this one value, so the field the gate cross-check consumes cannot
    # drift from the identity the records were actually bound to.
    execution_sha256 = canonical_digest(execution)
    rows = _generation_rows(generation)
    plan = _anchor_plan(rows)
    table_sha256 = _obligation_table_digest(rows)
    plain = generation.to_plain()
    expected_generation = {
        "sources_sha256": canonical_digest(plain["sources"]),
        "runtime_sha256": canonical_digest(plain["runtime"]),
        "registry_sha256": canonical_digest(plain["registry_components"])}

    root_fd = _open_directory(store_root, "store_root")
    try:
        _store_inventory(root_fd)
        store_identity = _store_identity(root_fd, store_root)
        store_sha256 = canonical_digest(store_identity)
        raw = _read_sealed(root_fd, REPORT_NAME, MAX_REPORT_BYTES, "report")
        _refuse_key_material(raw, key_hex, "report")
        report = _decode(raw, MAX_REPORT_BYTES, "report")
        _shape(report, REPORT_FIELDS, "report_field_set")
        _text(report["report_sha256"], _SHA, "report_seal_shape")
        body = {key: value for key, value in report.items()
                if key != "report_sha256"}
        # Transport integrity only. The trust anchor is re-derivation below.
        _require(_sha(canonical_json(body).encode("utf-8"))
                 == report["report_sha256"], "report_seal")
        # The keyed MAC over the report body is the anchor the forger lacks.
        macked = {field: value for field, value in body.items()
                  if field != "campaign_mac"}
        _mac_equal(report["campaign_mac"], _mac(anchor_key, macked),
                   "campaign_mac")
        _require(report["schema"] == SCHEMA, "report_schema")
        # The producer sealed the run it executed and the store it wrote.  A
        # byte-identical clone of that store refuses at a second path, and one
        # execution identity cannot be re-used to seal a second campaign,
        # because store_sha256 differs and both are inside the keyed MAC.
        _text(report["execution_sha256"], _SHA, "report_execution_shape")
        _require(report["execution_sha256"] == execution_sha256,
                 "report_execution_binding")
        _text(report["store_sha256"], _SHA, "report_store_shape")
        _require(report["store_sha256"] == store_sha256, "report_store_binding")
        _shape(report["generation"], _REPORT_GENERATION_FIELDS,
               "report_generation_shape")
        _require(report["generation"] == expected_generation,
                 "report_generation_binding")
        # The report names the exact obligation table it was written against,
        # and the reader recomputes that digest from the table it rebuilt
        # independently.  A report sealed against a different table refuses
        # here rather than being silently reinterpreted against this one.
        _text(report["obligation_table_sha256"], _SHA, "report_table_shape")
        _require(report["obligation_table_sha256"] == table_sha256,
                 "obligation_table_binding")
        _require(report["campaign_credit"] is False
                 and report["release_authorized"] is False
                 and report["qualification_authorized"] is False
                 and report["promotion_authorized"] is False,
                 "report_authority")
        evidence = _evidence_records(root_fd, rows, anchor_key, key_hex,
                                     execution, execution_sha256)
        closed = _closed_rows(rows, evidence)
    finally:
        os.close(root_fd)

    counts = {"total": len(rows), "closed": len(closed),
              "pending": len(rows) - len(closed)}
    # The closure the reader derived from bytes, sealed by the producer inside
    # the keyed MAC.  This is what replaces the embedded rows: the producer
    # must have known exactly which rows its evidence closes, and a report that
    # names a different closure refuses even though every count still agrees.
    # Checked before the counts, because it is the substantive disagreement:
    # a wrong closure almost always makes the counts wrong too, and naming the
    # counts there would report a symptom instead of the cause.  The counts
    # remain independently falsifiable, since a producer can seal the right
    # closure and still miscount it.
    closure_sha256 = canonical_digest(closed)
    _text(report["closure_sha256"], _SHA, "report_closure_shape")
    _require(report["closure_sha256"] == closure_sha256, "closure_binding")
    _require(report["obligation_counts"] == counts, "obligation_counts")
    status = COMPLETE_STATUS if not counts["pending"] else INCOMPLETE_STATUS
    _require(report["status"] == status, "report_status")
    # The grant loop: each gate-derived fact is evaluated, never listed.
    granted, withheld = [], {}
    closed_set = frozenset(closed)
    for fact in sorted(plan):
        open_rows = plan[fact] - closed_set
        if open_rows:
            withheld[fact] = len(open_rows)
        else:
            granted.append(fact)
    _require(report["completion_facts"] == granted, "completion_facts_binding")

    reading = rv.freeze({
        "schema": SCHEMA,
        "status": status,
        "component": COMPONENT,
        "generation": expected_generation,
        # The anchored run this reading is about.  The reader cannot know which
        # dispatch was legitimate, so it publishes the identity it verified and
        # the gate binds it to the production_execution child it actually
        # dispatched.  Without that cross-check a caller that supplies its own
        # anchor is only checking a store against itself.
        "execution_sha256": execution_sha256,
        # The exact dispatch seal the gate compares against its own dispatch
        # record, published beside the digest so the gate never has to trust a
        # caller-supplied preimage to perform that comparison.
        "execution_dispatch_sha256": execution["dispatch_sha256"],
        "execution_pid": execution["pid"],
        "execution_started_ns": execution["started_ns"],
        "execution_nonce": execution["nonce"],
        # The one store instance read, so a gate holding two readings can tell
        # whether they came from one store or two.
        "store_sha256": store_sha256,
        "obligation_counts": counts,
        "report_sha256": report["report_sha256"],
        "obligation_table_sha256": table_sha256,
        "closure_sha256": closure_sha256,
        "completion_facts": granted,
        "withheld_facts": withheld,
        "campaign_credit": False,
        "release_authorized": False,
        "qualification_authorized": False,
        "promotion_authorized": False})
    return _issue(ValidatedProductionCampaign(reading, _AUTHORITY), granted)


def validate_production_campaign(store_root, report, *, generation, anchor):
    """Re-derive from the same originals; a supplied report cannot reseal itself."""
    _require(type(report) is rv.FrozenValue, "report_not_immutable")
    rebuilt = verify_production_campaign(store_root, generation=generation,
                                         anchor=anchor)
    _require(report == rebuilt.report, "report_binding")
    return rebuilt


def completion_facts(validated):
    """Return the derived facts only for a result this reader itself issued."""
    _require(type(validated) is ValidatedProductionCampaign, "validated_type")
    derived = _issued(validated)
    report = validated.report.to_plain()
    _require(validated._authority is _AUTHORITY
             and report["schema"] == SCHEMA
             and report["component"] == COMPONENT
             and report["status"] in (COMPLETE_STATUS, INCOMPLETE_STATUS)
             and report["campaign_credit"] is False
             and report["release_authorized"] is False
             and report["qualification_authorized"] is False
             and report["promotion_authorized"] is False,
             "issued_report_binding")
    facts = report["completion_facts"]
    _require(type(facts) is list and len(set(facts)) == len(facts),
             "granted_fact_set")
    # The facts this reader derived at verify time, not the ones the carried
    # report asserts: a report is never its own evidence.
    _require(tuple(facts) == derived, "granted_fact_derivation")
    return derived


__all__ = ["SCHEMA", "EVIDENCE_SCHEMA", "CHECKLIST_SCHEMA", "COMPLETE_STATUS",
           "INCOMPLETE_STATUS", "COMPONENT", "ANCHOR_SCHEMA", "REPORT_FIELDS",
           "EVIDENCE_FIELDS", "RECORD_FIELDS", "ANCHOR_FIELDS",
           "EXECUTION_FIELDS", "GENERATION_FIELDS", "STORE_IDENTITY_FIELDS",
           "FACT_ROW_ANCHORS",
           "REPORT_NAME", "EVIDENCE_DIR", "ValidatedProductionCampaign",
           "verify_production_campaign", "validate_production_campaign",
           "completion_facts"]
