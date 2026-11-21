"""Scanner behaviour: discovery, incremental hashing, grouping, safety."""
import errno
import hashlib
import json
import os
import shutil
import time

from app import review
from app import scanner as scanner_mod
from helpers import PAYLOAD, PAYLOAD_SHA, add_plan, add_root, build_tree, run_scan


def _sha_of(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def test_content_duplicates_are_grouped(db, root):
    add_root(db, root)
    build_tree(root)
    run = run_scan(db)
    assert run["stats_json"]

    group = db.query_one("SELECT * FROM content_groups WHERE sha256=?", (PAYLOAD_SHA,))
    assert group is not None
    assert group["member_count"] == 2
    assert group["wasted_bytes"] == len(PAYLOAD)

    paths = {
        r["path"]
        for r in db.query(
            "SELECT p.path FROM file_paths p JOIN files f ON f.dev=p.dev AND f.ino=p.ino WHERE f.sha256=?",
            (PAYLOAD_SHA,),
        )
    }
    assert paths == {str(root / "a" / "dup.txt"), str(root / "b" / "dup_copy.txt")}

    files = db.query("SELECT COUNT(*) AS n FROM files WHERE status='present'")
    assert files[0]["n"] == 5


def test_unique_files_are_not_grouped(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    unique_sha = _sha_of(root / "c" / "unique.txt")
    assert db.query_one("SELECT 1 FROM content_groups WHERE sha256=?", (unique_sha,)) is None


def test_same_name_different_content_is_flagged(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    row = db.query_one("SELECT * FROM name_groups WHERE name='same_name.txt'")
    assert row is not None
    assert row["member_count"] == 2
    assert row["same_content"] == 0, "different bytes must never be reported as same content"


def test_symlinks_are_never_followed(db, root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"do-not-read")
    add_root(db, root)
    build_tree(root)
    os.symlink(outside, root / "link_to_outside")
    os.symlink(outside / "secret.txt", root / "a" / "link.txt")
    run_scan(db)
    assert db.query("SELECT 1 FROM file_paths WHERE path LIKE '%outside%'") == []
    assert db.query("SELECT 1 FROM file_paths WHERE name='link.txt'") == []


def test_exclude_globs_are_applied(db, root):
    root_id = add_root(db, root)
    build_tree(root)
    plan_id = add_plan(db, root_id, exclude_globs="b/*,c/*")
    run_scan(db, plan_id)
    assert db.query("SELECT 1 FROM file_paths WHERE path LIKE ?", (str(root / "b") + "/%",)) == []
    assert db.query("SELECT 1 FROM file_paths WHERE path=?", (str(root / "a" / "dup.txt"),)) != []


def test_second_scan_reuses_hashes(db, root):
    add_root(db, root)
    build_tree(root)
    first = run_scan(db)
    hashed_first = json.loads(first["stats_json"])["hashes_computed"]
    assert hashed_first >= 2

    second = run_scan(db)
    stats = json.loads(second["stats_json"])
    assert stats["hashes_computed"] == 0, "unchanged files must not be re-hashed"


def test_changed_file_is_rehashed(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)

    # Change a whole duplicate pair: the shared size keeps them hashing candidates,
    # which is the only case where a re-hash is expected (size changes alone are
    # not enough to make a file a candidate).
    new_bytes = b"changed-bytes-" * 2000
    targets = [root / "a" / "dup.txt", root / "b" / "dup_copy.txt"]
    for target in targets:
        target.write_bytes(new_bytes)
    new_sha = _sha_of(targets[0])

    run = run_scan(db)
    stats = json.loads(run["stats_json"])
    assert stats["hashes_computed"] >= 2
    for target in targets:
        row = db.query_one(
            "SELECT f.sha256 FROM files f JOIN file_paths p ON p.dev=f.dev AND p.ino=f.ino WHERE p.path=?",
            (str(target),),
        )
        assert row["sha256"] == new_sha


def test_removed_file_marks_record_missing(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    (root / "b" / "dup_copy.txt").unlink()
    run_scan(db)
    assert db.query("SELECT 1 FROM file_paths WHERE path=?", (str(root / "b" / "dup_copy.txt"),)) == []
    files = db.query("SELECT COUNT(*) AS n FROM files WHERE status='present'")
    assert files[0]["n"] == 4


def test_review_groups_are_synced_and_default_keep_is_earliest(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    group = review.list_groups(db, kind="content", status="pending")
    assert group["items"], "content duplicates must create pending review groups"
    g = group["items"][0]
    detail = review.group_detail(db, g["id"])
    assert len(detail["items"]) == 2
    decisions = [i["decision"] for i in detail["items"]]
    assert decisions.count("keep") == 1, "one member is pre-selected as keep"
    assert decisions.count("delete") == 0, "nothing is pre-selected for deletion"


def test_scan_without_plan_scans_all_roots(db, root, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "x.txt").write_bytes(b"x" * 100)
    add_root(db, root)
    add_root(db, other)
    build_tree(root)
    run_scan(db)
    assert db.query("SELECT 1 FROM file_paths WHERE path=?", (str(other / "x.txt"),)) != []


def test_empty_files_are_not_grouped(db, root):
    # Documented limitation: 0-byte files are never promoted to duplicates.
    # Deleting an empty file reclaims no space, so reporting them as duplicate
    # groups would only add noise and delete risk (see docs/04-开发说明.md).
    (root / "e1.dat").write_bytes(b"")
    (root / "e2.dat").write_bytes(b"")
    add_root(db, root)
    run_scan(db)
    empty_sha = hashlib.sha256(b"").hexdigest()
    row = db.query_one("SELECT * FROM content_groups WHERE sha256=?", (empty_sha,))
    assert row is None


def test_new_duplicate_next_to_cached_hashes_joins_content_group(db, root):
    """Regression for review P1-02: cached hashes must not hide a new duplicate."""
    add_root(db, root)
    (root / "a").mkdir()
    (root / "b").mkdir()
    (root / "a" / "dup.txt").write_bytes(PAYLOAD)
    (root / "b" / "dup_copy.txt").write_bytes(PAYLOAD)
    first = json.loads(run_scan(db)["stats_json"])
    assert first["hashes_computed"] == 2

    (root / "c").mkdir()
    (root / "c" / "dup_third.txt").write_bytes(PAYLOAD)
    second = run_scan(db)
    stats = json.loads(second["stats_json"])
    assert stats["hashes_computed"] >= 1, "the new duplicate must be fully hashed"

    group = db.query_one("SELECT * FROM content_groups WHERE sha256=?", (PAYLOAD_SHA,))
    assert group is not None
    assert group["member_count"] == 3
    assert group["wasted_bytes"] == 2 * len(PAYLOAD)
    unhashed = db.query_one(
        "SELECT COUNT(*) AS n FROM files WHERE status='present' AND sha256 IS NULL"
    )
    assert unhashed["n"] == 0


def test_new_same_size_file_next_to_cached_hashes_is_not_grouped(db, root):
    """A same-size newcomer must be compared, not assumed to be a duplicate."""
    add_root(db, root)
    (root / "a").mkdir()
    (root / "b").mkdir()
    (root / "a" / "dup.txt").write_bytes(PAYLOAD)
    (root / "b" / "dup_copy.txt").write_bytes(PAYLOAD)
    run_scan(db)

    (root / "c").mkdir()
    decoy = b"Z" * len(PAYLOAD)  # same size, different content
    (root / "c" / "same_size.bin").write_bytes(decoy)
    run_scan(db)

    assert db.query_one(
        "SELECT 1 FROM content_groups WHERE sha256=?", (hashlib.sha256(decoy).hexdigest(),)
    ) is None
    group = db.query_one("SELECT * FROM content_groups WHERE sha256=?", (PAYLOAD_SHA,))
    assert group["member_count"] == 2
    assert group["wasted_bytes"] == len(PAYLOAD)
    row = db.query_one(
        "SELECT f.sha256 FROM files f JOIN file_paths p ON p.dev=f.dev AND p.ino=f.ino "
        "WHERE p.path=?",
        (str(root / "c" / "same_size.bin"),),
    )
    assert row["sha256"] == hashlib.sha256(decoy).hexdigest()


def test_include_scoped_plan_does_not_expire_unrelated_files(db, root):
    """A plan with include_globs must not mark files outside its scope missing."""
    root_id = add_root(db, root)
    build_tree(root)
    run_scan(db)
    plan_id = add_plan(db, root_id, include_globs="*.txt")
    run = run_scan(db, plan_id)
    stats = json.loads(run["stats_json"])
    assert stats["files_indexed"] == 0
    assert db.query("SELECT COUNT(*) AS n FROM file_paths")[0]["n"] == 5
    assert db.query("SELECT COUNT(*) AS n FROM files WHERE status='present'")[0]["n"] == 5


def _indexed_paths(db) -> set:
    return {row["path"] for row in db.query("SELECT path FROM file_paths")}


def test_exclude_plan_clears_paths_indexed_by_earlier_unrestricted_scan(db, root):
    """DEF-01 (FR-007): a plan's exclude rules must also clean the index.

    Scenario from QA: scan without rules first, then scan with the NAS exclusion
    set (@eaDir/.Trash/*.tmp). Excluded noise used to stay in file_paths, so
    review/duplicate groups kept showing thumbs.db / old.bin / keep.tmp.
    """
    root_id = add_root(db, root)
    build_tree(root)
    (root / "@eaDir").mkdir()
    (root / ".Trash").mkdir()
    (root / "@eaDir" / "thumbs.db").write_bytes(PAYLOAD)
    (root / ".Trash" / "old.bin").write_bytes(PAYLOAD)
    (root / "a" / "keep.tmp").write_bytes(PAYLOAD)
    run_scan(db)  # first run: no rules, noise joins the index and the groups

    noise = ["@eaDir/thumbs.db", ".Trash/old.bin", "a/keep.tmp"]
    assert {str(root / p) for p in noise} <= _indexed_paths(db)

    plan_id = add_plan(
        db,
        root_id,
        exclude_globs="@eaDir/**,*/@eaDir/*,**/@eaDir/*,.Trash/**,*/.Trash/*,"
        "**/.Trash/*,*.tmp",
    )
    run = run_scan(db, plan_id)
    assert run["status"] == "completed"

    paths = _indexed_paths(db)
    assert len(paths) == 5, f"only the five real files may remain: {sorted(paths)}"
    for rel in noise:
        assert str(root / rel) not in paths
    assert db.query("SELECT COUNT(*) AS n FROM files WHERE status='present'")[0]["n"] == 5

    group = db.query_one("SELECT * FROM content_groups WHERE sha256=?", (PAYLOAD_SHA,))
    assert group is not None and group["member_count"] == 2, "excluded copies must leave the group"
    review_groups = review.list_groups(db, kind="content", status="pending")["items"]
    members = [
        item["path"]
        for g in review_groups
        for item in review.group_detail(db, g["id"])["items"]
    ]
    assert set(members) == {str(root / "a" / "dup.txt"), str(root / "b" / "dup_copy.txt")}


def test_exclude_glob_for_directory_clears_already_indexed_children(db, root):
    """DEF-01: excluding a directory name also drops children indexed earlier."""
    root_id = add_root(db, root)
    build_tree(root)
    (root / ".Trash").mkdir()
    (root / ".Trash" / "old.bin").write_bytes(PAYLOAD)
    run_scan(db)
    assert str(root / ".Trash" / "old.bin") in _indexed_paths(db)

    plan_id = add_plan(db, root_id, exclude_globs=".Trash")
    run_scan(db, plan_id)

    assert str(root / ".Trash" / "old.bin") not in _indexed_paths(db)
    assert db.query("SELECT COUNT(*) AS n FROM files WHERE status='present'")[0]["n"] == 5
    group = db.query_one("SELECT * FROM content_groups WHERE sha256=?", (PAYLOAD_SHA,))
    assert group is not None and group["member_count"] == 2


def test_deleted_directory_still_marks_files_missing(db, root):
    """When a directory really disappears, its entries are still expired."""
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    shutil.rmtree(root / "b")
    run_scan(db)
    assert db.query("SELECT 1 FROM file_paths WHERE path=?", (str(root / "b" / "dup_copy.txt"),)) == []
    assert db.query("SELECT COUNT(*) AS n FROM files WHERE status='present'")[0]["n"] == 4


# ---- DEF-03 (FR-013): skipped paths carry a reason -----------------------

def test_skipped_records_symlink_and_special_files(db, root, tmp_path):
    """DEF-03: symlinks / FIFOs are reported with a reason instead of vanishing."""
    add_root(db, root)
    build_tree(root)
    os.symlink(root / "a" / "dup.txt", root / "link.txt")
    os.symlink(str(tmp_path / "not-there"), root / "dangling")
    fifo = root / "pipe"
    if hasattr(os, "mkfifo"):
        os.mkfifo(fifo)

    run = run_scan(db)
    stats = json.loads(run["stats_json"])
    skipped = stats["skipped"]
    assert skipped["by_reason"]["symlink"] == 2
    assert skipped["by_reason"]["special"] == 1
    items = {item["path"]: item["reason"] for item in skipped["items"]}
    assert items[str(root / "link.txt")] == "symlink"
    assert items[str(fifo)] == "special"
    assert stats["errors"] == [], "a known skip must not be reported as a hard error"
    assert db.query("SELECT 1 FROM file_paths WHERE name='link.txt'") == []


def test_skipped_items_are_capped_while_counts_stay_exact(db, root):
    """DEF-03: a root full of symlinks must not inflate stats_json unboundedly."""
    add_root(db, root)
    target = root / "target.txt"
    target.write_bytes(b"x")
    for i in range(210):
        os.symlink(target, root / f"link-{i}.dat")

    run = run_scan(db)
    skipped = json.loads(run["stats_json"])["skipped"]
    assert skipped["count"] == 210
    assert skipped["by_reason"]["symlink"] == 210
    assert len(skipped["items"]) == 200, "items are capped, the count stays accurate"


def test_unreadable_file_is_skipped_and_aggregated_notification(db, root, monkeypatch):
    """DEF-03: EACCES during hashing -> skipped(permission) + one security notice."""
    add_root(db, root)
    (root / "a").mkdir()
    (root / "b").mkdir()
    small = b"tiny-duplicate-" * 10  # <= 2 * SAMPLE_BYTES -> full-hash branch
    secret = root / "secret.txt"
    secret.write_bytes(small)
    (root / "a" / "d1.txt").write_bytes(small)
    (root / "b" / "d2.txt").write_bytes(small)

    original = scanner_mod._sha256_file

    def unreadable(path, limiter):
        if os.fspath(path) == str(secret):
            raise PermissionError(errno.EACCES, "Permission denied")
        return original(path, limiter)

    monkeypatch.setattr(scanner_mod, "_sha256_file", unreadable)
    run = run_scan(db)

    stats = json.loads(run["stats_json"])
    skipped = stats["skipped"]
    assert skipped["by_reason"]["permission"] == 1
    assert skipped["items"][0]["path"] == str(secret)
    assert stats["errors"] == [], "permission problems are skips, not parse errors"
    assert str(secret) in _indexed_paths(db), "metadata stays indexed; only hashing was skipped"
    row = db.query_one(
        "SELECT f.sha256 FROM files f JOIN file_paths p ON p.dev=f.dev AND p.ino=f.ino "
        "WHERE p.path=?",
        (str(secret),),
    )
    assert row["sha256"] is None

    notes = db.query("SELECT * FROM notifications WHERE kind='security'")
    matching = [n for n in notes if n["title"] == "部分文件无法读取"]
    assert len(matching) == 1, "the skip is summarised once per run"
    assert "1 个文件" in matching[0]["body"]
    # The readable duplicates are still grouped normally.
    group = db.query_one(
        "SELECT * FROM content_groups WHERE sha256=?",
        (hashlib.sha256(small).hexdigest(),),
    )
    assert group is not None and group["member_count"] == 2


# ---- DEF-04 (FR-015): abnormal directory drop raises a security alert ---

def test_directory_drop_writes_security_notification_and_audit(db, root):
    """DEF-04: an abnormal directory-count drop is not just a hidden column."""
    add_root(db, root)
    build_tree(root)
    first = run_scan(db)
    assert first["incomplete_reason"] is None

    # 4 dirs -> 2 dirs is a 50% drop, well past the 20% threshold.
    shutil.rmtree(root / "b")
    shutil.rmtree(root / "c")
    second = run_scan(db)

    assert second["incomplete_reason"]
    notes = db.query("SELECT * FROM notifications WHERE kind='security' ORDER BY id")
    alerts = [n for n in notes if n["title"] == "扫描不完整，请检查挂载/权限"]
    assert len(alerts) == 1, "the alert must be raised exactly once per scan"
    assert "本次" in alerts[0]["body"] and "上次" in alerts[0]["body"]

    audit = db.query("SELECT * FROM audit_log WHERE action='scan.incomplete'")
    assert len(audit) == 1
    assert "目录" in audit[0]["detail"]

