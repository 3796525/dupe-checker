"""Scanner behaviour: discovery, incremental hashing, grouping, safety."""
import hashlib
import json
import os
import time

from app import review
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
