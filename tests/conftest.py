"""Test bootstrap: point the app at throwaway directories before import."""
import os
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="dupe-test-")
_ROOT = Path(_TMP) / "root"
_DATA = Path(_TMP) / "data"
_ROOT.mkdir(parents=True)
_DATA.mkdir(parents=True)

os.environ["DATA_DIR"] = str(_DATA)
os.environ["DB_PATH"] = str(_DATA / "db" / "dupe.db")
os.environ["MOUNT_ROOTS"] = str(_ROOT)

import pytest  # noqa: E402

from app.db import Database, now_iso, reset_db_for_tests  # noqa: E402


@pytest.fixture()
def db(tmp_path):
    database = reset_db_for_tests(str(tmp_path / "dupe.db"))
    database.set_setting("default_keep_policy", "earliest_mtime")
    yield database
    database.close()


@pytest.fixture()
def root(tmp_path):
    p = tmp_path / "data"
    p.mkdir()
    return p
