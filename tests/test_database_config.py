import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from database_config import (
    DEFAULT_DATABASE_PATH,
    resolve_database_path,
)
from fabric.persistent_db import PersistentStorageEngine


class TestDatabasePathConfiguration(unittest.TestCase):
    def test_uses_legacy_default_when_environment_is_unset(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                resolve_database_path(),
                DEFAULT_DATABASE_PATH,
            )

    def test_uses_environment_path_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = str(Path(temp_dir) / "agenttrust.db")
            with patch.dict(
                os.environ,
                {"AGENTTRUST_DB_PATH": target},
                clear=True,
            ):
                self.assertEqual(resolve_database_path(), target)

    def test_explicit_path_overrides_environment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            configured = str(Path(temp_dir) / "configured.db")
            explicit = str(Path(temp_dir) / "explicit.db")
            with patch.dict(
                os.environ,
                {"AGENTTRUST_DB_PATH": configured},
                clear=True,
            ):
                self.assertEqual(resolve_database_path(explicit), explicit)

    def test_empty_environment_path_raises_value_error(self):
        with patch.dict(os.environ, {"AGENTTRUST_DB_PATH": "   "}, clear=True):
            with self.assertRaises(ValueError):
                resolve_database_path()

    def test_persistent_storage_engine_adopts_environment_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = str(Path(temp_dir) / "sub" / "agenttrust.db")
            with patch.dict(
                os.environ,
                {"AGENTTRUST_DB_PATH": target},
                clear=True,
            ):
                engine = PersistentStorageEngine()
                self.assertEqual(engine.db_path, target)
                self.assertTrue(Path(target).parent.exists())
                self.assertTrue(Path(target).exists())
                engine.close()


if __name__ == "__main__":
    unittest.main()
