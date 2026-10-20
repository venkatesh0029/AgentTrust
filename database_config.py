import os
from os import PathLike

DEFAULT_DATABASE_PATH = "agenttrust_persistent.db"


def resolve_database_path(
    db_path: str | PathLike[str] | None = None,
) -> str:
    """Resolve an explicit database path or the shared environment setting."""
    if db_path is not None:
        return os.fspath(db_path)
    configured_path = os.environ.get("AGENTTRUST_DB_PATH")
    if configured_path is None:
        return DEFAULT_DATABASE_PATH
    configured_path = configured_path.strip()
    if not configured_path:
        raise ValueError("AGENTTRUST_DB_PATH must not be empty.")
    return configured_path
