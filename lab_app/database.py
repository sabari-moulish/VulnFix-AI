"""
Database management for the intentionally vulnerable local security lab.
Uses SQLite strictly with synthetic/fake test data.
"""

from pathlib import Path
import sqlite3
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "lab_data.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_db() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(reset: bool = False) -> None:
    """Initializes the database using schema.sql and seeds synthetic test data."""
    if reset or not DB_PATH.exists():
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_script = f.read()
        
        with sqlite3.connect(DB_PATH) as conn:
            conn.executescript(schema_script)
            conn.commit()


# Initialize database upon import if not yet present
init_db()
