"""
Platform Configuration & Database Initialization
AI-Powered Vulnerability Validation and Proof-of-Fix Platform
Track: Offensive Security & Red Teaming
"""

from pathlib import Path
import sqlite3
import json
from typing import List
from urllib.parse import urlparse

# Base Project Directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
FINDINGS_DIR = DATA_DIR / "findings"
EVIDENCE_DIR = DATA_DIR / "evidence"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "platform.db"

# Scope Control & Safety Boundaries
# STRICT POLICY: Only locally hosted, intentionally vulnerable testbeds are permitted.
STRICT_LOCAL_ONLY: bool = True
ALLOWED_SCHEMES: tuple = ("http", "https")
DEFAULT_ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "::1"]

# Standard local development / testbed ports
DEFAULT_ALLOWED_PORTS: List[int] = [
    80, 443, 3000, 4200, 5000, 5173, 8000, 8080, 8443, 8888, 9000, 9090
]

# Explicitly allowed local test target base URLs
# Default allows only local loopback targets
DEFAULT_EXPLICIT_TARGETS: List[str] = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:5000",
    "http://localhost:5000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]

EXPLICIT_ALLOWED_TARGETS: List[str] = list(DEFAULT_EXPLICIT_TARGETS)
AUTHORIZED_TARGETS_FILE = DATA_DIR / "authorized_targets.json"
SCOPE_AUDIT_LOG_FILE = DATA_DIR / "scope_audit_log.json"


def ensure_directories() -> None:
    """Ensure all required runtime data directories exist."""
    for directory in [DATA_DIR, FINDINGS_DIR, EVIDENCE_DIR, REPORTS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory configured."""
    ensure_directories()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database() -> None:
    """Initializes the SQLite schema for persistent findings, evidence, and re-test tracking."""
    ensure_directories()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Targets Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                host TEXT NOT NULL,
                port INTEGER,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                authorized INTEGER DEFAULT 1
            )
        """)

        # Findings Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                title TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                cwe_id TEXT,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'DETECTED',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Evidence Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                payload TEXT,
                response_snippet TEXT,
                file_path TEXT,
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )
        """)

        # Validations Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS validations (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                is_reproducible INTEGER NOT NULL,
                validation_method TEXT NOT NULL,
                validation_log TEXT,
                validated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )
        """)

        # Remediations Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediations (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                fix_summary TEXT NOT NULL,
                code_patch TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )
        """)

        # Retest Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS retests (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                status TEXT NOT NULL,
                proof_of_fix TEXT,
                tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )
        """)

        # Scope Audit Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scope_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                operation TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        # Risk Assessments Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_assessments (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                risk_score REAL NOT NULL,
                severity TEXT NOT NULL,
                exploitability_score REAL NOT NULL,
                impact_score REAL NOT NULL,
                confidence_score REAL NOT NULL,
                remediation_priority TEXT NOT NULL,
                remediation_urgency TEXT NOT NULL,
                summary TEXT,
                factors_json TEXT NOT NULL,
                assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )
        """)

        conn.commit()


def load_authorized_targets() -> List[str]:
    """Loads authorized targets from JSON config, falling back to defaults."""
    ensure_directories()
    if AUTHORIZED_TARGETS_FILE.exists():
        try:
            with open(AUTHORIZED_TARGETS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list) and data:
                    return data
        except Exception:
            pass
    # Persist defaults initially
    save_authorized_targets(DEFAULT_EXPLICIT_TARGETS)
    return list(DEFAULT_EXPLICIT_TARGETS)


def save_authorized_targets(targets: List[str]) -> None:
    """Saves explicitly authorized targets to persistent JSON file and targets table."""
    ensure_directories()
    unique_targets = sorted(list(set(targets)))
    try:
        with open(AUTHORIZED_TARGETS_FILE, "w", encoding="utf-8") as f:
            json.dump(unique_targets, f, indent=2)
    except Exception:
        pass

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            for t in unique_targets:
                parsed = urlparse(t)
                try:
                    explicit_port = parsed.port
                except ValueError:
                    explicit_port = None

                if parsed.scheme:
                    host = parsed.hostname or t.split("//")[-1].split(":")[0].split("/")[0]
                    if explicit_port is not None:
                        port = explicit_port
                    else:
                        port = 443 if parsed.scheme.lower() == "https" else 80
                else:
                    host = t.split("//")[-1].split(":")[0].split("/")[0]
                    if ":" in t.split("//")[-1]:
                        try:
                            port = int(t.split(":")[-1].split("/")[0])
                        except ValueError:
                            port = 80
                    else:
                        port = 80

                cursor.execute(
                    "INSERT OR IGNORE INTO targets (url, host, port, authorized) VALUES (?, ?, ?, 1)",
                    (t, host, port),
                )
            conn.commit()
    except Exception:
        pass


# Automatically initialize directories and database when config is imported
ensure_directories()
init_database()
