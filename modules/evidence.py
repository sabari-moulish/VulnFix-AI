"""
Evidence Management Module
Stores request/response logs, proof-of-concept outputs, and validation evidence
in JSON format and SQLite database for auditability.
"""

from pathlib import Path
import json
import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from config import EVIDENCE_DIR, get_db_connection


class EvidenceManager:
    """
    Manages safe archival of validation artifacts, request/response dumps,
    and audit trails for validated vulnerabilities.
    """

    def __init__(self, base_dir: Path = EVIDENCE_DIR):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def record_evidence(
        self,
        finding_id: str,
        evidence_type: str,
        payload: str,
        response_snippet: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Saves evidence artifact to disk and records an entry in the SQLite evidence table.
        """
        evidence_id = f"ev-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now().isoformat()
        
        evidence_record = {
            "evidence_id": evidence_id,
            "finding_id": finding_id,
            "evidence_type": evidence_type,
            "payload": payload,
            "response_snippet": response_snippet,
            "metadata": metadata or {},
            "recorded_at": timestamp,
        }

        # Save JSON file
        file_path = self.base_dir / f"{finding_id}_{evidence_id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(evidence_record, f, indent=2)

        # Store reference in SQLite
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO evidence (id, finding_id, evidence_type, payload, response_snippet, file_path)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (evidence_id, finding_id, evidence_type, payload, response_snippet, str(file_path)),
                )
                conn.commit()
        except Exception:
            # Fall back gracefully if db is in read-only or lock
            pass

        return evidence_record
