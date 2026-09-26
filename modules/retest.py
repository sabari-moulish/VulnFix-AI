"""
Retest & Proof-of-Fix Module
AI-Powered Vulnerability Validation and Proof-of-Fix Platform
Track: Offensive Security & Red Teaming

Re-evaluates remediated targets with safe verification probes to prove the fix
and ensure no regression or bypass exists.
Consumes:
- FindingCandidate results from modules.vulnerability_detector
- RemediationPlan results from modules.remediation
- ValidationOutcome results from modules.validator

Reuses existing deterministic validation logic from VulnerabilityValidator.
Distinguishes:
- FIXED_VERIFIED: Defensive controls active, probe neutralized.
- STILL_VULNERABLE: Vulnerability persists and was reproduced.
- INCONCLUSIVE: Probing yielded indeterminate signals.
- BLOCKED_OUT_OF_SCOPE: Target out of authorized testing boundaries.

Persists retest outcomes to SQLite database and reports directory.
"""

from typing import Dict, Any, Optional, Union, List, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
import json
import uuid
from pathlib import Path

from config import get_db_connection, REPORTS_DIR
from modules.scope_controller import ScopeController
from modules.validator import VulnerabilityValidator, ValidationOutcome
from modules.vulnerability_detector import FindingCandidate
from modules.remediation import RemediationPlan


@dataclass
class RetestResult:
    """Proof-of-Fix validation outcome."""
    finding_id: str
    target_url: str
    status: str  # 'FIXED_VERIFIED', 'STILL_VULNERABLE', 'INCONCLUSIVE', 'BLOCKED_OUT_OF_SCOPE'
    proof_of_fix_details: str
    tested_at: str
    retest_id: Optional[str] = None
    report_file: Optional[str] = None
    validation_outcome: Optional[Dict[str, Any]] = None
    verification_steps_checked: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the retest result to a dictionary."""
        return asdict(self)


class RetestEngine:
    """
    Automates post-remediation verification on explicitly authorized local targets.
    Reuses VulnerabilityValidator to assert fix effectiveness without duplicating detection logic.
    """

    def __init__(
        self,
        scope_controller: Optional[ScopeController] = None,
        validator: Optional[VulnerabilityValidator] = None,
        reports_dir: Optional[Path] = None,
        max_requests: int = 25,
        timeout: float = 3.0,
    ):
        self.scope_controller = scope_controller or ScopeController()
        self.validator = validator or VulnerabilityValidator(
            scope_controller=self.scope_controller,
            max_requests=max_requests,
            timeout=timeout,
        )
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _normalize_finding_and_steps(
        self,
        finding: Union[FindingCandidate, RemediationPlan, Dict[str, Any]],
        remediation_plan: Optional[Union[RemediationPlan, Dict[str, Any]]] = None,
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Extracts uniform finding metadata and verification steps from candidate, remediation, or dict inputs.
        """
        steps: List[str] = []

        if isinstance(remediation_plan, RemediationPlan):
            steps = list(remediation_plan.verification_steps)
        elif isinstance(remediation_plan, dict):
            steps = list(remediation_plan.get("verification_steps", []))

        if isinstance(finding, RemediationPlan):
            if not steps:
                steps = list(finding.verification_steps)
            norm = {
                "id": finding.finding_id,
                "vuln_type": finding.vuln_type,
                "cwe_id": finding.cwe_id,
                "endpoint": finding.endpoint,
                "affected_parameter": finding.affected_parameter,
                "title": finding.title,
                "is_vulnerable": True,
            }
        elif isinstance(finding, FindingCandidate):
            norm = {
                "id": finding.id,
                "vuln_type": finding.vuln_type,
                "cwe_id": finding.cwe_id,
                "endpoint": finding.endpoint,
                "affected_parameter": finding.affected_parameter,
                "input_location": finding.input_location,
                "title": finding.title,
                "is_vulnerable": finding.is_vulnerable,
                "evidence": finding.evidence,
            }
        elif isinstance(finding, dict):
            if not steps and "verification_steps" in finding:
                steps = list(finding["verification_steps"])
            norm = {
                "id": finding.get("id") or finding.get("finding_id", f"FIND-{uuid.uuid4().hex[:6].upper()}"),
                "vuln_type": finding.get("vuln_type", ""),
                "cwe_id": finding.get("cwe_id", ""),
                "endpoint": finding.get("endpoint", ""),
                "affected_parameter": finding.get("affected_parameter") or finding.get("param"),
                "title": finding.get("title", ""),
                "is_vulnerable": finding.get("is_vulnerable", True),
                "evidence": finding.get("evidence", {}),
            }
        else:
            norm = {
                "id": "unknown",
                "vuln_type": "",
                "cwe_id": "",
                "endpoint": "",
                "affected_parameter": None,
                "is_vulnerable": True,
            }

        return norm, steps

    def _persist_retest(self, result: RetestResult) -> None:
        """
        Persists retest result to SQLite retests table and JSON report artifact.
        """
        # 1. Save JSON report artifact
        try:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            report_path = self.reports_dir / f"retest_{result.finding_id}_{result.retest_id}.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2)
            result.report_file = str(report_path)
        except Exception:
            pass

        # 2. Persist in SQLite retests table
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Ensure findings table has entry for this finding
                cursor.execute("SELECT id FROM findings WHERE id = ?", (result.finding_id,))
                row = cursor.fetchone()
                if not row:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO findings (id, target_url, title, vuln_type, cwe_id, severity, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            result.finding_id,
                            result.target_url,
                            f"Finding {result.finding_id}",
                            "UNKNOWN",
                            "CWE-Unknown",
                            "INFO",
                            result.status,
                        ),
                    )
                else:
                    # Update status in findings table based on proof-of-fix
                    new_status = "REMEDIATED" if result.status == "FIXED_VERIFIED" else ("STILL_VULNERABLE" if result.status == "STILL_VULNERABLE" else "RETESTED")
                    cursor.execute(
                        "UPDATE findings SET status = ? WHERE id = ?",
                        (new_status, result.finding_id),
                    )

                cursor.execute(
                    """
                    INSERT OR REPLACE INTO retests (id, finding_id, status, proof_of_fix, tested_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        result.retest_id,
                        result.finding_id,
                        result.status,
                        result.proof_of_fix_details,
                        result.tested_at,
                    ),
                )
                conn.commit()
        except Exception:
            pass

    def verify_fix(
        self,
        target_url: str,
        finding: Union[FindingCandidate, RemediationPlan, Dict[str, Any]],
        remediation_plan: Optional[Union[RemediationPlan, Dict[str, Any]]] = None,
        persist: bool = True,
    ) -> RetestResult:
        """
        Re-probes the endpoint to confirm whether the vulnerability has been remediated.
        Reuses VulnerabilityValidator for deterministic, safe verification.
        Distinguishes: FIXED_VERIFIED, STILL_VULNERABLE, INCONCLUSIVE, BLOCKED_OUT_OF_SCOPE.
        """
        norm_finding, steps = self._normalize_finding_and_steps(finding, remediation_plan)
        finding_id = norm_finding["id"]
        tested_at = datetime.now().isoformat()
        retest_id = f"ret-{uuid.uuid4().hex[:8]}"

        # 1. Scope Controller Authorization Check
        scope_res = self.scope_controller.authorize_operation(
            target_url, operation="PROOF_OF_FIX_RETEST"
        )
        if not scope_res.is_allowed:
            result = RetestResult(
                finding_id=finding_id,
                target_url=target_url,
                status="BLOCKED_OUT_OF_SCOPE",
                proof_of_fix_details=f"Scope violation: {scope_res.reason}",
                tested_at=tested_at,
                retest_id=retest_id,
                verification_steps_checked=steps,
            )
            if persist:
                self._persist_retest(result)
            return result

        # 2. Re-probe using VulnerabilityValidator
        outcome: ValidationOutcome = self.validator.validate_finding(target_url, norm_finding)
        outcome_dict = asdict(outcome)

        # 3. Determine Retest Status & Proof-of-Fix Narrative
        if outcome.validation_status == "CONFIRMED" or outcome.is_confirmed:
            status = "STILL_VULNERABLE"
            details = (
                f"Vulnerability persists (STILL_VULNERABLE). Safe verification reproduced the defect: "
                f"{outcome.proof_of_concept_safe or outcome.details}. "
                f"Differential observed: {outcome.differential_observed or 'Anomaly confirmed'}."
            )
        elif outcome.validation_status in ("NOT_CONFIRMED", "SAFELY_ENCODED", "ACCESS_PROPERLY_CONTROLLED"):
            status = "FIXED_VERIFIED"
            details = (
                f"Remediation verified (FIXED_VERIFIED). Defensive controls successfully neutralized probe input: "
                f"{outcome.details}. {outcome.differential_observed or 'No differential anomaly observed'}."
            )
        elif outcome.validation_status == "BLOCKED_OUT_OF_SCOPE":
            status = "BLOCKED_OUT_OF_SCOPE"
            details = f"Retest blocked: {outcome.details}"
        else:
            status = "INCONCLUSIVE"
            details = (
                f"Retest outcome inconclusive (INCONCLUSIVE). Response differences did not decisively verify "
                f"or refute remediation: {outcome.details}."
            )

        if steps:
            details += f" | Verification steps evaluated: {'; '.join(steps)}"

        result = RetestResult(
            finding_id=finding_id,
            target_url=target_url,
            status=status,
            proof_of_fix_details=details.strip(),
            tested_at=tested_at,
            retest_id=retest_id,
            validation_outcome=outcome_dict,
            verification_steps_checked=steps,
        )

        if persist:
            self._persist_retest(result)

        return result

    def retest_candidates(
        self,
        target_url: str,
        findings: List[Union[FindingCandidate, RemediationPlan, Dict[str, Any]]],
        remediations: Optional[List[Union[RemediationPlan, Dict[str, Any]]]] = None,
        persist: bool = True,
    ) -> List[RetestResult]:
        """
        Retests a batch of findings against an authorized local target.
        """
        rem_map: Dict[str, Any] = {}
        if remediations:
            for r in remediations:
                fid = r.finding_id if isinstance(r, RemediationPlan) else r.get("finding_id")
                if fid:
                    rem_map[fid] = r

        results: List[RetestResult] = []
        for f in findings:
            if isinstance(f, RemediationPlan):
                fid = f.finding_id
            elif isinstance(f, FindingCandidate):
                fid = f.id
            else:
                fid = f.get("id") or f.get("finding_id")

            rem_match = rem_map.get(fid) if fid else None
            res = self.verify_fix(target_url, f, remediation_plan=rem_match, persist=persist)
            results.append(res)

        return results

    # Convenience aliases
    retest_all = retest_candidates
    verify_all = retest_candidates
