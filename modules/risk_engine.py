"""
Risk Assessment Engine Module
AI-Powered Vulnerability Validation and Proof-of-Fix Platform
Track: Offensive Security & Red Teaming

Computes transparent, rule-based contextual risk scores, exploitability, impact,
and remediation priorities for vulnerability findings.
Consumes:
- FindingCandidate results from modules.vulnerability_detector
- ValidationOutcome results from modules.validator

No external LLM or public APIs. Strictly local, deterministic assessment.
Persists assessments in SQLite database and reports directory.
"""

from typing import Dict, Any, Optional, Union, List, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
import json
import uuid
from pathlib import Path

from config import get_db_connection, REPORTS_DIR
from modules.vulnerability_detector import FindingCandidate
from modules.validator import ValidationOutcome


@dataclass
class RiskFactors:
    """Breakdown of individual scoring factors contributing to the composite risk score."""
    vuln_type: str
    cwe_id: str
    base_exploitability: float
    exploitability_score: float
    base_impact: float
    impact_score: float
    confidence_score: float
    evidence_strength: float
    validation_status: str
    validation_multiplier: float
    is_confirmed: bool
    context_modifiers: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Comprehensive contextual risk assessment for a vulnerability finding."""
    assessment_id: str
    finding_id: str
    risk_score: float  # Normalized strictly 0.0 - 10.0
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    remediation_priority: str  # P1, P2, P3, P4
    remediation_urgency: str  # CRITICAL_IMMEDIATE, HIGH_PRIORITY, MODERATE_PRIORITY, LOW_PRIORITY
    exploitability: float  # 0.0 - 10.0
    impact: float  # 0.0 - 10.0
    confidence: float  # 0.0 - 1.0
    factors: RiskFactors
    summary: str
    assessed_at: str
    target_url: str = ""
    report_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the assessment to a dictionary."""
        return asdict(self)


class RiskEngine:
    """
    Transparent, rule-based contextual risk engine.
    Calculates multi-dimensional risk metrics based on:
    - Vulnerability class (CWE-89, CWE-79, CWE-639)
    - Validation proof outcome (CONFIRMED, NOT_CONFIRMED, INCONCLUSIVE)
    - Exposure context (API vs UI, query vs path parameter)
    - Impact scope (tenant isolation breach, data leak)
    - Evidence strength (differential proof, PoC availability)
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 10.0,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "INFO": 0.5,
    }

    BASE_EXPLOITABILITY = {
        "SQL_INJECTION": 8.5,
        "CWE-89": 8.5,
        "BROKEN_ACCESS_CONTROL": 9.0,
        "IDOR": 9.0,
        "CWE-639": 9.0,
        "REFLECTED_XSS": 7.0,
        "CWE-79": 7.0,
    }

    BASE_IMPACT = {
        "SQL_INJECTION": 9.0,
        "CWE-89": 9.0,
        "BROKEN_ACCESS_CONTROL": 8.5,
        "IDOR": 8.5,
        "CWE-639": 8.5,
        "REFLECTED_XSS": 6.0,
        "CWE-79": 6.0,
    }

    def __init__(self, reports_dir: Optional[Path] = None):
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def calculate_score(vuln_type: str, severity: str, is_validated: bool) -> Dict[str, Any]:
        """
        Calculates normalized risk score and priority.
        Preserved for backward-compatibility with earlier scaffold tests.
        """
        base_weight = RiskEngine.SEVERITY_WEIGHTS.get(severity.upper(), 3.0)
        validation_multiplier = 1.2 if is_validated else 0.8
        score = min(10.0, max(0.0, round(base_weight * validation_multiplier, 1)))

        return {
            "score": score,
            "severity": severity.upper(),
            "is_validated": is_validated,
            "remediation_urgency": "IMMEDIATE" if score >= 8.0 else ("MODERATE" if score >= 5.0 else "LOW"),
            "remediation_priority": "P1" if score >= 8.0 else ("P2" if score >= 5.0 else "P4"),
        }

    def _compute_exploitability(
        self,
        vuln_type: str,
        cwe_id: str,
        endpoint: str,
        param_location: str,
        has_poc: bool,
    ) -> Tuple[float, float, Dict[str, float]]:
        """
        Computes exploitability score (1.0 - 10.0) with granular contextual modifiers.
        """
        key = vuln_type.upper() if vuln_type else cwe_id.upper()
        base = self.BASE_EXPLOITABILITY.get(key, self.BASE_EXPLOITABILITY.get(cwe_id.upper(), 5.0))
        mods: Dict[str, float] = {}

        # Exposure: API endpoints are machine-automatable without CSRF/rendering barriers
        if "/api/" in endpoint or endpoint.startswith("api"):
            mods["api_endpoint_exposure"] = 1.0

        # Location: URL query/path parameters are accessible via direct link sharing
        if param_location in ("query_param", "path_param"):
            mods["url_accessible_input"] = 0.5
        elif param_location == "form_body":
            mods["post_body_input"] = 0.2

        # Actionable PoC availability
        if has_poc:
            mods["verified_poc_available"] = 0.5

        total = base + sum(mods.values())
        bounded = min(10.0, max(1.0, round(total, 2)))
        return base, bounded, mods

    def _compute_impact(
        self,
        vuln_type: str,
        cwe_id: str,
        endpoint: str,
        is_cross_tenant: bool,
    ) -> Tuple[float, float, Dict[str, float]]:
        """
        Computes impact score (1.0 - 10.0) with contextual breach modifiers.
        """
        key = vuln_type.upper() if vuln_type else cwe_id.upper()
        base = self.BASE_IMPACT.get(key, self.BASE_IMPACT.get(cwe_id.upper(), 4.0))
        mods: Dict[str, float] = {}

        # Multi-tenant breach: IDOR crossing tenant boundary into foreign organization data
        if is_cross_tenant:
            mods["cross_tenant_data_leak"] = 1.5

        # Structured data exposure in API responses
        if "/api/" in endpoint or endpoint.startswith("api"):
            mods["structured_api_data_exposure"] = 0.5

        total = base + sum(mods.values())
        bounded = min(10.0, max(1.0, round(total, 2)))
        return base, bounded, mods

    def _compute_confidence_and_evidence(
        self,
        finding_conf: float,
        val_conf: Optional[float],
        evidence_dict: Dict[str, Any],
        differential_text: str,
        has_poc: bool,
    ) -> Tuple[float, float, Dict[str, float]]:
        """
        Computes composite confidence (0.1 - 1.0) and evidence strength metric.
        """
        if val_conf is not None and val_conf > 0.0:
            base_conf = val_conf
        elif finding_conf > 0.0:
            base_conf = finding_conf
        else:
            base_conf = 0.5

        mods: Dict[str, float] = {}

        # Differential observed between baseline and probe
        if differential_text and differential_text.strip():
            mods["differential_observed"] = 0.05

        # Multi-probe interactions
        interactions = evidence_dict.get("raw_interactions", [])
        if interactions and len(interactions) >= 2:
            mods["multi_interaction_verification"] = 0.05

        # Actionable PoC present
        if has_poc:
            mods["reproducible_poc"] = 0.05

        evidence_strength = min(1.0, max(0.2, round(0.5 + sum(mods.values()), 2)))
        confidence_score = min(1.0, max(0.1, round(base_conf + (sum(mods.values()) * 0.5), 2)))

        return confidence_score, evidence_strength, mods

    def _compute_validation_multiplier(self, validation_status: str, is_confirmed: bool) -> float:
        """
        Calculates validation multiplier based on validation outcome:
        - CONFIRMED: 1.0 (True positive verified by secondary validation)
        - NOT_CONFIRMED: 0.1 (Proven safe / remediated / false positive - residual risk only)
        - INCONCLUSIVE: 0.6 (Candidate hypothesis unproven - potential risk discounted)
        - BLOCKED_OUT_OF_SCOPE: 0.0 (Out of scope, no authorized risk)
        """
        status = validation_status.upper()
        if status == "CONFIRMED" or is_confirmed:
            return 1.0
        elif status in ("NOT_CONFIRMED", "SAFELY_ENCODED", "ACCESS_PROPERLY_CONTROLLED", "LIKELY_NOT_VULNERABLE"):
            return 0.1
        elif status == "BLOCKED_OUT_OF_SCOPE":
            return 0.0
        else:
            return 0.6

    def _determine_severity(self, score: float) -> str:
        """Determines qualitative severity tier based on risk score."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 1.0:
            return "LOW"
        else:
            return "INFO"

    def _determine_priority_and_urgency(self, score: float) -> Tuple[str, str]:
        """
        Maps risk score to actionable remediation priorities and urgency tiers.
        - P1: Score >= 9.0 (CRITICAL_IMMEDIATE)
        - P2: 7.0 <= Score < 9.0 (HIGH_PRIORITY)
        - P3: 4.0 <= Score < 7.0 (MODERATE_PRIORITY)
        - P4: Score < 4.0 (LOW_PRIORITY)
        """
        if score >= 9.0:
            return "P1", "CRITICAL_IMMEDIATE"
        elif score >= 7.0:
            return "P2", "HIGH_PRIORITY"
        elif score >= 4.0:
            return "P3", "MODERATE_PRIORITY"
        else:
            return "P4", "LOW_PRIORITY"

    def _generate_summary(
        self,
        vuln_type: str,
        cwe_id: str,
        severity: str,
        score: float,
        priority: str,
        val_status: str,
    ) -> str:
        """Generates clear, transparent explanation of risk assessment."""
        if val_status == "CONFIRMED":
            return (
                f"CONFIRMED {severity} Risk ({score}/10.0, {priority}): Verified {vuln_type} ({cwe_id}) "
                f"with elevated exploitability and high potential impact. Immediate remediation prioritized."
            )
        elif val_status == "NOT_CONFIRMED":
            return (
                f"RESOLVED / NON-VULNERABLE ({score}/10.0, {priority}): {vuln_type} was not confirmed by validation. "
                f"Defensive controls or remediation are active. Residual operational risk is minimal."
            )
        elif val_status == "BLOCKED_OUT_OF_SCOPE":
            return (
                f"BLOCKED ({score}/10.0, {priority}): Target is out of authorized scope. No testing allowed."
            )
        else:
            return (
                f"POTENTIAL {severity} Risk ({score}/10.0, {priority}): Candidate {vuln_type} ({cwe_id}) "
                f"detected but unconfirmed. Requires review or targeted re-validation."
            )

    def _persist_assessment(self, assessment: RiskAssessment, target_url: str = "") -> None:
        """
        Persists risk assessment to SQLite database and JSON report artifact.
        """
        # 1. Save JSON report artifact
        try:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            report_path = self.reports_dir / f"risk_{assessment.finding_id}_{assessment.assessment_id}.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(assessment.to_dict(), f, indent=2)
            assessment.report_file = str(report_path)
        except Exception:
            pass

        # 2. Persist in SQLite risk_assessments table
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Ensure findings table has entry for this finding
                cursor.execute("SELECT id FROM findings WHERE id = ?", (assessment.finding_id,))
                row = cursor.fetchone()
                if not row:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO findings (id, target_url, title, vuln_type, cwe_id, severity, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            assessment.finding_id,
                            target_url or "http://127.0.0.1:5000",
                            f"Finding {assessment.finding_id}",
                            assessment.factors.vuln_type,
                            assessment.factors.cwe_id,
                            assessment.severity,
                            "CONFIRMED" if assessment.factors.is_confirmed else "ASSESSED",
                        ),
                    )
                else:
                    # Update severity in findings table to match risk assessment
                    cursor.execute(
                        "UPDATE findings SET severity = ? WHERE id = ?",
                        (assessment.severity, assessment.finding_id),
                    )

                cursor.execute(
                    """
                    INSERT OR REPLACE INTO risk_assessments (
                        id, finding_id, risk_score, severity, exploitability_score,
                        impact_score, confidence_score, remediation_priority,
                        remediation_urgency, summary, factors_json, assessed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        assessment.assessment_id,
                        assessment.finding_id,
                        assessment.risk_score,
                        assessment.severity,
                        assessment.exploitability,
                        assessment.impact,
                        assessment.confidence,
                        assessment.remediation_priority,
                        assessment.remediation_urgency,
                        assessment.summary,
                        json.dumps(asdict(assessment.factors)),
                        assessment.assessed_at,
                    ),
                )
                conn.commit()
        except Exception:
            pass

    def assess(
        self,
        finding: Union[FindingCandidate, Dict[str, Any]],
        validation: Optional[Union[ValidationOutcome, Dict[str, Any]]] = None,
        persist: bool = True,
    ) -> RiskAssessment:
        """
        Executes comprehensive contextual risk assessment for a finding and validation result.
        Consumes FindingCandidate and ValidationOutcome results.
        """
        # Normalize finding inputs
        if isinstance(finding, FindingCandidate):
            finding_id = finding.id
            vuln_type = finding.vuln_type
            cwe_id = finding.cwe_id
            endpoint = finding.endpoint
            param_location = finding.input_location
            finding_conf = finding.confidence
            evidence_dict = finding.evidence or {}
            target_url = finding.target_url
            finding_vuln = finding.is_vulnerable
            det_status = finding.detection_status
        elif isinstance(finding, dict):
            finding_id = finding.get("id", f"FIND-{uuid.uuid4().hex[:6].upper()}")
            vuln_type = finding.get("vuln_type", "")
            cwe_id = finding.get("cwe_id", "")
            endpoint = finding.get("endpoint", "")
            param_location = finding.get("input_location", "query_param")
            finding_conf = float(finding.get("confidence", 0.5))
            evidence_dict = finding.get("evidence", {})
            target_url = finding.get("target_url", "")
            finding_vuln = finding.get("is_vulnerable", True)
            det_status = finding.get("detection_status", "INCONCLUSIVE")
        else:
            finding_id = "unknown"
            vuln_type = ""
            cwe_id = ""
            endpoint = ""
            param_location = "query_param"
            finding_conf = 0.5
            evidence_dict = {}
            target_url = ""
            finding_vuln = False
            det_status = "INCONCLUSIVE"

        # Normalize validation inputs
        if isinstance(validation, ValidationOutcome):
            val_status = validation.validation_status
            is_confirmed = validation.is_confirmed
            val_conf = validation.confidence_score
            poc = validation.proof_of_concept_safe
            diff = validation.differential_observed
        elif isinstance(validation, dict):
            val_status = validation.get("validation_status") or validation.get("status", "INCONCLUSIVE")
            is_confirmed = validation.get("is_confirmed", False)
            val_conf = float(validation.get("confidence_score", 0.0)) if validation.get("confidence_score") is not None else None
            poc = validation.get("proof_of_concept_safe", "")
            diff = validation.get("differential_observed", "")
        else:
            val_status = "CONFIRMED" if finding_vuln and det_status in ("LIKELY_VULNERABLE", "CONFIRMED") else det_status
            is_confirmed = finding_vuln
            val_conf = None
            poc = evidence_dict.get("request_payload", "")
            diff = evidence_dict.get("differential_observed", "")

        has_poc = bool(poc and poc.strip())

        # Check cross-tenant breach context (IDOR)
        is_cross_tenant = False
        if "ACCESS" in vuln_type.upper() or "IDOR" in vuln_type.upper() or cwe_id == "CWE-639":
            evidence_str = str(evidence_dict) + diff + str(finding)
            if "cross-tenant" in evidence_str.lower() or "cross_tenant" in evidence_str.lower() or "data_leaked_across_tenancy" in evidence_str:
                is_cross_tenant = True
            elif is_confirmed and ("/record" in endpoint or "/api/record" in endpoint):
                is_cross_tenant = True

        # 1. Compute Factor Scores
        base_exp, exploitability, exp_mods = self._compute_exploitability(
            vuln_type, cwe_id, endpoint, param_location, has_poc
        )
        base_imp, impact, imp_mods = self._compute_impact(
            vuln_type, cwe_id, endpoint, is_cross_tenant
        )
        confidence, evidence_strength, conf_mods = self._compute_confidence_and_evidence(
            finding_conf, val_conf, evidence_dict, diff, has_poc
        )
        val_multiplier = self._compute_validation_multiplier(val_status, is_confirmed)

        # 2. Compute Composite Risk Score
        # Formula: Base = 0.45 * Exploitability + 0.55 * Impact
        # Raw = Base * Confidence * Validation Multiplier
        base_composite = (0.45 * exploitability) + (0.55 * impact)
        raw_score = base_composite * confidence * val_multiplier
        risk_score = min(10.0, max(0.0, round(raw_score, 1)))

        # 3. Determine Qualitative Severity & Remediation Priorities
        severity = self._determine_severity(risk_score)
        priority, urgency = self._determine_priority_and_urgency(risk_score)
        summary = self._generate_summary(vuln_type, cwe_id, severity, risk_score, priority, val_status)

        assessment_id = f"risk-{uuid.uuid4().hex[:8]}"
        assessed_at = datetime.now().isoformat()

        all_mods = {
            "exploitability_modifiers": exp_mods,
            "impact_modifiers": imp_mods,
            "confidence_modifiers": conf_mods,
        }

        factors = RiskFactors(
            vuln_type=vuln_type,
            cwe_id=cwe_id,
            base_exploitability=base_exp,
            exploitability_score=exploitability,
            base_impact=base_imp,
            impact_score=impact,
            confidence_score=confidence,
            evidence_strength=evidence_strength,
            validation_status=val_status,
            validation_multiplier=val_multiplier,
            is_confirmed=is_confirmed,
            context_modifiers=all_mods,
        )

        assessment = RiskAssessment(
            assessment_id=assessment_id,
            finding_id=finding_id,
            risk_score=risk_score,
            severity=severity,
            remediation_priority=priority,
            remediation_urgency=urgency,
            exploitability=exploitability,
            impact=impact,
            confidence=confidence,
            factors=factors,
            summary=summary,
            assessed_at=assessed_at,
            target_url=target_url,
        )

        # 4. Persist assessment
        if persist:
            self._persist_assessment(assessment, target_url)

        return assessment

    # Convenience aliases
    assess_candidate = assess

    def assess_all(
        self,
        findings: List[Union[FindingCandidate, Dict[str, Any]]],
        validations: Optional[List[Union[ValidationOutcome, Dict[str, Any]]]] = None,
        persist: bool = True,
    ) -> List[RiskAssessment]:
        """
        Assesses a batch of findings and corresponding validation outcomes.
        """
        val_map: Dict[str, Any] = {}
        if validations:
            for v in validations:
                fid = v.finding_id if isinstance(v, ValidationOutcome) else v.get("finding_id")
                if fid:
                    val_map[fid] = v

        results: List[RiskAssessment] = []
        for f in findings:
            fid = f.id if isinstance(f, FindingCandidate) else f.get("id")
            val_match = val_map.get(fid) if fid else None
            assessment = self.assess(f, validation=val_match, persist=persist)
            results.append(assessment)

        return results
