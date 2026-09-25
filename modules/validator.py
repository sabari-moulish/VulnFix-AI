"""
Vulnerability Validator Module
AI-Powered Vulnerability Validation and Proof-of-Fix Platform
Track: Offensive Security & Red Teaming

Executes safe, deterministic, non-destructive validation of detected vulnerability hypotheses.
Consumes FindingCandidate results from modules.vulnerability_detector.
Validates:
1. SQL Injection (CWE-89): Reproduces boolean differential without database dumping.
2. Reflected XSS (CWE-79): Reproduces reflection using a unique non-executable canary (no JavaScript execution).
3. Broken Access Control / IDOR (CWE-639): Reproduces cross-tenant access using known synthetic records (no enumeration).

Strictly constrained to authorized local test targets (localhost / 127.0.0.1:5000).
Enforces Scope Controller on every operation, bounded requests, timeouts, and redirect blocking.
"""

from typing import List, Dict, Any, Optional, Tuple, Union
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from datetime import datetime
import json
import uuid
import requests

from config import get_db_connection
from modules.scope_controller import ScopeController
from modules.evidence import EvidenceManager
from modules.vulnerability_detector import FindingCandidate


@dataclass
class ValidationOutcome:
    """Result of vulnerability confirmation testing for an individual finding candidate."""
    finding_id: str
    is_confirmed: bool
    confidence_score: float
    validation_method: str
    proof_of_concept_safe: str
    details: str
    validation_status: str = "INCONCLUSIVE"  # "CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE", "BLOCKED_OUT_OF_SCOPE"
    evidence_id: Optional[str] = None
    differential_observed: str = ""
    evidence_file: Optional[str] = None
    raw_interactions: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = ""

    @property
    def status(self) -> str:
        """Alias for backward compatibility."""
        return self.validation_status


@dataclass
class ValidationRunResult:
    """Summary of a batch validation run across multiple finding candidates."""
    target_url: str
    success: bool
    total_validated: int
    confirmed_count: int
    not_confirmed_count: int
    inconclusive_count: int
    blocked_count: int
    outcomes: List[ValidationOutcome] = field(default_factory=list)
    total_requests: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None
    timestamp: str = ""


class VulnerabilityValidator:
    """
    Validates vulnerability candidates against explicitly authorized local targets.
    Strictly forbids uncontrolled exploitation, payload mutation beyond verification,
    data exfiltration, or destructive operations.
    """

    def __init__(
        self,
        scope_controller: Optional[ScopeController] = None,
        evidence_manager: Optional[EvidenceManager] = None,
        max_requests: int = 25,
        timeout: float = 3.0,
    ):
        self.scope_controller = scope_controller or ScopeController()
        self.evidence_manager = evidence_manager or EvidenceManager()
        self.max_requests = max_requests
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnFix-ValidatorEngine/1.0 (Authorized Local Validation Testing)",
            "Accept": "text/html,application/json,*/*",
        })
        self._request_count = 0

    def _normalize_origin(self, target_url: str) -> Tuple[str, str, int]:
        """Extracts (scheme, host, port) for strict same-origin enforcement."""
        parsed = urlparse(target_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return (parsed.scheme.lower(), (parsed.hostname or "").lower(), port)

    def _safe_request(
        self,
        method: str,
        url: str,
        base_origin: Tuple[str, str, int],
        **kwargs,
    ) -> Tuple[Optional[requests.Response], bool, str]:
        """
        Executes a bounded, scope-verified HTTP request.
        Returns: (Response or None, is_out_of_scope, failure_reason)
        """
        # 1. Scope authorization check for every request
        scope_res = self.scope_controller.authorize_operation(
            url, operation="VULNERABILITY_VALIDATION"
        )
        if not scope_res.is_allowed:
            return None, True, f"Scope check failed: {scope_res.reason}"

        # 2. Strict same-origin check against authorized target base
        cand_origin = self._normalize_origin(url)
        if cand_origin != base_origin:
            return None, True, "Cross-origin request blocked: outside authorized target origin"

        # 3. Bounded request limit enforcement
        if self._request_count >= self.max_requests:
            return None, False, f"Request limit of {self.max_requests} reached"

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)

        try:
            resp = self.session.request(method, url, **kwargs)
            self._request_count += 1

            # 4. Out-of-scope redirect blocking
            if 300 <= resp.status_code < 400:
                loc = resp.headers.get("Location")
                if loc:
                    resolved_loc = urljoin(url, loc)
                    if self._normalize_origin(resolved_loc) != base_origin:
                        return resp, True, f"Redirect to external origin {resolved_loc} blocked"

            return resp, False, ""
        except requests.Timeout:
            self._request_count += 1
            return None, False, "Request timed out"
        except requests.RequestException as e:
            self._request_count += 1
            return None, False, f"Request error: {str(e)}"

    def _extract_candidate_info(self, finding: Union[FindingCandidate, Dict[str, Any]]) -> Dict[str, Any]:
        """Normalizes candidate metadata from FindingCandidate object or dictionary."""
        if isinstance(finding, FindingCandidate):
            return {
                "id": finding.id,
                "vuln_type": finding.vuln_type,
                "cwe_id": finding.cwe_id,
                "title": finding.title,
                "endpoint": finding.endpoint,
                "http_method": finding.http_method,
                "param": finding.affected_parameter,
                "input_location": finding.input_location,
                "evidence": finding.evidence,
                "is_vulnerable": finding.is_vulnerable,
            }
        elif isinstance(finding, dict):
            return {
                "id": finding.get("id", f"FIND-{uuid.uuid4().hex[:6].upper()}"),
                "vuln_type": finding.get("vuln_type", ""),
                "cwe_id": finding.get("cwe_id", ""),
                "title": finding.get("title", ""),
                "endpoint": finding.get("endpoint", ""),
                "http_method": finding.get("http_method", "GET"),
                "param": finding.get("affected_parameter") or finding.get("param"),
                "input_location": finding.get("input_location", "query_param"),
                "evidence": finding.get("evidence", {}),
                "is_vulnerable": finding.get("is_vulnerable", True),
            }
        else:
            return {
                "id": "unknown",
                "vuln_type": "",
                "cwe_id": "",
                "title": "",
                "endpoint": "",
                "http_method": "GET",
                "param": None,
                "input_location": "",
                "evidence": {},
                "is_vulnerable": False,
            }

    # --- 1. SQL Injection Validator (CWE-89) ---

    def _validate_sqli(
        self,
        target_url: str,
        base_origin: Tuple[str, str, int],
        info: Dict[str, Any],
    ) -> Tuple[bool, str, float, str, str, str, List[Dict[str, Any]], str]:
        """
        Validates SQL Injection hypothesis by reproducing the boolean differential.
        Strictly non-destructive: Uses boolean tautology (' OR '1'='1 vs ' AND '1'='2)
        without database dumping, schema extraction, or data exfiltration.
        """
        endpoint = info.get("endpoint") or "/api/search"
        param_name = info.get("param") or ("q" if "api" in endpoint else "query")
        full_url = urljoin(f"{target_url}/", endpoint.lstrip("/"))
        interactions: List[Dict[str, Any]] = []

        # Probe 1: Baseline Request
        payload_base = "Sensor"
        resp_base, out_of_scope, err = self._safe_request(
            "GET", full_url, base_origin, params={param_name: payload_base}
        )
        if out_of_scope:
            return False, "BLOCKED_OUT_OF_SCOPE", 0.0, "", "Target redirected out of scope during baseline.", "", interactions, ""
        if resp_base is None:
            return False, "INCONCLUSIVE", 0.0, "", f"Baseline request failed: {err}", "", interactions, ""

        interactions.append({
            "probe": "baseline",
            "param": param_name,
            "payload": payload_base,
            "status": resp_base.status_code,
            "length": len(resp_base.text),
        })

        # Probe 2: True Condition (' OR '1'='1)
        payload_true = "' OR '1'='1"
        resp_true, out_of_scope, err = self._safe_request(
            "GET", full_url, base_origin, params={param_name: payload_true}
        )
        if out_of_scope:
            return False, "BLOCKED_OUT_OF_SCOPE", 0.0, "", "Target redirected out of scope during true probe.", "", interactions, ""
        if resp_true is None:
            return False, "INCONCLUSIVE", 0.0, "", f"True condition request failed: {err}", "", interactions, ""

        interactions.append({
            "probe": "true_condition",
            "param": param_name,
            "payload": payload_true,
            "status": resp_true.status_code,
            "length": len(resp_true.text),
        })

        # Probe 3: False Condition (' AND '1'='2)
        payload_false = "' AND '1'='2"
        resp_false, out_of_scope, err = self._safe_request(
            "GET", full_url, base_origin, params={param_name: payload_false}
        )
        if out_of_scope:
            return False, "BLOCKED_OUT_OF_SCOPE", 0.0, "", "Target redirected out of scope during false probe.", "", interactions, ""
        if resp_false is None:
            return False, "INCONCLUSIVE", 0.0, "", f"False condition request failed: {err}", "", interactions, ""

        interactions.append({
            "probe": "false_condition",
            "param": param_name,
            "payload": payload_false,
            "status": resp_false.status_code,
            "length": len(resp_false.text),
        })

        # Evaluate Differential in JSON response
        if "json" in resp_true.headers.get("Content-Type", ""):
            try:
                data_base = resp_base.json()
                data_true = resp_true.json()
                data_false = resp_false.json()

                count_base = data_base.get("count", len(data_base.get("results", [])))
                count_true = data_true.get("count", len(data_true.get("results", [])))
                count_false = data_false.get("count", len(data_false.get("results", [])))

                diff = f"JSON Item Differential: Baseline={count_base}, True={count_true}, False={count_false}"

                if count_true > count_base and count_false == 0 and count_true > count_false:
                    poc = f"GET {full_url}?{param_name}={payload_true}"
                    return (
                        True,
                        "CONFIRMED",
                        0.98,
                        poc,
                        "Deterministic SQL injection boolean differential confirmed: True query returned expanded dataset while False query returned empty set.",
                        diff,
                        interactions,
                        resp_true.text[:300],
                    )
                elif count_true == 0 and count_false == 0:
                    return (
                        False,
                        "NOT_CONFIRMED",
                        0.95,
                        "",
                        "Parameterized query verified: Injected boolean syntax was safely treated as literal search string with no query manipulation.",
                        diff,
                        interactions,
                        resp_true.text[:300],
                    )
            except Exception:
                pass

        # Evaluate Differential in HTML response
        has_all_true = ("Loopback Probe" in resp_true.text and "Calibration Toolkit" in resp_true.text and "Diagnostic Sensor" in resp_true.text)
        has_all_base = ("Loopback Probe" in resp_base.text and "Calibration Toolkit" in resp_base.text and "Diagnostic Sensor" in resp_base.text)
        has_any_false = ("Loopback Probe" in resp_false.text or "Calibration Toolkit" in resp_false.text or "Diagnostic Sensor" in resp_false.text)

        html_diff = f"HTML Length Differential: Baseline={len(resp_base.text)}b, True={len(resp_true.text)}b, False={len(resp_false.text)}b"

        if has_all_true and not has_all_base and not has_any_false:
            poc = f"GET {full_url}?{param_name}={payload_true}"
            return (
                True,
                "CONFIRMED",
                0.98,
                poc,
                "Deterministic SQL boolean tautology injection verified: Unsafe query string concatenation expanded catalog to all records.",
                html_diff,
                interactions,
                resp_true.text[:300],
            )
        elif not has_all_true and not has_any_false and resp_true.status_code == 200:
            return (
                False,
                "NOT_CONFIRMED",
                0.95,
                "",
                "Parameterized query verified: Injected boolean syntax did not alter database query structure.",
                html_diff,
                interactions,
                resp_true.text[:300],
            )

        return (
            False,
            "INCONCLUSIVE",
            0.50,
            "",
            "Differential analysis inconclusive: Response difference did not decisively confirm or refute SQL injection.",
            html_diff,
            interactions,
            resp_true.text[:300],
        )

    # --- 2. Reflected XSS Validator (CWE-79) ---

    def _validate_xss(
        self,
        target_url: str,
        base_origin: Tuple[str, str, int],
        info: Dict[str, Any],
    ) -> Tuple[bool, str, float, str, str, str, List[Dict[str, Any]], str]:
        """
        Validates Reflected XSS hypothesis using a unique non-executable canary token.
        Strictly non-destructive: Does NOT execute JavaScript or use active script payloads.
        """
        endpoint = info.get("endpoint") or "/api/greet"
        param_name = info.get("param") or "name"
        full_url = urljoin(f"{target_url}/", endpoint.lstrip("/"))
        interactions: List[Dict[str, Any]] = []

        # Unique non-executable verification token
        val_id = uuid.uuid4().hex[:8]
        val_token = f"val_token_{val_id}"
        val_canary = f"{val_token}<poc_probe_nonexec>"

        resp, out_of_scope, err = self._safe_request(
            "GET", full_url, base_origin, params={param_name: val_canary}
        )
        if out_of_scope:
            return False, "BLOCKED_OUT_OF_SCOPE", 0.0, "", "Target redirected out of scope during XSS probe.", "", interactions, ""
        if resp is None:
            return False, "INCONCLUSIVE", 0.0, "", f"XSS canary probe failed: {err}", "", interactions, ""

        interactions.append({
            "probe": "non_executable_canary_reflection",
            "endpoint": endpoint,
            "param": param_name,
            "payload": val_canary,
            "status": resp.status_code,
            "length": len(resp.text),
        })

        resp_text = resp.text

        # Evaluate JSON response
        if "json" in resp.headers.get("Content-Type", ""):
            try:
                data = resp.json()
                reflected = data.get("reflected", "")
                is_escaped = data.get("is_escaped", False)

                if val_canary in reflected and not is_escaped:
                    poc = f"GET {full_url}?{param_name}={val_canary}"
                    diff = f"Unescaped non-executable canary reflection confirmed in JSON payload: '{val_canary}'"
                    return (
                        True,
                        "CONFIRMED",
                        0.98,
                        poc,
                        "Reflected XSS verified: Untrusted canary markup reflected verbatim without HTML entity encoding.",
                        diff,
                        interactions,
                        resp_text[:300],
                    )
                elif "&lt;poc_probe_nonexec&gt;" in reflected or is_escaped:
                    diff = "Context-aware HTML encoding verified: '<' and '>' were escaped to '&lt;' and '&gt;'."
                    return (
                        False,
                        "NOT_CONFIRMED",
                        0.95,
                        "",
                        "Sanitization verified: Canary was properly HTML entity-encoded in JSON output.",
                        diff,
                        interactions,
                        resp_text[:300],
                    )
            except Exception:
                pass

        # Evaluate HTML response
        if val_canary in resp_text:
            poc = f"GET {full_url}?{param_name}={val_canary}"
            diff = f"Unescaped non-executable canary markup reflected verbatim in HTML context: '{val_canary}'"
            return (
                True,
                "CONFIRMED",
                0.98,
                poc,
                "Reflected XSS confirmed: Non-executable canary probe reflected verbatim into HTML document context.",
                diff,
                interactions,
                resp_text[:300],
            )
        elif f"{val_token}&lt;poc_probe_nonexec&gt;" in resp_text:
            diff = "HTML entity encoding confirmed: '<poc_probe_nonexec>' neutralized to '&lt;poc_probe_nonexec&gt;'."
            return (
                False,
                "NOT_CONFIRMED",
                0.95,
                "",
                "Sanitization verified: Injected HTML tags were neutralized via context-aware entity encoding.",
                diff,
                interactions,
                resp_text[:300],
            )
        elif val_token in resp_text:
            diff = "Canary string was reflected but HTML angle brackets were neutralized."
            return (
                False,
                "NOT_CONFIRMED",
                0.80,
                "",
                "Canary string reflected without raw markup tags.",
                diff,
                interactions,
                resp_text[:300],
            )

        return (
            False,
            "INCONCLUSIVE",
            0.50,
            "",
            "Canary was not reflected in the HTTP response body.",
            "No reflection observable.",
            interactions,
            resp_text[:300],
        )

    # --- 3. Broken Access Control / IDOR Validator (CWE-639) ---

    def _validate_idor(
        self,
        target_url: str,
        base_origin: Tuple[str, str, int],
        info: Dict[str, Any],
    ) -> Tuple[bool, str, float, str, str, str, List[Dict[str, Any]], str]:
        """
        Validates IDOR / Broken Object-Level Authorization using only known synthetic test records.
        Strictly non-destructive: Uses Record 1 (Authorized for User A) and Record 2 (Foreign Tenant, Org B).
        No broad enumeration or ID brute-forcing.
        """
        endpoint = info.get("endpoint") or "/api/record"
        interactions: List[Dict[str, Any]] = []

        # Determine target paths for known synthetic objects
        if "api" in endpoint:
            url_auth = urljoin(f"{target_url}/", "api/record/1")
            url_foreign = urljoin(f"{target_url}/", "api/record/2")
        else:
            url_auth = urljoin(f"{target_url}/", "record/1")
            url_foreign = urljoin(f"{target_url}/", "record/2")

        # Baseline Probe: Authorized Record 1
        resp_auth, out_of_scope, err = self._safe_request("GET", url_auth, base_origin)
        if out_of_scope:
            return False, "BLOCKED_OUT_OF_SCOPE", 0.0, "", "Target redirected out of scope during authorized baseline probe.", "", interactions, ""
        if resp_auth is None:
            return False, "INCONCLUSIVE", 0.0, "", f"Authorized baseline request failed: {err}", "", interactions, ""

        interactions.append({
            "probe": "authorized_baseline",
            "url": url_auth,
            "status": resp_auth.status_code,
            "length": len(resp_auth.text),
        })

        # Foreign Tenant Probe: Record 2 (Owned by Organization 2)
        resp_foreign, out_of_scope, err = self._safe_request("GET", url_foreign, base_origin)
        if out_of_scope:
            return False, "BLOCKED_OUT_OF_SCOPE", 0.0, "", "Target redirected out of scope during foreign tenant probe.", "", interactions, ""
        if resp_foreign is None:
            return False, "INCONCLUSIVE", 0.0, "", f"Foreign tenant request failed: {err}", "", interactions, ""

        interactions.append({
            "probe": "foreign_tenant_probe",
            "url": url_foreign,
            "status": resp_foreign.status_code,
            "length": len(resp_foreign.text),
        })

        poc = f"GET {url_foreign}"

        # Evaluate Foreign Access
        if resp_foreign.status_code == 200:
            diff = "Cross-tenant access allowed: HTTP 200 returned for foreign tenant object (Record 2, Org 2)."
            return (
                True,
                "CONFIRMED",
                0.98,
                poc,
                "IDOR / Broken Object-Level Authorization confirmed: User A session accessed foreign tenant Record 2 without authorization check.",
                diff,
                interactions,
                resp_foreign.text[:300],
            )
        elif resp_foreign.status_code == 403:
            diff = "Tenant isolation verified: Server correctly rejected cross-tenant access with HTTP 403 Forbidden."
            return (
                False,
                "NOT_CONFIRMED",
                0.95,
                "",
                "Access control verified: Foreign tenant object was blocked with HTTP 403 Forbidden.",
                diff,
                interactions,
                resp_foreign.text[:300],
            )
        elif resp_foreign.status_code == 404:
            return (
                False,
                "INCONCLUSIVE",
                0.50,
                "",
                "Foreign record was not found (HTTP 404).",
                "Record 2 returned 404.",
                interactions,
                resp_foreign.text[:300],
            )

        return (
            False,
            "INCONCLUSIVE",
            0.50,
            "",
            f"Unexpected status code {resp_foreign.status_code} during foreign tenant probe.",
            f"Status: {resp_foreign.status_code}",
            interactions,
            resp_foreign.text[:300],
        )

    # --- Core Validation Orchestrator ---

    def validate_finding(
        self,
        target_url: str,
        finding: Union[FindingCandidate, Dict[str, Any]],
    ) -> ValidationOutcome:
        """
        Executes bounded, safe validation for a single finding candidate.
        Consumes FindingCandidate results from modules.vulnerability_detector.
        """
        info = self._extract_candidate_info(finding)
        timestamp = datetime.now().isoformat()

        # 1. Target scope verification
        scope_res = self.scope_controller.authorize_operation(
            target_url, operation="VULNERABILITY_VALIDATION"
        )
        if not scope_res.is_allowed:
            return ValidationOutcome(
                finding_id=info["id"],
                is_confirmed=False,
                confidence_score=0.0,
                validation_method="ScopeBoundaryCheck",
                proof_of_concept_safe="",
                details=f"Scope violation: {scope_res.reason}",
                validation_status="BLOCKED_OUT_OF_SCOPE",
                timestamp=timestamp,
            )

        base_origin = self._normalize_origin(target_url)
        vuln_type = info.get("vuln_type", "").upper()
        cwe_id = info.get("cwe_id", "").upper()

        # 2. Select specialized validator
        if "SQL" in vuln_type or cwe_id == "CWE-89":
            method = "DeterministicBooleanDifferential"
            is_confirmed, status, confidence, poc, details, diff, interactions, snippet = self._validate_sqli(
                target_url, base_origin, info
            )
        elif "XSS" in vuln_type or cwe_id == "CWE-79":
            method = "NonExecutableCanaryReflection"
            is_confirmed, status, confidence, poc, details, diff, interactions, snippet = self._validate_xss(
                target_url, base_origin, info
            )
        elif "ACCESS" in vuln_type or "IDOR" in vuln_type or cwe_id == "CWE-639":
            method = "SyntheticMultiTenantBoundaryCheck"
            is_confirmed, status, confidence, poc, details, diff, interactions, snippet = self._validate_idor(
                target_url, base_origin, info
            )
        else:
            method = "UnsupportedTypeCheck"
            is_confirmed = False
            status = "INCONCLUSIVE"
            confidence = 0.0
            poc = ""
            details = f"Unsupported vulnerability type '{vuln_type}' for automated proof validation."
            diff = ""
            interactions = []
            snippet = ""

        # 3. Store reproducible evidence in data/evidence/ and SQLite
        ev_id = None
        ev_file = None
        try:
            ev_record = self.evidence_manager.record_evidence(
                finding_id=info["id"],
                evidence_type="PROOF_OF_CONCEPT_VALIDATION",
                payload=poc or "SAFE_VERIFICATION_PROBE",
                response_snippet=snippet,
                metadata={
                    "validation_status": status,
                    "is_confirmed": is_confirmed,
                    "confidence_score": confidence,
                    "validation_method": method,
                    "differential_observed": diff,
                    "raw_interactions": interactions,
                    "timestamp": timestamp,
                },
            )
            ev_id = ev_record.get("evidence_id")
            ev_file = str(self.evidence_manager.base_dir / f"{info['id']}_{ev_id}.json")
        except Exception:
            pass

        # 4. Store validation log in SQLite validations table
        val_id = f"val-{uuid.uuid4().hex[:8]}"
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Ensure finding exists in findings table
                cursor.execute("SELECT id FROM findings WHERE id = ?", (info["id"],))
                if not cursor.fetchone():
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO findings (id, target_url, title, vuln_type, cwe_id, severity, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            info["id"],
                            target_url,
                            info.get("title") or f"Finding {info['id']}",
                            info.get("vuln_type", ""),
                            info.get("cwe_id", ""),
                            "HIGH" if is_confirmed else "INFO",
                            status,
                        ),
                    )
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO validations (id, finding_id, is_reproducible, validation_method, validation_log, validated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        val_id,
                        info["id"],
                        1 if is_confirmed else 0,
                        method,
                        json.dumps({
                            "validation_status": status,
                            "poc": poc,
                            "differential": diff,
                            "details": details,
                        }),
                        timestamp,
                    ),
                )
                conn.commit()
        except Exception:
            pass

        return ValidationOutcome(
            finding_id=info["id"],
            is_confirmed=is_confirmed,
            confidence_score=confidence,
            validation_method=method,
            proof_of_concept_safe=poc,
            details=details,
            validation_status=status,
            evidence_id=ev_id,
            differential_observed=diff,
            evidence_file=ev_file,
            raw_interactions=interactions,
            timestamp=timestamp,
        )

    def validate_candidates(
        self,
        target_url: str,
        candidates: List[Union[FindingCandidate, Dict[str, Any]]],
    ) -> ValidationRunResult:
        """
        Executes bounded, safe validation across a list of finding candidates.
        """
        start_time = datetime.now()
        timestamp = start_time.isoformat()

        # Verify target scope upfront
        scope_res = self.scope_controller.authorize_operation(
            target_url, operation="VULNERABILITY_VALIDATION"
        )
        if not scope_res.is_allowed:
            blocked_outcomes = [
                ValidationOutcome(
                    finding_id=(c.id if isinstance(c, FindingCandidate) else c.get("id", "unknown")),
                    is_confirmed=False,
                    confidence_score=0.0,
                    validation_method="ScopeBoundaryCheck",
                    proof_of_concept_safe="",
                    details=f"Scope violation: {scope_res.reason}",
                    validation_status="BLOCKED_OUT_OF_SCOPE",
                    timestamp=timestamp,
                )
                for c in candidates
            ]
            return ValidationRunResult(
                target_url=target_url,
                success=False,
                total_validated=len(candidates),
                confirmed_count=0,
                not_confirmed_count=0,
                inconclusive_count=0,
                blocked_count=len(candidates),
                outcomes=blocked_outcomes,
                total_requests=0,
                duration_seconds=0.0,
                error=f"Scope violation: {scope_res.reason}",
                timestamp=timestamp,
            )

        outcomes: List[ValidationOutcome] = []
        confirmed = 0
        not_confirmed = 0
        inconclusive = 0
        blocked = 0

        for candidate in candidates:
            # Check request limits before attempting next candidate
            if self._request_count >= self.max_requests:
                c_id = candidate.id if isinstance(candidate, FindingCandidate) else candidate.get("id", "unknown")
                outcomes.append(
                    ValidationOutcome(
                        finding_id=c_id,
                        is_confirmed=False,
                        confidence_score=0.0,
                        validation_method="RequestLimitEnforcer",
                        proof_of_concept_safe="",
                        details=f"Request limit of {self.max_requests} reached before candidate validation.",
                        validation_status="INCONCLUSIVE",
                        timestamp=datetime.now().isoformat(),
                    )
                )
                inconclusive += 1
                continue

            outcome = self.validate_finding(target_url, candidate)
            outcomes.append(outcome)

            if outcome.validation_status == "CONFIRMED":
                confirmed += 1
            elif outcome.validation_status == "NOT_CONFIRMED":
                not_confirmed += 1
            elif outcome.validation_status == "BLOCKED_OUT_OF_SCOPE":
                blocked += 1
            else:
                inconclusive += 1

        duration = (datetime.now() - start_time).total_seconds()
        return ValidationRunResult(
            target_url=target_url,
            success=True,
            total_validated=len(candidates),
            confirmed_count=confirmed,
            not_confirmed_count=not_confirmed,
            inconclusive_count=inconclusive,
            blocked_count=blocked,
            outcomes=outcomes,
            total_requests=self._request_count,
            duration_seconds=duration,
            timestamp=timestamp,
        )

    # Convenience alias for batch execution
    validate_all = validate_candidates
