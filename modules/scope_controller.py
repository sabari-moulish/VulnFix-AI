"""
Strict Scope Controller & Authorized Target Management Module
Enforces authorization boundaries: strictly permits only localhost, 127.0.0.1,
and explicitly configured local test targets. Prohibits external scanning.
Maintains persistent audit logs for all security scope decisions.
"""

import ipaddress
import json
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Optional, Set, Dict, Any
from dataclasses import dataclass

from config import (
    DEFAULT_ALLOWED_HOSTS,
    DEFAULT_ALLOWED_PORTS,
    EXPLICIT_ALLOWED_TARGETS,
    ALLOWED_SCHEMES,
    STRICT_LOCAL_ONLY,
    SCOPE_AUDIT_LOG_FILE,
    get_db_connection,
    load_authorized_targets,
    save_authorized_targets,
)


@dataclass
class ScopeValidationResult:
    """Represents the outcome of a scope authorization evaluation."""
    is_allowed: bool
    reason: str
    target_url: str
    normalized_host: Optional[str] = None
    port: Optional[int] = None
    is_loopback: bool = False
    operation: str = "SCOPE_VALIDATION"


class ScopeController:
    """
    Enforces strict authorization boundaries and manages authorized targets.
    Default policy:
    - Only local targets: localhost, 127.0.0.1, ::1
    - Explicitly configured local testbed targets
    - Strictly blocks any remote IP, cloud metadata IP, or external domain.
    - Records comprehensive audit logs for all scope decisions.
    """

    def __init__(
        self,
        allowed_hosts: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        explicit_targets: Optional[List[str]] = None,
        strict_local_only: bool = STRICT_LOCAL_ONLY,
    ):
        self.allowed_hosts: Set[str] = set(allowed_hosts or DEFAULT_ALLOWED_HOSTS)
        self.allowed_ports: Set[int] = set(allowed_ports or DEFAULT_ALLOWED_PORTS)
        
        # Load explicit targets from storage/config if not explicitly provided
        loaded_targets = explicit_targets if explicit_targets is not None else load_authorized_targets()
        self.explicit_targets: Set[str] = set(loaded_targets or EXPLICIT_ALLOWED_TARGETS)
        self.strict_local_only: bool = strict_local_only
        self.current_target: Optional[str] = None
        
        # In-memory audit log cache
        self._in_memory_audit_logs: List[Dict[str, Any]] = []

    def _is_ip_loopback(self, host: str) -> bool:
        """Verify whether an IP address is strictly a loopback address."""
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_loopback
        except ValueError:
            return False

    def is_loopback_host(self, host: str) -> bool:
        """Determines if host evaluates to a local loopback interface."""
        host_lower = host.lower()
        if host_lower in {"localhost", "127.0.0.1", "::1"}:
            return True
        return self._is_ip_loopback(host_lower)

    def record_audit_log(self, target: str, operation: str, decision: str, reason: str) -> Dict[str, Any]:
        """
        Records scope decision with timestamp, target, operation, decision, and reason.
        Saves to both SQLite and persistent JSON log.
        """
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "target": target,
            "operation": operation,
            "decision": decision,  # 'ALLOWED' or 'REJECTED'
            "reason": reason,
        }

        # Add to in-memory list
        self._in_memory_audit_logs.append(log_entry)

        # Persist to SQLite
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO scope_audit_logs (timestamp, target, operation, decision, reason)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (timestamp, target, operation, decision, reason),
                )
                conn.commit()
        except Exception:
            pass

        # Persist to JSON log
        try:
            existing_logs = []
            if SCOPE_AUDIT_LOG_FILE.exists():
                try:
                    with open(SCOPE_AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                        existing_logs = json.load(f)
                except Exception:
                    existing_logs = []
            existing_logs.append(log_entry)
            # Keep latest 200 logs
            trimmed = existing_logs[-200:]
            with open(SCOPE_AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(trimmed, f, indent=2)
        except Exception:
            pass

        return log_entry

    def get_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent audit log entries from SQLite (or in-memory cache)."""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT timestamp, target, operation, decision, reason
                    FROM scope_audit_logs
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                if rows:
                    return [
                        {
                            "timestamp": r["timestamp"],
                            "target": r["target"],
                            "operation": r["operation"],
                            "decision": r["decision"],
                            "reason": r["reason"],
                        }
                        for r in rows
                    ]
        except Exception:
            pass
        return list(reversed(self._in_memory_audit_logs[-limit:]))

    def validate_target(
        self,
        target_url: str,
        record_audit: bool = True,
        operation: str = "SCOPE_VALIDATION",
    ) -> ScopeValidationResult:
        """
        Validates whether target URL is strictly authorized for testing.
        Returns a ScopeValidationResult with details.
        """
        if not target_url or not isinstance(target_url, str) or not target_url.strip():
            reason = "Invalid, empty, or malformed target specification."
            res = ScopeValidationResult(
                is_allowed=False,
                reason=reason,
                target_url=str(target_url),
                operation=operation,
            )
            if record_audit:
                self.record_audit_log(str(target_url), operation, "REJECTED", reason)
            return res

        target_cleaned = target_url.strip()

        # Check explicit whitelist match first (normalized prefix match)
        for explicit in self.explicit_targets:
            if target_cleaned == explicit or target_cleaned.startswith(f"{explicit}/"):
                parsed = urlparse(target_cleaned)
                is_loopback = self.is_loopback_host(parsed.hostname or "")
                reason = f"Target matches explicitly authorized local target: {explicit}"
                res = ScopeValidationResult(
                    is_allowed=True,
                    reason=reason,
                    target_url=target_cleaned,
                    normalized_host=parsed.hostname,
                    port=parsed.port or (443 if parsed.scheme == "https" else 80),
                    is_loopback=is_loopback,
                    operation=operation,
                )
                if record_audit:
                    self.record_audit_log(target_cleaned, operation, "ALLOWED", reason)
                return res

        # Parse URL
        try:
            parsed = urlparse(target_cleaned)
        except Exception as e:
            reason = f"Failed to parse target URL: {str(e)}"
            res = ScopeValidationResult(
                is_allowed=False,
                reason=reason,
                target_url=target_cleaned,
                operation=operation,
            )
            if record_audit:
                self.record_audit_log(target_cleaned, operation, "REJECTED", reason)
            return res

        # Validate Scheme
        if not parsed.scheme or parsed.scheme.lower() not in ALLOWED_SCHEMES:
            reason = f"Unsupported scheme '{parsed.scheme}'. Only {ALLOWED_SCHEMES} are allowed."
            res = ScopeValidationResult(
                is_allowed=False,
                reason=reason,
                target_url=target_cleaned,
                operation=operation,
            )
            if record_audit:
                self.record_audit_log(target_cleaned, operation, "REJECTED", reason)
            return res

        hostname = parsed.hostname
        if not hostname:
            reason = "Target URL lacks a valid hostname."
            res = ScopeValidationResult(
                is_allowed=False,
                reason=reason,
                target_url=target_cleaned,
                operation=operation,
            )
            if record_audit:
                self.record_audit_log(target_cleaned, operation, "REJECTED", reason)
            return res

        hostname_lower = hostname.lower()

        # Strict local-only enforcement
        is_loopback = self.is_loopback_host(hostname_lower)
        is_allowed_host_string = hostname_lower in self.allowed_hosts

        if self.strict_local_only and not (is_loopback or is_allowed_host_string):
            reason = (
                f"Forbidden target host '{hostname}'. Only strictly authorized local testbeds "
                "(localhost, 127.0.0.1) are permitted. External scanning is prohibited."
            )
            res = ScopeValidationResult(
                is_allowed=False,
                reason=reason,
                target_url=target_cleaned,
                normalized_host=hostname_lower,
                is_loopback=False,
                operation=operation,
            )
            if record_audit:
                self.record_audit_log(target_cleaned, operation, "REJECTED", reason)
            return res

        # Validate Port (defaults to 80 for HTTP, 443 for HTTPS if omitted)
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            reason = "Target URL contains an invalid port specification."
            res = ScopeValidationResult(
                is_allowed=False,
                reason=reason,
                target_url=target_cleaned,
                normalized_host=hostname_lower,
                operation=operation,
            )
            if record_audit:
                self.record_audit_log(target_cleaned, operation, "REJECTED", reason)
            return res

        if self.allowed_ports and port not in self.allowed_ports:
            reason = (
                f"Port {port} is not in the allowed local testing ports list: "
                f"{sorted(list(self.allowed_ports))}."
            )
            res = ScopeValidationResult(
                is_allowed=False,
                reason=reason,
                target_url=target_cleaned,
                normalized_host=hostname_lower,
                port=port,
                is_loopback=is_loopback,
                operation=operation,
            )
            if record_audit:
                self.record_audit_log(target_cleaned, operation, "REJECTED", reason)
            return res

        reason = "Target is strictly within authorized local testbed scope."
        res = ScopeValidationResult(
            is_allowed=True,
            reason=reason,
            target_url=target_cleaned,
            normalized_host=hostname_lower,
            port=port,
            is_loopback=is_loopback,
            operation=operation,
        )
        if record_audit:
            self.record_audit_log(target_cleaned, operation, "ALLOWED", reason)
        return res

    def authorize_operation(self, target_url: str, operation: str = "GENERIC_OPERATION") -> ScopeValidationResult:
        """
        Enforces that every security operation passes through the scope controller before execution.
        """
        return self.validate_target(target_url, record_audit=True, operation=operation)

    def set_selected_target(self, target_url: str) -> ScopeValidationResult:
        """
        Sets the active target for the platform session after verifying scope authorization.
        """
        val = self.validate_target(target_url, record_audit=True, operation="TARGET_SELECTION")
        if val.is_allowed:
            self.current_target = val.target_url
        return val

    def get_selected_target(self) -> Optional[str]:
        """Returns the currently active target URL."""
        return self.current_target

    def get_target_status(self, target_url: Optional[str] = None) -> Dict[str, Any]:
        """Returns the authorization status and metadata for a target."""
        target = target_url or self.current_target
        if not target:
            return {
                "target": None,
                "is_authorized": False,
                "status_text": "NO_TARGET_SELECTED",
                "reason": "No target has been selected yet.",
            }

        val = self.validate_target(target, record_audit=False)
        return {
            "target": target,
            "is_authorized": val.is_allowed,
            "status_text": "AUTHORIZED" if val.is_allowed else "REJECTED",
            "host": val.normalized_host,
            "port": val.port,
            "is_loopback": val.is_loopback,
            "reason": val.reason,
        }

    def add_explicit_target(self, target_url: str) -> ScopeValidationResult:
        """Adds an explicitly authorized local test target after safety validation."""
        val = self.validate_target(target_url, record_audit=False)
        # Even when adding explicitly, ensure it is local loopback if strict_local_only is on
        if self.strict_local_only and not val.is_loopback and val.normalized_host not in self.allowed_hosts:
            reason = f"Cannot add target '{target_url}': Strict local-only mode rejects non-local hosts."
            self.record_audit_log(target_url, "ADD_EXPLICIT_TARGET", "REJECTED", reason)
            return ScopeValidationResult(
                is_allowed=False,
                reason=reason,
                target_url=target_url,
                operation="ADD_EXPLICIT_TARGET",
            )
        
        target_cleaned = target_url.strip()
        self.explicit_targets.add(target_cleaned)
        save_authorized_targets(list(self.explicit_targets))

        reason = f"Target '{target_url}' successfully authorized and added to scope."
        self.record_audit_log(target_cleaned, "ADD_EXPLICIT_TARGET", "ALLOWED", reason)
        return ScopeValidationResult(
            is_allowed=True,
            reason=reason,
            target_url=target_cleaned,
            normalized_host=val.normalized_host,
            port=val.port,
            is_loopback=val.is_loopback,
            operation="ADD_EXPLICIT_TARGET",
        )

    def remove_explicit_target(self, target_url: str) -> bool:
        """Removes a target from explicitly authorized targets."""
        target_cleaned = target_url.strip()
        if target_cleaned in self.explicit_targets:
            self.explicit_targets.remove(target_cleaned)
            save_authorized_targets(list(self.explicit_targets))
            self.record_audit_log(target_cleaned, "REMOVE_EXPLICIT_TARGET", "ALLOWED", "Target removed from explicit scope.")
            if self.current_target == target_cleaned:
                self.current_target = None
            return True
        return False

    def get_authorized_targets(self) -> List[str]:
        """Returns sorted list of currently authorized targets."""
        return sorted(list(self.explicit_targets))

    def get_scope_summary(self) -> dict:
        """Returns a snapshot of the current active scope configuration."""
        return {
            "strict_local_only": self.strict_local_only,
            "allowed_hosts": sorted(list(self.allowed_hosts)),
            "allowed_ports": sorted(list(self.allowed_ports)),
            "explicit_targets_count": len(self.explicit_targets),
            "explicit_targets": sorted(list(self.explicit_targets)),
            "current_target": self.current_target,
        }
