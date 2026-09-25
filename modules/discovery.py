"""
Discovery Engine Module
Safely maps the attack surface of authorized local testbed targets.
Strictly bounded by the Scope Controller: no internet-wide scanning, port scanning,
brute force, credential attacks, or uncontrolled crawling.
"""

from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, parse_qs
from dataclasses import dataclass, asdict, field
from html.parser import HTMLParser
from datetime import datetime
from pathlib import Path
import re
import json
import requests

from config import FINDINGS_DIR
from modules.scope_controller import ScopeController, ScopeValidationResult


@dataclass
class DiscoveredInput:
    """Represents a user-controllable input parameter found on an endpoint."""
    name: str
    location: str  # 'query_param', 'form_body', 'path_param', 'none'
    input_type: str = "text"  # 'text', 'search', 'number', 'hidden', etc.
    sample_value: Optional[str] = None


@dataclass
class DiscoveredEndpoint:
    """
    Structured model for a discovered application endpoint.
    Complies with required discovery model specification.
    """
    endpoint: str  # Relative path (e.g. "/sqli")
    full_url: str  # Complete URL (e.g. "http://127.0.0.1:5000/sqli")
    method: str  # HTTP method ("GET", "POST", etc.)
    parameter_name: Optional[str] = None  # Primary input name or None
    input_location: str = "none"  # "query_param", "form_body", "path_param", "none"
    status_code: int = 200
    content_type: str = "text/html"
    discovery_source: str = "route_probe"  # "html_form", "html_link", "api_probe", "route_probe"
    inputs: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class DiscoveryResult:
    """Full attack surface discovery result with safety metrics and evidence reference."""
    target_url: str
    success: bool
    timestamp: str
    scope_decision: Dict[str, Any]
    error: Optional[str] = None
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    all_inputs: List[Dict[str, Any]] = field(default_factory=list)
    redirect_violations: List[Dict[str, Any]] = field(default_factory=list)
    total_requests: int = 0
    duration_seconds: float = 0.0
    evidence_file: Optional[str] = None


class _HTMLAttackSurfaceParser(HTMLParser):
    """
    Lightweight HTML parser to extract links, forms, and input elements.
    Operates without external dependencies.
    """

    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        # Extract anchor links
        if tag == "a":
            href = attr_dict.get("href")
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(href)

        # Extract form declarations
        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            self._current_form = {
                "action": action,
                "method": method,
                "inputs": [],
            }

        # Extract inputs within forms
        elif tag in ("input", "textarea", "select"):
            name = attr_dict.get("name")
            if name:
                input_info = {
                    "name": name,
                    "type": attr_dict.get("type", "text").lower(),
                    "value": attr_dict.get("value", ""),
                }
                if self._current_form is not None:
                    self._current_form["inputs"].append(input_info)

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class DiscoveryEngine:
    """
    Safe, deterministic discovery engine for authorized local test applications.
    Enforces strict request limits, timeouts, same-target boundaries, and redirect guards.
    """

    DEFAULT_CANDIDATE_ROUTES: List[str] = [
        "/",
        "/sqli",
        "/xss",
        "/idor",
        "/record/1",
        "/record/2",
        "/record_lookup",
        "/api/health",
        "/api/mode",
        "/api/search",
        "/api/search?q=",
        "/api/greet",
        "/api/greet?name=",
        "/api/record/1",
        "/api/record/2",
        "/search",
        "/login",
    ]

    def __init__(
        self,
        scope_controller: Optional[ScopeController] = None,
        max_requests: int = 30,
        timeout: float = 3.0,
        candidates: Optional[List[str]] = None,
    ):
        self.scope_controller = scope_controller or ScopeController()
        self.max_requests = max_requests
        self.timeout = timeout
        self.candidate_routes = list(candidates or self.DEFAULT_CANDIDATE_ROUTES)

    def _normalize_target_origin(self, target_url: str) -> Tuple[str, str, int]:
        """Extracts (scheme, hostname, port) for origin comparison."""
        parsed = urlparse(target_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return (parsed.scheme.lower(), (parsed.hostname or "").lower(), port)

    def _is_same_origin(self, base_origin: Tuple[str, str, int], candidate_url: str) -> bool:
        """Enforces same-origin boundary to prevent external crawl drift."""
        cand_origin = self._normalize_target_origin(candidate_url)
        return base_origin == cand_origin

    def _detect_path_parameters(self, path: str) -> List[DiscoveredInput]:
        """Identifies URL path parameters (e.g. /record/1 -> parameter record_id)."""
        inputs = []
        segments = [s for s in path.strip("/").split("/") if s]
        for i, seg in enumerate(segments):
            if seg.isdigit():
                param_name = segments[i - 1] + "_id" if i > 0 else "id"
                inputs.append(
                    DiscoveredInput(
                        name=param_name,
                        location="path_param",
                        input_type="integer",
                        sample_value=seg,
                    )
                )
        return inputs

    def discover(self, target_url: str) -> DiscoveryResult:
        """
        Executes bounded, safe discovery on an authorized local target.
        """
        start_time = datetime.now()
        timestamp_str = start_time.isoformat()

        # Step 1: Mandatory Scope Controller Authorization
        val: ScopeValidationResult = self.scope_controller.authorize_operation(
            target_url, operation="DISCOVERY_ATTACK_SURFACE"
        )
        if not val.is_allowed:
            return DiscoveryResult(
                target_url=target_url,
                success=False,
                timestamp=timestamp_str,
                scope_decision=asdict(val),
                error=f"Scope violation: {val.reason}",
                total_requests=0,
            )

        target_base = target_url.rstrip("/")
        base_origin = self._normalize_target_origin(target_base)

        discovered_endpoints: Dict[Tuple[str, str], DiscoveredEndpoint] = {}
        all_inputs_list: List[Dict[str, Any]] = []
        redirect_violations: List[Dict[str, Any]] = []
        visited_urls: Set[str] = set()
        request_count = 0

        # Create session with connection controls
        session = requests.Session()
        session.headers.update({
            "User-Agent": "VulnFix-DiscoveryEngine/1.0 (Authorized Local Security Testing)",
            "Accept": "text/html,application/json,*/*",
        })

        # Queue of paths to inspect
        queue: List[str] = list(self.candidate_routes)

        while queue and request_count < self.max_requests:
            current_path = queue.pop(0)
            
            # Format and normalize URL
            if current_path.startswith("http://") or current_path.startswith("https://"):
                full_url = current_path
                parsed = urlparse(full_url)
                current_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            else:
                full_url = urljoin(f"{target_base}/", current_path.lstrip("/"))

            # Skip already visited URLs
            clean_visited_key = f"GET:{full_url}"
            if clean_visited_key in visited_urls:
                continue
            visited_urls.add(clean_visited_key)

            # Enforce same-origin boundary
            if not self._is_same_origin(base_origin, full_url):
                redirect_violations.append({
                    "source": current_path,
                    "target": full_url,
                    "reason": "URL leaves authorized target origin.",
                })
                continue

            # Execute safe HTTP request (bounded timeout, no auto redirects)
            request_count += 1
            try:
                resp = session.get(
                    full_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.Timeout:
                continue
            except requests.RequestException:
                continue

            # Inspect redirect responses (3xx)
            if 300 <= resp.status_code < 400:
                location = resp.headers.get("Location")
                if location:
                    redirect_target = urljoin(full_url, location)
                    if not self._is_same_origin(base_origin, redirect_target):
                        redirect_violations.append({
                            "source": current_path,
                            "target": redirect_target,
                            "reason": "Redirect destination leaves authorized origin scope.",
                        })
                    else:
                        parsed_redir = urlparse(redirect_target)
                        rel_path = parsed_redir.path + (f"?{parsed_redir.query}" if parsed_redir.query else "")
                        if rel_path not in queue and f"GET:{redirect_target}" not in visited_urls:
                            queue.append(rel_path)

            content_type = resp.headers.get("Content-Type", "unknown").split(";")[0].strip()
            parsed_url = urlparse(full_url)
            norm_endpoint = parsed_url.path or "/"

            # Extract inputs from query parameters
            query_inputs: List[DiscoveredInput] = []
            parsed_query = parse_qs(parsed_url.query, keep_blank_values=True)
            for param_name, values in parsed_query.items():
                query_inputs.append(
                    DiscoveredInput(
                        name=param_name,
                        location="query_param",
                        input_type="query_string",
                        sample_value=values[0] if values else "",
                    )
                )

            # Extract path parameters
            path_inputs = self._detect_path_parameters(norm_endpoint)

            # Parse HTML content if applicable
            html_forms: List[Dict[str, Any]] = []
            if "html" in content_type and resp.text:
                try:
                    parser = _HTMLAttackSurfaceParser()
                    parser.feed(resp.text)
                    html_forms = parser.forms

                    # Enqueue newly discovered links if under request limit
                    for link in parser.links:
                        resolved_link = urljoin(full_url, link)
                        if self._is_same_origin(base_origin, resolved_link):
                            p_link = urlparse(resolved_link)
                            clean_rel = p_link.path + (f"?{p_link.query}" if p_link.query else "")
                            if clean_rel not in queue and f"GET:{resolved_link}" not in visited_urls:
                                queue.append(clean_rel)
                except Exception:
                    pass

            # Combine inputs found for this GET endpoint
            combined_get_inputs: List[DiscoveredInput] = query_inputs + path_inputs
            primary_param = combined_get_inputs[0].name if combined_get_inputs else None
            primary_loc = combined_get_inputs[0].location if combined_get_inputs else "none"

            # Determine discovery source
            source = "api_probe" if "/api/" in norm_endpoint else "route_probe"

            endpoint_key = ("GET", norm_endpoint)
            if endpoint_key not in discovered_endpoints:
                discovered_endpoints[endpoint_key] = DiscoveredEndpoint(
                    endpoint=norm_endpoint,
                    full_url=urljoin(f"{target_base}/", norm_endpoint.lstrip("/")),
                    method="GET",
                    parameter_name=primary_param,
                    input_location=primary_loc,
                    status_code=resp.status_code,
                    content_type=content_type,
                    discovery_source=source,
                    inputs=[asdict(i) for i in combined_get_inputs],
                )
            else:
                existing_ep = discovered_endpoints[endpoint_key]
                existing_input_names = {i["name"] for i in existing_ep.inputs}
                for inp in combined_get_inputs:
                    if inp.name not in existing_input_names:
                        existing_ep.inputs.append(asdict(inp))
                        if not existing_ep.parameter_name:
                            existing_ep.parameter_name = inp.name
                            existing_ep.input_location = inp.location

            # Record inputs
            for inp in combined_get_inputs:
                all_inputs_list.append({
                    "endpoint": norm_endpoint,
                    "method": "GET",
                    "name": inp.name,
                    "location": inp.location,
                    "type": inp.input_type,
                })

            # Process discovered HTML forms
            for form in html_forms:
                form_action = form.get("action", "") or norm_endpoint
                form_method = form.get("method", "GET").upper()
                resolved_form_url = urljoin(full_url, form_action)
                form_endpoint = urlparse(resolved_form_url).path or "/"

                form_inputs: List[DiscoveredInput] = []
                for inp_dict in form.get("inputs", []):
                    form_inputs.append(
                        DiscoveredInput(
                            name=inp_dict["name"],
                            location="form_body" if form_method == "POST" else "query_param",
                            input_type=inp_dict.get("type", "text"),
                            sample_value=inp_dict.get("value", ""),
                        )
                    )

                primary_form_param = form_inputs[0].name if form_inputs else None
                primary_form_loc = form_inputs[0].location if form_inputs else "none"

                form_key = (form_method, form_endpoint)
                if form_key not in discovered_endpoints:
                    discovered_endpoints[form_key] = DiscoveredEndpoint(
                        endpoint=form_endpoint,
                        full_url=resolved_form_url,
                        method=form_method,
                        parameter_name=primary_form_param,
                        input_location=primary_form_loc,
                        status_code=200,  # discovered form
                        content_type="text/html",
                        discovery_source="html_form",
                        inputs=[asdict(i) for i in form_inputs],
                    )
                else:
                    existing_form_ep = discovered_endpoints[form_key]
                    existing_input_names = {i["name"] for i in existing_form_ep.inputs}
                    for inp in form_inputs:
                        if inp.name not in existing_input_names:
                            existing_form_ep.inputs.append(asdict(inp))
                            if not existing_form_ep.parameter_name:
                                existing_form_ep.parameter_name = inp.name
                                existing_form_ep.input_location = inp.location

                for f_inp in form_inputs:
                    all_inputs_list.append({
                        "endpoint": form_endpoint,
                        "method": form_method,
                        "name": f_inp.name,
                        "location": f_inp.location,
                        "type": f_inp.input_type,
                    })

        # Deduplicate all_inputs_list
        unique_inputs = []
        seen_inputs = set()
        for item in all_inputs_list:
            key = (item["endpoint"], item["method"], item["name"], item["location"])
            if key not in seen_inputs:
                seen_inputs.add(key)
                unique_inputs.append(item)

        endpoints_list = [asdict(ep) for ep in discovered_endpoints.values()]

        # Compute duration
        duration = round((datetime.now() - start_time).total_seconds(), 3)

        # Step 7: Store Evidence JSON artifact under data/findings/
        evidence_file_path = None
        try:
            FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
            safe_host = val.normalized_host or "localhost"
            filename = f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_host}_{val.port or 80}.json"
            evidence_path = FINDINGS_DIR / filename
            
            evidence_data = {
                "timestamp": timestamp_str,
                "authorized_target": target_url,
                "scope_decision": asdict(val),
                "summary": {
                    "total_endpoints": len(endpoints_list),
                    "total_inputs": len(unique_inputs),
                    "total_requests": request_count,
                    "duration_seconds": duration,
                },
                "discovered_endpoints": endpoints_list,
                "discovered_inputs": unique_inputs,
                "redirect_violations": redirect_violations,
            }

            with open(evidence_path, "w", encoding="utf-8") as f:
                json.dump(evidence_data, f, indent=2)
            evidence_file_path = str(evidence_path)
        except Exception:
            pass

        return DiscoveryResult(
            target_url=target_url,
            success=True,
            timestamp=timestamp_str,
            scope_decision=asdict(val),
            endpoints=endpoints_list,
            all_inputs=unique_inputs,
            redirect_violations=redirect_violations,
            total_requests=request_count,
            duration_seconds=duration,
            evidence_file=evidence_file_path,
        )


class LocalServiceDiscovery(DiscoveryEngine):
    """
    Backward-compatible interface for discovery operations.
    Inherits all capabilities of the DiscoveryEngine.
    """

    def discover_endpoints(self, target_base_url: str, endpoint_candidates: Optional[List[str]] = None) -> Dict[str, Any]:
        """Provides backwards-compatible dictionary format."""
        if endpoint_candidates:
            self.candidate_routes = endpoint_candidates
        res = self.discover(target_base_url)
        return {
            "success": res.success,
            "target": res.target_url,
            "total_endpoints": len(res.endpoints),
            "endpoints": res.endpoints,
            "inputs": res.all_inputs,
            "scope_verified": res.success,
            "error": res.error,
        }
