"""
VulnFix AI — Offensive Security & Red Teaming
AI-Powered Vulnerability Validation and Proof-of-Fix Platform

Presentation Dashboard & Scope Governance Portal
"""

import streamlit as st
import os
import json
import requests
from pathlib import Path
from datetime import datetime
from dataclasses import asdict
from typing import Dict, Any, Optional, List, Union

import config
from modules.scope_controller import ScopeController, ScopeValidationResult
from modules.discovery import DiscoveryEngine, DiscoveryResult
from modules.vulnerability_detector import VulnerabilityDetector, FindingCandidate, DetectionResult
from modules.evidence import EvidenceManager
from modules.validator import VulnerabilityValidator, ValidationOutcome, ValidationRunResult
from modules.risk_engine import RiskEngine, RiskAssessment, RiskFactors
from modules.remediation import RemediationEngine, RemediationPlan
from modules.retest import RetestEngine, RetestResult


# --- Page Configuration ---
st.set_page_config(
    page_title="VulnFix AI — Offensive Security & Red Teaming",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom Styling ---
st.markdown(
    """
    <style>
        .main-header {
            font-size: 2.1rem;
            font-weight: 700;
            color: #0F172A;
            margin-bottom: 0.1rem;
        }
        .track-badge {
            display: inline-block;
            background: linear-gradient(135deg, #DC2626, #991B1B);
            color: white;
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.2rem 0.65rem;
            border-radius: 9999px;
            margin-bottom: 0.4rem;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }
        .stepper-container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #F8FAFC;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 0.75rem 1rem;
            margin-bottom: 1.2rem;
            font-size: 0.82rem;
            overflow-x: auto;
        }
        .step-item {
            display: flex;
            align-items: center;
            gap: 0.35rem;
            font-weight: 600;
        }
        .step-arrow {
            color: #94A3B8;
            font-size: 0.85rem;
        }
        .badge-done {
            background: #DCFCE7;
            color: #166534;
            padding: 0.2rem 0.55rem;
            border-radius: 9999px;
            border: 1px solid #86EFAC;
            font-size: 0.78rem;
            font-weight: 600;
        }
        .badge-pending {
            background: #F1F5F9;
            color: #64748B;
            padding: 0.2rem 0.55rem;
            border-radius: 9999px;
            border: 1px solid #CBD5E1;
            font-size: 0.78rem;
            font-weight: 500;
        }
        .badge-allowed {
            background-color: #16A34A;
            color: white;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.75rem;
        }
        .badge-rejected {
            background-color: #DC2626;
            color: white;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.75rem;
        }
        .badge-sec-vulnerable {
            background-color: #FEF2F2;
            color: #991B1B;
            border: 1px solid #FCA5A5;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.82rem;
            display: inline-block;
        }
        .badge-sec-secure {
            background-color: #F0FDF4;
            color: #166534;
            border: 1px solid #86EFAC;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.82rem;
            display: inline-block;
        }
        .target-card-active {
            background: #F0FDF4;
            border: 2px solid #22C55E;
            border-radius: 8px;
            padding: 1.1rem;
            margin-bottom: 1rem;
        }
        .target-card-empty {
            background: #FFFBEB;
            border: 2px dashed #F59E0B;
            border-radius: 8px;
            padding: 1.1rem;
            margin-bottom: 1rem;
        }
        .lifecycle-stage-card {
            background: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 1rem 1.25rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }
        .lifecycle-stage-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #F1F5F9;
            padding-bottom: 0.5rem;
            margin-bottom: 0.75rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Persistent Session State Initialization ---
if "scope_controller" not in st.session_state:
    st.session_state.scope_controller = ScopeController()

scope_ctrl: ScopeController = st.session_state.scope_controller

if "selected_target" not in st.session_state:
    default_target = "http://127.0.0.1:5000"
    val = scope_ctrl.set_selected_target(default_target)
    if val.is_allowed:
        st.session_state.selected_target = default_target
    else:
        auth_targets = scope_ctrl.get_authorized_targets()
        st.session_state.selected_target = auth_targets[0] if auth_targets else None


# --- Lab Helper Functions ---
def get_current_lab_mode(target_url: Optional[str]) -> Optional[str]:
    """Queries the target lab's current security mode (vulnerable vs secure)."""
    if not target_url:
        return None
    try:
        resp = requests.get(f"{target_url}/api/mode", timeout=1.0)
        if resp.status_code == 200:
            return resp.json().get("security_mode")
    except Exception:
        pass
    return None


def set_lab_mode(target_url: Optional[str], new_mode: str) -> bool:
    """Toggles the target lab's security mode."""
    if not target_url:
        return False
    try:
        resp = requests.post(f"{target_url}/api/mode", json={"mode": new_mode}, timeout=2.0)
        return resp.status_code == 200
    except Exception:
        return False


# --- Full End-to-End Pipeline Executor ---
def execute_full_pipeline(curr_target: str) -> bool:
    """Executes all 6 sequential engines in one click and persists all session state."""
    auth_check = scope_ctrl.authorize_operation(curr_target, "FULL_PIPELINE")
    if not auth_check.is_allowed:
        st.error(f"Cannot run pipeline: {auth_check.reason}")
        return False

    try:
        with st.spinner("Executing Full Pipeline (Discovery ➔ Detection ➔ Validation ➔ Risk ➔ Remediation ➔ Retest)..."):
            # 1. Discovery
            disc_engine = DiscoveryEngine(scope_controller=scope_ctrl, max_requests=30, timeout=2.5)
            disc_res = disc_engine.discover(curr_target)
            st.session_state["discovery_result"] = asdict(disc_res)

            # 2. Detection
            det_engine = VulnerabilityDetector(scope_controller=scope_ctrl, max_requests=25, timeout=2.5)
            det_res = det_engine.detect_candidates(curr_target, discovery_result=disc_res)
            st.session_state["detection_result"] = asdict(det_res)

            candidates = det_res.candidates

            # 3. Validation
            val_engine = VulnerabilityValidator(scope_controller=scope_ctrl, max_requests=25, timeout=2.5)
            val_res = val_engine.validate_candidates(curr_target, candidates)
            st.session_state["validation_result"] = asdict(val_res)

            # 4. Risk Assessment
            risk_engine = RiskEngine()
            assessments = risk_engine.assess_all(candidates, validations=val_res.outcomes, persist=True)
            st.session_state["risk_results"] = [a.to_dict() for a in assessments]

            # 5. Remediation
            rem_engine = RemediationEngine()
            plans = rem_engine.generate_remediations_all(candidates, risk_assessments=st.session_state["risk_results"], persist=True)
            st.session_state["remediation_results"] = [p.to_dict() for p in plans]

            # 6. Retest
            retest_engine = RetestEngine(scope_controller=scope_ctrl)
            retests = retest_engine.retest_candidates(curr_target, candidates, remediations=st.session_state["remediation_results"], persist=True)
            st.session_state["retest_results"] = [r.to_dict() for r in retests]

        st.success("✅ Full End-to-End Pipeline executed successfully! All stages completed.")
        return True
    except Exception as e:
        st.error(f"Pipeline execution halted: {e}")
        return False


# --- Sidebar Component ---
def render_sidebar():
    """Renders persistent platform controls, current target, and scope parameters."""
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/shield.png", width=56)
        st.markdown("### **VulnFix AI Platform**")
        st.caption("Offensive Security & Red Teaming Track")
        st.markdown("---")

        st.markdown("#### 🎯 **Active Target**")
        curr_target = st.session_state.get("selected_target", "http://127.0.0.1:5000")
        if curr_target:
            st.success(f"**Target**: `{curr_target}`")
            status = scope_ctrl.get_target_status(curr_target)
            st.markdown(
                f"""
                - **Status**: `🟢 AUTHORIZED`
                - **Host**: `{status.get('host')}`
                - **Port**: `{status.get('port')}`
                - **Loopback**: `{'Yes' if status.get('is_loopback') else 'No'}`
                """
            )
        else:
            st.warning("⚠️ No active target selected.")

        st.markdown("---")
        st.markdown("#### 🔒 **Strict Scope Policy**")
        st.markdown(
            """
            - **Strict Local Only**: `ENABLED`
            - **Allowed Hosts**: `localhost`, `127.0.0.1`, `::1`
            - **External Probing**: `BLOCKED`
            - **Destructive Actions**: `LOCKED OUT`
            """
        )

        st.markdown("---")
        st.markdown("#### 📁 **Platform Storage**")
        db_exists = config.DB_PATH.exists()
        st.write(f"• **SQLite Database**: {'🟢 Connected' if db_exists else '🔴 Missing'}")
        st.write(f"• **Audit Log File**: `{config.SCOPE_AUDIT_LOG_FILE.name}`")
        st.write(f"• **Target Config File**: `{config.AUTHORIZED_TARGETS_FILE.name}`")

        st.markdown("---")
        st.caption("VulnFix AI Platform v1.0.0 — Proof-of-Fix Architecture")


# --- Top Header Component ---
def render_header(curr_target: str, lab_mode: Optional[str]):
    """Renders the top branding, active target status, lab security mode toggle, and primary actions."""
    st.markdown('<div class="track-badge">Track: Offensive Security & Red Teaming</div>', unsafe_allow_html=True)
    st.markdown('<div class="main-header">VulnFix AI — Offensive Security & Red Teaming</div>', unsafe_allow_html=True)
    st.caption("Deterministic Vulnerability Validation, Multi-Factor Risk Assessment, Contextual Remediation & Proof-of-Fix")

    # Header Card with target status, lab mode, toggle, and Full Pipeline trigger
    is_sec = (lab_mode == "secure")
    mode_label = "SECURE (Remediated)" if is_sec else ("VULNERABLE (Defects Active)" if lab_mode == "vulnerable" else "UNKNOWN")
    mode_class = "badge-sec-secure" if is_sec else "badge-sec-vulnerable"

    col_target, col_mode, col_actions = st.columns([4, 3, 3], gap="medium")
    with col_target:
        st.markdown(
            f"""
            <div style="background:#F8FAFC; border:1px solid #CBD5E1; border-radius:8px; padding:0.85rem 1rem;">
                <div style="font-size:0.72rem; color:#64748B; font-weight:700; text-transform:uppercase;">Active Target</div>
                <div style="font-size:1.15rem; font-weight:700; color:#0F172A; margin:0.2rem 0;">
                    <code>{curr_target}</code> <span class="badge-allowed">AUTHORIZED</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_mode:
        st.markdown(
            f"""
            <div style="background:#F8FAFC; border:1px solid #CBD5E1; border-radius:8px; padding:0.85rem 1rem; margin-bottom:0.35rem;">
                <div style="font-size:0.75rem; color:#64748B; font-weight:700; text-transform:uppercase;">Lab Security Mode</div>
                <div style="margin-top:0.25rem;">
                    <span class="{mode_class}">● {mode_label}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if lab_mode:
            toggle_label = "Switch Lab to Vulnerable" if is_sec else "Switch Lab to Secure (Remediated)"
            if st.button(f"⚡ {toggle_label}", use_container_width=True, key="header_mode_toggle"):
                new_mode = "vulnerable" if is_sec else "secure"
                if set_lab_mode(curr_target, new_mode):
                    st.success(f"Lab switched to {new_mode.upper()}")
                    st.rerun()
                else:
                    st.error("Failed to switch lab security mode.")

    with col_actions:
        st.write("")
        run_full_btn = st.button("▶ Run Full End-to-End Pipeline", type="primary", use_container_width=True, key="btn_run_full_pipeline")
        if run_full_btn:
            if execute_full_pipeline(curr_target):
                st.rerun()


# --- Stepper Component ---
def render_stepper():
    """Renders the 8-stage progress stepper across the security lifecycle."""
    has_disc = bool(st.session_state.get("discovery_result"))
    has_det = bool(st.session_state.get("detection_result"))
    has_val = bool(st.session_state.get("validation_result"))
    has_risk = bool(st.session_state.get("risk_results"))
    has_rem = bool(st.session_state.get("remediation_results"))
    has_retest = bool(st.session_state.get("retest_results"))

    def b(is_done: bool, label: str) -> str:
        cls = "badge-done" if is_done else "badge-pending"
        icon = "✅" if is_done else "⚪"
        return f'<span class="{cls}">{icon} {label}</span>'

    st.markdown(
        f"""
        <div class="stepper-container">
            <div class="step-item">{b(True, "1. Scope Check")}</div>
            <span class="step-arrow">➔</span>
            <div class="step-item">{b(True, "2. Target Auth")}</div>
            <span class="step-arrow">➔</span>
            <div class="step-item">{b(has_disc, "3. Discovery")}</div>
            <span class="step-arrow">➔</span>
            <div class="step-item">{b(has_det, "4. Detection")}</div>
            <span class="step-arrow">➔</span>
            <div class="step-item">{b(has_val, "5. Validation")}</div>
            <span class="step-arrow">➔</span>
            <div class="step-item">{b(has_risk, "6. Risk Engine")}</div>
            <span class="step-arrow">➔</span>
            <div class="step-item">{b(has_rem, "7. Remediation")}</div>
            <span class="step-arrow">➔</span>
            <div class="step-item">{b(has_retest, "8. Retest")}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# =============================================================================
# TAB 1: 🚀 End-to-End Pipeline
# =============================================================================
def render_tab1_pipeline(curr_target: str, lab_mode: Optional[str]):
    """Renders the 4 compact pipeline stages with step-by-step executions and expanders."""
    render_stepper()

    disc_data = st.session_state.get("discovery_result")
    det_data = st.session_state.get("detection_result")
    val_data = st.session_state.get("validation_result")
    risk_data = st.session_state.get("risk_results")
    rem_data = st.session_state.get("remediation_results")
    retest_data = st.session_state.get("retest_results")

    candidates = det_data.get("candidates", []) if det_data else []
    val_outcomes = val_data.get("outcomes", []) if val_data else []

    # -------------------------------------------------------------------------
    # 1. Discovery & Attack Surface
    # -------------------------------------------------------------------------
    disc_status_badge = "✅ COMPLETED" if disc_data else "⚪ READY"
    with st.expander(f"🔎 **1. Discovery & Attack Surface** [{disc_status_badge}]", expanded=True):
        col_d_ctrl, col_d_run = st.columns([3, 1], gap="medium")
        with col_d_ctrl:
            with st.expander("⚙️ Bounded Safety Limits", expanded=False):
                max_reqs = st.slider("Max HTTP Requests", min_value=5, max_value=50, value=30, step=5, key="disc_slider_reqs")
                timeout_sec = st.slider("Request Timeout (s)", min_value=1.0, max_value=5.0, value=2.5, step=0.5, key="disc_slider_timeout")
        with col_d_run:
            st.write("")
            run_disc_btn = st.button("🚀 Run Discovery", type="primary", use_container_width=True, key="btn_run_discovery")

        if run_disc_btn:
            with st.spinner(f"Executing bounded discovery against {curr_target}..."):
                engine = DiscoveryEngine(
                    scope_controller=scope_ctrl,
                    max_requests=max_reqs,
                    timeout=timeout_sec,
                )
                disc_res = engine.discover(curr_target)
                st.session_state["discovery_result"] = asdict(disc_res)
                st.rerun()

        if disc_data:
            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric("Endpoints Discovered", len(disc_data.get("endpoints", [])))
            with m2:
                st.metric("Inputs Cataloged", len(disc_data.get("all_inputs", [])))
            with m3:
                st.metric("Network Probes", f"{disc_data.get('total_requests', 0)} ({disc_data.get('duration_seconds', 0.0)}s)")

            endpoints = disc_data.get("endpoints", [])
            inputs = disc_data.get("all_inputs", [])

            col_ep, col_inp = st.columns([1, 1], gap="medium")
            with col_ep:
                st.markdown("##### **Discovered Endpoints**")
                if endpoints:
                    st.dataframe(
                        [
                            {
                                "Method": ep["method"],
                                "Endpoint": ep["endpoint"],
                                "Status": ep["status_code"],
                                "Param": ep["parameter_name"] or "—",
                                "Source": ep["discovery_source"],
                            }
                            for ep in endpoints
                        ],
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.info("No endpoints discovered.")

            with col_inp:
                st.markdown("##### **Cataloged Inputs**")
                if inputs:
                    st.dataframe(
                        [
                            {
                                "Endpoint": inp["endpoint"],
                                "Method": inp["method"],
                                "Param": inp["name"],
                                "Location": inp["location"],
                                "Type": inp["type"],
                            }
                            for inp in inputs
                        ],
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.info("No input parameters cataloged.")

            # Neutral Attack Surface summary
            query_inputs = [i for i in inputs if i["location"] == "query_param"]
            form_inputs = [i for i in inputs if i["location"] == "form_body"]
            path_inputs = [i for i in inputs if i["location"] == "path_param"]
            api_endpoints = [ep for ep in endpoints if ep["discovery_source"] == "api_probe"]

            c_as1, c_as2, c_as3, c_as4 = st.columns(4)
            with c_as1:
                st.caption(f"🌐 **Query Parameters**: {len(query_inputs)}")
            with c_as2:
                st.caption(f"📝 **Form Fields**: {len(form_inputs)}")
            with c_as3:
                st.caption(f"🆔 **Path Parameters**: {len(path_inputs)}")
            with c_as4:
                st.caption(f"⚡ **API Routes**: {len(api_endpoints)}")

            with st.expander("📁 Raw Discovery Artifact & JSON", expanded=False):
                if disc_data.get("evidence_file"):
                    st.caption(f"Evidence Artifact: `{disc_data.get('evidence_file')}`")
                st.json(disc_data)
        else:
            st.info("Discovery has not been executed yet. Click 'Run Discovery' above.")

    # -------------------------------------------------------------------------
    # 2. Detection & Validation
    # -------------------------------------------------------------------------
    det_badge = f"✅ {len(candidates)} Candidates" if candidates else ("✅ 0 Found" if det_data else "⚪ READY")
    with st.expander(f"🛡️ **2. Detection & Validation** [{det_badge}]", expanded=bool(disc_data)):
        tab_det, tab_val = st.tabs(["🎯 Controlled Detection", "🔬 Deterministic Validation"])

        with tab_det:
            c_det_cfg, c_det_run = st.columns([3, 1], gap="medium")
            with c_det_cfg:
                with st.expander("⚙️ Detection Safety Settings", expanded=False):
                    det_max_reqs = st.slider("Detection Request Limit", min_value=10, max_value=40, value=25, step=5, key="det_slider_reqs")
                    det_timeout = st.slider("Probe Timeout (s)", min_value=1.0, max_value=5.0, value=2.5, step=0.5, key="det_slider_timeout")
            with c_det_run:
                st.write("")
                run_det_btn = st.button("🎯 Run Detection", type="primary", use_container_width=True, key="btn_run_detection")

            if run_det_btn:
                with st.spinner(f"Executing non-destructive vulnerability detection against {curr_target}..."):
                    detector = VulnerabilityDetector(scope_controller=scope_ctrl, max_requests=det_max_reqs, timeout=det_timeout)
                    discovery_obj = None
                    if disc_data:
                        discovery_obj = DiscoveryResult(
                            target_url=disc_data.get("target_url", curr_target),
                            success=disc_data.get("success", True),
                            timestamp=disc_data.get("timestamp", ""),
                            scope_decision=disc_data.get("scope_decision", {}),
                            endpoints=disc_data.get("endpoints", []),
                            all_inputs=disc_data.get("all_inputs", []),
                            redirect_violations=disc_data.get("redirect_violations", []),
                            total_requests=disc_data.get("total_requests", 0),
                        )
                    det_res = detector.detect_candidates(curr_target, discovery_result=discovery_obj)
                    st.session_state["detection_result"] = asdict(det_res)
                    st.rerun()

            if det_data:
                vuln_count = len([c for c in candidates if c.get("is_vulnerable")])
                s1, s2, s3 = st.columns(3)
                with s1:
                    st.metric("Hypotheses Evaluated", len(candidates))
                with s2:
                    st.metric("Likely Vulnerabilities", vuln_count, delta=f"{vuln_count} detected" if vuln_count else "None", delta_color="inverse" if vuln_count else "normal")
                with s3:
                    st.metric("Probes Executed", det_data.get("total_requests", 0))

                if candidates:
                    st.dataframe(
                        [
                            {
                                "ID": c.get("id"),
                                "Vulnerability": c.get("vuln_type"),
                                "CWE": c.get("cwe_id"),
                                "Endpoint": c.get("endpoint"),
                                "Param": c.get("affected_parameter") or "—",
                                "Status": c.get("detection_status"),
                                "Confidence": f"{int(c.get('confidence', 0.0) * 100)}%",
                                "Severity": c.get("severity"),
                            }
                            for c in candidates
                        ],
                        use_container_width=True,
                        hide_index=True,
                    )
                with st.expander("📁 Raw Detection Evidence & Payloads", expanded=False):
                    if det_data.get("evidence_file"):
                        st.caption(f"Detection Artifact: `{det_data.get('evidence_file')}`")
                    st.json(det_data)
            else:
                st.info("Detection has not been run for this session. Click 'Run Detection' above.")

        with tab_val:
            c_val_cfg, c_val_run = st.columns([3, 1], gap="medium")
            with c_val_cfg:
                with st.expander("⚙️ Validation Safety Bounds", expanded=False):
                    val_max_reqs = st.slider("Validation Max Requests", min_value=10, max_value=40, value=25, step=5, key="val_req_slider")
                    val_timeout = st.slider("Probe Timeout (s)", min_value=1.0, max_value=5.0, value=2.5, step=0.5, key="val_timeout_slider")
            with c_val_run:
                st.write("")
                run_val_btn = st.button("🔬 Run Validation", type="primary", use_container_width=True, disabled=not bool(candidates), key="btn_run_val")

            if run_val_btn:
                with st.spinner(f"Executing deterministic validation against {curr_target}..."):
                    validator = VulnerabilityValidator(scope_controller=scope_ctrl, max_requests=val_max_reqs, timeout=val_timeout)
                    val_run = validator.validate_candidates(curr_target, candidates)
                    st.session_state["validation_result"] = asdict(val_run)
                    st.rerun()

            if val_data:
                v1, v2, v3 = st.columns(3)
                with v1:
                    st.metric("Confirmed Vulnerabilities", val_data.get("confirmed_count", 0), delta=f"{val_data.get('confirmed_count', 0)} confirmed" if val_data.get("confirmed_count") else "None", delta_color="inverse")
                with v2:
                    st.metric("Not Confirmed (Safe)", val_data.get("not_confirmed_count", 0))
                with v3:
                    st.metric("Total Validated", val_data.get("total_validated", 0))

                if val_outcomes:
                    st.dataframe(
                        [
                            {
                                "Finding ID": o.get("finding_id"),
                                "Status": o.get("validation_status"),
                                "Confirmed": "✅ Yes" if o.get("is_confirmed") else "❌ No",
                                "Confidence": f"{int(o.get('confidence_score', 0.0) * 100)}%",
                                "Method": o.get("validation_method"),
                                "Safe PoC": o.get("proof_of_concept_safe") or "—",
                            }
                            for o in val_outcomes
                        ],
                        use_container_width=True,
                        hide_index=True,
                    )
                with st.expander("📁 Raw Validation Outcomes & Evidence", expanded=False):
                    st.json(val_data)
            else:
                st.info("Deterministic validation has not been run for this session. Click 'Run Validation' above.")

    # -------------------------------------------------------------------------
    # 3. Risk & Remediation
    # -------------------------------------------------------------------------
    risk_badge = f"✅ {len(risk_data)} Scored" if risk_data else "⚪ READY"
    with st.expander(f"📊 **3. Risk Assessment & Remediation** [{risk_badge}]", expanded=bool(val_data)):
        tab_risk, tab_rem = st.tabs(["📊 Contextual Risk Assessment", "🛠️ Defensive Guidance & Code Patches"])

        with tab_risk:
            c_r_info, c_r_run = st.columns([3, 1], gap="medium")
            with c_r_info:
                st.caption(f"Formula: `(0.45 × Exploitability + 0.55 × Impact) × Confidence × Validation Multiplier` | Inputs: {len(candidates)} findings, {len(val_outcomes)} validations")
            with c_r_run:
                run_risk_btn = st.button("📊 Calculate Risk", type="primary", use_container_width=True, disabled=not bool(candidates), key="btn_run_risk")

            if run_risk_btn:
                with st.spinner("Computing rule-based multi-factor contextual risk scores..."):
                    risk_engine = RiskEngine()
                    assessments = risk_engine.assess_all(candidates, validations=val_outcomes, persist=True)
                    st.session_state["risk_results"] = [a.to_dict() for a in assessments]
                    st.rerun()

            if risk_data:
                max_score = max([r.get("risk_score", 0.0) for r in risk_data])
                crit_count = len([r for r in risk_data if r.get("severity") == "CRITICAL"])
                p1_count = len([r for r in risk_data if r.get("remediation_priority") == "P1"])

                r1, r2, r3 = st.columns(3)
                with r1:
                    st.metric("Peak Risk Score", f"{max_score}/10.0", delta="CRITICAL" if max_score >= 9.0 else "ELEVATED", delta_color="inverse")
                with r2:
                    st.metric("P1 / Critical Priorities", p1_count)
                with r3:
                    st.metric("Total Findings Assessed", len(risk_data))

                st.dataframe(
                    [
                        {
                            "Finding ID": r.get("finding_id"),
                            "Risk Score": f"{r.get('risk_score')}/10.0",
                            "Severity": r.get("severity"),
                            "Priority": r.get("remediation_priority"),
                            "Urgency": r.get("remediation_urgency"),
                            "Exploitability": f"{r.get('exploitability')}/10.0",
                            "Impact": f"{r.get('impact')}/10.0",
                            "Confidence": f"{int(r.get('confidence', 0.0) * 100)}%",
                        }
                        for r in risk_data
                    ],
                    use_container_width=True,
                    hide_index=True,
                )
                with st.expander("📁 Raw Risk Factors & Formula Traces", expanded=False):
                    st.json(risk_data)
            else:
                st.info("Risk assessment has not been run for this session. Click 'Calculate Risk' above.")

        with tab_rem:
            c_rem_info, c_rem_run = st.columns([3, 1], gap="medium")
            with c_rem_info:
                st.caption(f"Generates concrete code patches, architectural guidance, and verification checklists for {len(candidates)} findings.")
            with c_rem_run:
                run_rem_btn = st.button("🛠️ Generate Remediation", type="primary", use_container_width=True, disabled=not bool(candidates), key="btn_run_rem")

            if run_rem_btn:
                with st.spinner("Generating contextual code patches and verification checklists..."):
                    rem_engine = RemediationEngine()
                    plans = rem_engine.generate_remediations_all(candidates, risk_assessments=risk_data, persist=True)
                    st.session_state["remediation_results"] = [p.to_dict() for p in plans]
                    st.rerun()

            if rem_data:
                st.dataframe(
                    [
                        {
                            "Finding ID": p.get("finding_id"),
                            "CWE": p.get("cwe_id"),
                            "Strategy": p.get("title"),
                            "Priority": p.get("remediation_priority"),
                            "Severity": p.get("severity"),
                            "Endpoint": p.get("endpoint"),
                        }
                        for p in rem_data
                    ],
                    use_container_width=True,
                    hide_index=True,
                )

                selected_rem_id = st.selectbox(
                    "Inspect Patch & Guidance for Finding:",
                    options=[p["finding_id"] for p in rem_data],
                    key="rem_tab1_inspect_select",
                )
                sel_p = next((p for p in rem_data if p["finding_id"] == selected_rem_id), None)
                if sel_p:
                    st.markdown(f"**Strategy**: `{sel_p.get('title')}` | **CWE**: `{sel_p.get('cwe_id')}`")
                    st.code(sel_p.get("code_patch"), language="python")
                    with st.expander("View Root Cause, Guidance & Verification Steps"):
                        st.write(f"**Root Cause**: {sel_p.get('root_cause')}")
                        st.write(f"**Guidance**: {sel_p.get('guidance')}")
                        st.markdown("**Verification Steps:**")
                        for idx, step in enumerate(sel_p.get("verification_steps", []), 1):
                            st.write(f"{idx}. {step}")

                with st.expander("📁 Raw Remediation Plan Metadata", expanded=False):
                    st.json(rem_data)
            else:
                st.info("Remediation plans have not been generated for this session. Click 'Generate Remediation' above.")

    # -------------------------------------------------------------------------
    # 4. Retest & Proof-of-Fix
    # -------------------------------------------------------------------------
    retest_badge = f"✅ {len(retest_data)} Evaluated" if retest_data else "⚪ READY"
    with st.expander(f"🔄 **4. Retest & Proof-of-Fix** [{retest_badge}]", expanded=bool(rem_data)):
        col_rt_stat, col_rt_act = st.columns([3, 1], gap="medium")
        with col_rt_stat:
            is_sec = lab_mode == "secure"
            st.caption(f"Active Lab Mode: **{lab_mode.upper() if lab_mode else 'UNKNOWN'}** — {'🟢 Remediated (Fixes Active)' if is_sec else '🔴 Vulnerable (Defects Active)'}")
        with col_rt_act:
            run_retest_btn = st.button("🔄 Execute Proof-of-Fix Retest", type="primary", use_container_width=True, disabled=not bool(candidates), key="btn_run_retest")

        if run_retest_btn:
            with st.spinner("Executing post-remediation verification retest..."):
                retest_engine = RetestEngine(scope_controller=scope_ctrl)
                retests = retest_engine.retest_candidates(curr_target, candidates, remediations=rem_data, persist=True)
                st.session_state["retest_results"] = [r.to_dict() for r in retests]
                st.rerun()

        if retest_data:
            fixed_count = len([r for r in retest_data if r.get("status") == "FIXED_VERIFIED"])
            still_vuln_count = len([r for r in retest_data if r.get("status") == "STILL_VULNERABLE"])
            other_count = len(retest_data) - fixed_count - still_vuln_count

            t1, t2, t3 = st.columns(3)
            with t1:
                st.metric("Fixed Verified", fixed_count, delta=f"{fixed_count} resolved" if fixed_count else "None")
            with t2:
                st.metric("Still Vulnerable", still_vuln_count, delta=f"{still_vuln_count} persisting" if still_vuln_count else "0", delta_color="inverse")
            with t3:
                st.metric("Total Retested", len(retest_data))

            st.dataframe(
                [
                    {
                        "Finding ID": r.get("finding_id"),
                        "Status": r.get("status"),
                        "Target": r.get("target_url"),
                        "Proof of Fix Details": r.get("proof_of_fix_details")[:120] + "...",
                        "Tested At": r.get("tested_at"),
                    }
                    for r in retest_data
                ],
                use_container_width=True,
                hide_index=True,
            )

            with st.expander("📁 Raw Proof-of-Fix Records & Report Logs", expanded=False):
                st.json(retest_data)
        else:
            st.info("Proof-of-Fix retest has not been executed for this session. Click 'Execute Proof-of-Fix Retest' above.")


# =============================================================================
# TAB 2: 🔍 Finding Lifecycle Center
# =============================================================================
def render_tab2_lifecycle():
    """Renders the single-selector, unified end-to-end vulnerability lifecycle center."""
    st.markdown("### 🔍 **Finding Lifecycle Center**")

    det_data = st.session_state.get("detection_result")
    candidates = det_data.get("candidates", []) if det_data else []

    if not candidates:
        st.info("ℹ️ No finding candidates recorded in session yet. Run the Detection stage in Tab 1 or click '▶ Run Full End-to-End Pipeline' above.")
        return

    val_data = st.session_state.get("validation_result")
    val_outcomes = val_data.get("outcomes", []) if val_data else []
    risk_data = st.session_state.get("risk_results") or []
    rem_data = st.session_state.get("remediation_results") or []
    retest_data = st.session_state.get("retest_results") or []

    finding_ids = [c["id"] for c in candidates]
    selected_fid = st.selectbox(
        "Select Finding to inspect complete lifecycle:",
        options=finding_ids,
        format_func=lambda fid: f"{fid} — {next((c['title'] for c in candidates if c['id'] == fid), fid)}",
        key="lifecycle_finding_select",
    )

    candidate = next((c for c in candidates if c["id"] == selected_fid), {})
    outcome = next((o for o in val_outcomes if o.get("finding_id") == selected_fid), None)
    risk_item = next((r for r in risk_data if r.get("finding_id") == selected_fid), None)
    rem_plan = next((p for p in rem_data if p.get("finding_id") == selected_fid), None)
    retest_item = next((r for r in retest_data if r.get("finding_id") == selected_fid), None)

    is_vuln = candidate.get("is_vulnerable", False)
    det_status = candidate.get("detection_status", "UNKNOWN")
    val_status = outcome.get("validation_status") if outcome else "PENDING"
    retest_status = retest_item.get("status") if retest_item else "PENDING"

    # Compact Finding Title & Meta Banner
    st.markdown(
        f"""
        <div style="background:#FFFFFF; border:1px solid #CBD5E1; border-radius:8px; padding:0.85rem 1.1rem; margin-bottom:0.75rem;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h4 style="margin:0; color:#0F172A;">{candidate.get('title')}</h4>
                <div>
                    <span class="badge" style="background:#2563EB; color:white; padding:0.2rem 0.55rem; border-radius:4px; font-weight:600; font-size:0.8rem;">{candidate.get('cwe_id')}</span>
                    <span class="badge" style="background:{'#DC2626' if is_vuln else '#16A34A'}; color:white; padding:0.2rem 0.55rem; border-radius:4px; font-weight:600; font-size:0.8rem; margin-left:0.25rem;">{candidate.get('severity')}</span>
                </div>
            </div>
            <div style="margin-top:0.35rem; font-size:0.85rem; color:#475569;">
                <code>{candidate.get('http_method')} {candidate.get('endpoint')}</code> | Parameter: <code>{candidate.get('affected_parameter') or 'Path / Object'}</code>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 1. Horizontal 5-Stage Status Summary
    col_s1, col_s2, col_s3, col_s4, col_s5 = st.columns(5)
    with col_s1:
        st.metric("1. Detection", det_status)
    with col_s2:
        st.metric("2. Validation", val_status)
    with col_s3:
        st.metric("3. Risk Score", f"{risk_item.get('risk_score', '—')}/10.0" if risk_item else "PENDING")
    with col_s4:
        st.metric("4. Remediation", rem_plan.get("remediation_priority", "PENDING") if rem_plan else "PENDING")
    with col_s5:
        st.metric("5. Proof-of-Fix", retest_status)

    st.markdown("<div style='margin-bottom:0.6rem;'></div>", unsafe_allow_html=True)

    # 2. Compact Parallel Columns for Stages 1-4
    col_left, col_right = st.columns([1, 1], gap="medium")

    with col_left:
        # Stage 1: Detection Signal
        det_badge_class = "badge-rejected" if (is_vuln or "VULNERABLE" in det_status) else "badge-allowed"
        st.markdown(
            f"""
            <div class="lifecycle-stage-card" style="border-left: 4px solid {'#DC2626' if is_vuln else '#16A34A'};">
                <div class="lifecycle-stage-header">
                    <span style="font-weight:700; font-size:0.98rem; color:#0F172A;">📡 Stage 1: Detection Signal</span>
                    <span class="{det_badge_class}">{det_status}</span>
                </div>
                <p style="margin:0; font-size:0.86rem; color:#334155;"><strong>Behavior:</strong> {candidate.get('observed_behavior')}</p>
                <p style="margin:0.25rem 0 0 0; font-size:0.86rem; color:#991B1B;"><strong>Impact:</strong> {candidate.get('potential_impact')}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        with st.expander("🔍 Raw Detection Evidence & Payloads", expanded=False):
            st.json(candidate.get("evidence", {}))

        # Stage 2: Deterministic Validation
        if outcome:
            is_conf = outcome.get("is_confirmed", False)
            st.markdown(
                f"""
                <div class="lifecycle-stage-card" style="border-left: 4px solid {'#DC2626' if is_conf else '#16A34A'};">
                    <div class="lifecycle-stage-header">
                        <span style="font-weight:700; font-size:0.98rem; color:#0F172A;">🔬 Stage 2: Deterministic Validation</span>
                        <span class="{'badge-rejected' if is_conf else 'badge-allowed'}">{outcome.get('validation_status')} ({int(outcome.get('confidence_score', 0.0) * 100)}%)</span>
                    </div>
                    <p style="margin:0; font-size:0.86rem; color:#334155;"><strong>Method:</strong> <code>{outcome.get('validation_method')}</code></p>
                    <p style="margin:0.25rem 0 0 0; font-size:0.86rem; color:#334155;"><strong>Details:</strong> {outcome.get('details')}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if outcome.get("proof_of_concept_safe"):
                st.markdown("**Safe Verification Proof-of-Concept:**")
                st.code(outcome.get("proof_of_concept_safe"), language="http")
            if outcome.get("differential_observed"):
                st.info(f"**Differential Observed:** {outcome.get('differential_observed')}")
            with st.expander("🔬 Raw Validation Details & Artifact", expanded=False):
                st.json(outcome)
        else:
            st.info("Stage 2: Validation has not been executed yet for this finding.")

    with col_right:
        # Stage 3: Contextual Risk Assessment
        if risk_item:
            factors = risk_item.get("factors", {})
            st.markdown(
                f"""
                <div class="lifecycle-stage-card">
                    <div class="lifecycle-stage-header">
                        <span style="font-weight:700; font-size:0.98rem; color:#0F172A;">📊 Stage 3: Contextual Risk</span>
                        <span style="font-weight:700; font-size:1.0rem; color:{'#DC2626' if risk_item.get('risk_score', 0) >= 8.5 else '#D97706'};">
                            Score: {risk_item.get('risk_score')}/10.0 ({risk_item.get('severity')} - {risk_item.get('remediation_priority')})
                        </span>
                    </div>
                    <p style="margin:0; font-size:0.86rem; color:#334155;"><strong>Summary:</strong> {risk_item.get('summary')}</p>
                    <p style="margin:0.25rem 0 0 0; font-size:0.82rem; color:#64748B;">
                        Exploitability: {risk_item.get('exploitability')}/10.0 | Impact: {risk_item.get('impact')}/10.0 | Urgency: {risk_item.get('remediation_urgency')}
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.expander("📊 Raw Risk Factors & Formula Trace", expanded=False):
                st.json(factors)
        else:
            st.info("Stage 3: Contextual risk scoring has not been computed yet for this finding.")

        # Stage 4: Contextual Remediation
        if rem_plan:
            st.markdown(
                f"""
                <div class="lifecycle-stage-card">
                    <div class="lifecycle-stage-header">
                        <span style="font-weight:700; font-size:0.98rem; color:#0F172A;">🛠️ Stage 4: Contextual Remediation</span>
                        <span class="badge" style="background:#2563EB; color:white; padding:0.2rem 0.5rem; border-radius:4px; font-weight:600;">{rem_plan.get('cwe_id')}</span>
                    </div>
                    <h5 style="margin:0 0 0.25rem 0; color:#1E40AF;">{rem_plan.get('title')}</h5>
                    <p style="margin:0 0 0.25rem 0; font-size:0.86rem; color:#334155;"><strong>Root Cause:</strong> {rem_plan.get('root_cause')}</p>
                    <p style="margin:0; font-size:0.86rem; color:#334155;"><strong>Guidance:</strong> {rem_plan.get('guidance')}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown("**Tailored Code Patch Diff:**")
            st.code(rem_plan.get("code_patch"), language="python")

            st.markdown("**Verification Checklist:**")
            for idx, step in enumerate(rem_plan.get("verification_steps", []), 1):
                st.write(f"**Step {idx}:** {step}")

            with st.expander("🛠️ Raw Remediation Plan Metadata", expanded=False):
                st.json(rem_plan)
        else:
            st.info("Stage 4: Remediation guidance has not been generated yet for this finding.")

    # 3. Stage 5: Proof-of-Fix Retest Card (Full Width at bottom)
    with st.container():
        if retest_item:
            is_fixed = retest_item.get("status") == "FIXED_VERIFIED"
            st.markdown(
                f"""
                <div class="lifecycle-stage-card" style="border: 2px solid {'#16A34A' if is_fixed else '#DC2626'}; background: {'#F0FDF4' if is_fixed else '#FEF2F2'};">
                    <div class="lifecycle-stage-header">
                        <span style="font-weight:700; font-size:1.05rem; color:{'#166534' if is_fixed else '#991B1B'};">🔄 Stage 5: Proof-of-Fix Retest Verification</span>
                        <span class="{'badge-allowed' if is_fixed else 'badge-rejected'}">{retest_item.get('status')}</span>
                    </div>
                    <p style="margin:0; font-size:0.92rem; color:#1E293B;"><strong>Verification Result:</strong> {retest_item.get('proof_of_fix_details')}</p>
                    <p style="margin:0.35rem 0 0 0; font-size:0.8rem; color:#64748B;">Tested At: {retest_item.get('tested_at')}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if retest_item.get("verification_steps_checked"):
                st.markdown("**Evaluated Verification Checks:**")
                for s in retest_item.get("verification_steps_checked", []):
                    st.write(f"• {s}")
            with st.expander("🔄 Raw Proof-of-Fix Retest Trace", expanded=False):
                st.json(retest_item)
        else:
            st.info("Stage 5: Proof-of-Fix retest has not been executed yet for this finding.")


# =============================================================================
# TAB 3: 🔒 Scope Governance & Audit
# =============================================================================
def render_tab3_governance(curr_target: str):
    """Renders Target Scope Management, Live Scope Evaluator, Scope Audit Log, and Pipeline Architecture."""
    st.markdown("### 🔒 **Scope Governance, Target Management & Audit Trail**")

    # 1. Target Management
    st.markdown("#### **1. Authorized Target Management**")
    col_t_stat, col_t_add = st.columns([1, 1], gap="large")

    with col_t_stat:
        status = scope_ctrl.get_target_status(curr_target)
        if curr_target and status.get("is_authorized"):
            st.markdown(
                f"""
                <div class="target-card-active">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-weight:700; font-size:1.15rem; color:#166534;">{curr_target}</span>
                        <span class="badge-allowed">AUTHORIZED LOCAL TARGET</span>
                    </div>
                    <p style="margin:0.5rem 0 0 0; color:#14532D; font-size:0.9rem;">
                        <strong>Host:</strong> <code>{status.get('host')}</code> | 
                        <strong>Port:</strong> <code>{status.get('port')}</code> | 
                        <strong>Loopback Verified:</strong> ✅
                    </p>
                    <p style="margin:0.2rem 0 0 0; color:#15803D; font-size:0.8rem;">
                        Policy: {status.get('reason')}
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """
                <div class="target-card-empty">
                    <span style="font-weight:700; color:#B45309;">No Authorized Target Selected</span>
                    <p style="margin:0.4rem 0 0 0; color:#78350F; font-size:0.85rem;">
                        Select or configure an authorized local target below to enable testing operations.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        auth_targets = scope_ctrl.get_authorized_targets()
        curr_idx = auth_targets.index(curr_target) if curr_target in auth_targets else 0
        selected_option = st.selectbox(
            "Select Target from Authorized List",
            options=auth_targets,
            index=curr_idx if auth_targets else 0,
            key="governance_target_select",
        )

        col_sel_btn, col_del_btn = st.columns([2, 1])
        with col_sel_btn:
            if st.button("📌 Set as Active Target", use_container_width=True, type="primary", key="btn_set_target"):
                result = scope_ctrl.set_selected_target(selected_option)
                if result.is_allowed:
                    st.session_state.selected_target = result.target_url
                    st.success(f"Active target updated to: `{result.target_url}`")
                    st.rerun()
                else:
                    st.error(f"Failed to set target: {result.reason}")
        with col_del_btn:
            if st.button("🗑️ Remove Target", use_container_width=True, key="btn_remove_target"):
                if selected_option:
                    scope_ctrl.remove_explicit_target(selected_option)
                    if st.session_state.get("selected_target") == selected_option:
                        st.session_state.selected_target = None
                    st.warning(f"Removed target `{selected_option}`.")
                    st.rerun()

    with col_t_add:
        st.markdown("##### **Authorize New Local Target**")
        st.caption("Add a new local development URL. Non-local and public addresses will be automatically rejected.")
        with st.form("add_target_form_tab3"):
            new_target_url = st.text_input(
                "Local Target URL",
                placeholder="http://localhost:8080 or http://127.0.0.1:3000",
                help="Must be a local loopback URL on an authorized port.",
            )
            submit_add = st.form_submit_button("➕ Authorize Target", use_container_width=True)
            if submit_add:
                if not new_target_url:
                    st.error("Please provide a target URL.")
                else:
                    add_result = scope_ctrl.add_explicit_target(new_target_url)
                    if add_result.is_allowed:
                        st.session_state.selected_target = add_result.target_url
                        st.success(f"✅ Target authorized: `{add_result.target_url}`")
                        st.rerun()
                    else:
                        st.error(f"🛑 Authorization Failed: {add_result.reason}")

    # 2. Live Scope Evaluator
    st.markdown("---")
    st.markdown("#### **2. Live Target Scope Evaluator**")
    st.caption("Test how the Scope Controller evaluates different targets in real time.")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("Test Local 5000", use_container_width=True, key="btn_test_5000"):
            st.session_state["eval_url"] = "http://localhost:5000"
    with col2:
        if st.button("Test Local 8080", use_container_width=True, key="btn_test_8080"):
            st.session_state["eval_url"] = "http://127.0.0.1:8080"
    with col3:
        if st.button("Test Remote (example.com)", use_container_width=True, key="btn_test_remote"):
            st.session_state["eval_url"] = "https://example.com"
    with col4:
        if st.button("Test Cloud Metadata", use_container_width=True, key="btn_test_metadata"):
            st.session_state["eval_url"] = "http://169.254.169.254"

    eval_input = st.text_input(
        "Evaluate Target URL",
        value=st.session_state.get("eval_url", "http://localhost:5000"),
        key="eval_input_box",
    )

    if st.button("Evaluate Scope Boundary", type="secondary", key="btn_eval_scope"):
        res = scope_ctrl.validate_target(eval_input, record_audit=True, operation="LIVE_SCOPE_TEST")
        if res.is_allowed:
            st.success(f"✅ **SCOPE ALLOWED**: `{res.target_url}`")
        else:
            st.error(f"🛑 **SCOPE REJECTED**: `{res.target_url}` (Reason: {res.reason})")

        with st.expander("View Complete Scope Decision JSON", expanded=False):
            st.json({
                "decision": "ALLOWED" if res.is_allowed else "REJECTED",
                "target": res.target_url,
                "host": res.normalized_host,
                "port": res.port,
                "is_loopback": res.is_loopback,
                "reason": res.reason,
            })

    # 3. Scope Decisions Audit Log
    st.markdown("---")
    st.markdown("#### **3. Scope Decisions Audit Log**")
    st.caption("All target evaluations and security operations are persistently recorded.")

    logs = scope_ctrl.get_audit_logs(limit=40)
    col_filter, col_refresh = st.columns([3, 1])
    with col_filter:
        decision_filter = st.selectbox("Filter Decisions", options=["ALL", "ALLOWED", "REJECTED"], index=0, key="log_decision_filter")
    with col_refresh:
        st.write("")
        if st.button("🔄 Refresh Logs", use_container_width=True, key="btn_refresh_logs"):
            st.rerun()

    filtered_logs = logs if decision_filter == "ALL" else [l for l in logs if l.get("decision") == decision_filter]

    with st.expander(f"📜 View Scope Audit Log Entries ({len(filtered_logs)} records)", expanded=False):
        if filtered_logs:
            for entry in filtered_logs[:12]:
                decision = entry.get("decision", "UNKNOWN")
                is_allowed = decision == "ALLOWED"
                badge_html = '<span class="badge-allowed">ALLOWED</span>' if is_allowed else '<span class="badge-rejected">REJECTED</span>'
                st.markdown(
                    f"""
                    <div style="border: 1px solid #E2E8F0; border-radius: 6px; padding: 0.65rem 0.9rem; margin-bottom: 0.4rem; background: {'#F0FDF4' if is_allowed else '#FEF2F2'};">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-weight:600; font-size:0.9rem; color:#1E293B;">Target: <code>{entry.get('target')}</code></span>
                            <div>
                                <span style="font-size:0.75rem; color:#64748B; margin-right:0.6rem;">{entry.get('timestamp')}</span>
                                {badge_html}
                            </div>
                        </div>
                        <div style="margin-top:0.25rem; font-size:0.8rem; color:#475569;">
                            <strong>Operation:</strong> <code>{entry.get('operation')}</code> | 
                            <strong>Reason:</strong> {entry.get('reason')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("No audit logs matching criteria.")

    # 4. Pipeline Architecture
    st.markdown("---")
    st.markdown("#### **4. Pipeline Security Enforcement Architecture**")
    st.caption("Every operation passes through the Scope Controller gatekeeper prior to network execution:")
    st.code(
        """
        [ Pipeline Operation Request ]
                      │
                      ▼
        [ ScopeController.authorize_operation() ] ───▶ [ Audit Log (SQLite + JSON) ]
                      │
                      ├─▶ REJECTED: Immediate Abort (Out of Scope / Non-Local)
                      │
                      └─▶ ALLOWED (localhost / 127.0.0.1 only)
                              │
                              ▼
        [ Discovery ➔ Detection ➔ Safe Validation ➔ Risk ➔ Remediation ➔ Proof-of-Fix Retest ]
        """,
        language="text",
    )


# =============================================================================
# Main Application Entry Point
# =============================================================================
def main():
    """Main Streamlit dashboard orchestrator with the clean 3-tab layout."""
    curr_target = st.session_state.get("selected_target", "http://127.0.0.1:5000")
    lab_mode = get_current_lab_mode(curr_target)

    # 1. Sidebar
    render_sidebar()

    # 2. Top Header
    render_header(curr_target, lab_mode)

    st.markdown("---")

    # 3. Main 3-Tab Architecture
    tab1, tab2, tab3 = st.tabs([
        "🚀 End-to-End Pipeline",
        "🔍 Finding Lifecycle Center",
        "🔒 Scope Governance & Audit",
    ])

    with tab1:
        render_tab1_pipeline(curr_target, lab_mode)

    with tab2:
        render_tab2_lifecycle()

    with tab3:
        render_tab3_governance(curr_target)


if __name__ == "__main__":
    main()
