#!/usr/bin/env python3
"""
SecureGuard AI — Streamlit UI

Interactive web interface for the SecureGuard AI vulnerability detection
and code remediation pipeline.

Usage:
    streamlit run ui_app.py
"""

import streamlit as st
import tempfile
import os
import sys
import io
import subprocess
import json
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so we can import backend modules
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SecureGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* Header styling */
    .main-header {
        background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
        padding: 1.5rem 2rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        color: white;
        text-align: center;
    }
    .main-header h1 { margin: 0; font-size: 2rem; }
    .main-header p  { margin: 0.3rem 0 0 0; opacity: 0.85; font-size: 0.95rem; }

    /* Metric cards */
    .metric-card {
        background: #f8f9fa;
        border-left: 4px solid #2c5364;
        border-radius: 6px;
        padding: 0.8rem 1rem;
        margin-bottom: 0.5rem;
    }
    .metric-card .label { font-size: 0.8rem; color: #666; }
    .metric-card .value { font-size: 1.4rem; font-weight: 700; color: #1a1a2e; }

    /* Status badges */
    .badge-verified   { background: #28a745; color: #fff; padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; }
    .badge-unverified { background: #ffc107; color: #333; padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; }
    .badge-error      { background: #dc3545; color: #fff; padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; }

    /* Diff container */
    div[data-testid="stCode"] pre { max-height: 500px; overflow-y: auto; }

    /* Sidebar tweaks */
    [data-testid="stSidebar"] { min-width: 320px; }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def load_env_defaults() -> dict:
    """Read defaults from .env (already loaded into os.environ)."""
    return {
        "llm_provider": os.getenv("LLM_PROVIDER", "anthropic"),
        "llm_model": os.getenv("LLM_MODEL", "claude-sonnet-4-20250514"),
        "max_retries": int(os.getenv("MAX_RETRIES", "3")),
        "review_mode": os.getenv("REVIEW_MODE", "automatic"),
        "fp_threshold": float(os.getenv("FP_CONFIDENCE_THRESHOLD", "0.75")),
        "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "2048")),
        "output_dir": os.getenv("OUTPUT_DIR", "output"),
    }


def apply_patch(patch_path: str, repo_path: str) -> tuple[bool, str]:
    """
    Apply a patch file to a repository using git apply.

    Returns (success: bool, message: str).
    """
    try:
        result = subprocess.run(
            ["git", "apply", "--stat", patch_path],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        stat_output = result.stdout

        result = subprocess.run(
            ["git", "apply", patch_path],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return True, f"Patch applied successfully.\n{stat_output}"
        else:
            return False, f"git apply failed:\n{result.stderr}"
    except FileNotFoundError:
        return False, "git is not installed or not on PATH."
    except subprocess.TimeoutExpired:
        return False, "git apply timed out."
    except Exception as exc:
        return False, f"Unexpected error: {exc}"


def execute_pipeline(scan_path: str, repo_path: str, cfg: dict) -> tuple[dict, str]:
    """
    Run the backend pipeline, capturing all stdout/stderr as logs.

    Returns (results_dict, captured_logs).
    """
    # Temporarily override env vars with UI-selected config
    env_overrides = {
        "LLM_PROVIDER": cfg["llm_provider"],
        "LLM_MODEL": cfg["llm_model"],
        "MAX_RETRIES": str(cfg["max_retries"]),
        "LLM_MAX_TOKENS": str(cfg["max_tokens"]),
        "FP_CONFIDENCE_THRESHOLD": str(cfg["fp_threshold"]),
    }
    old_env = {}
    for k, v in env_overrides.items():
        old_env[k] = os.environ.get(k)
        os.environ[k] = v

    log_buffer = io.StringIO()
    try:
        from main import run_pipeline

        with redirect_stdout(log_buffer), redirect_stderr(log_buffer):
            results = run_pipeline(
                scan_path=scan_path,
                repo_path=repo_path,
                output_dir=cfg.get("output_dir", "output"),
                mode=cfg["review_mode"],
                max_retries=cfg["max_retries"],
                verbose=True,
            )
        return results, log_buffer.getvalue()

    except Exception as exc:
        import traceback
        log_buffer.write(f"\n\n--- PIPELINE ERROR ---\n{traceback.format_exc()}")
        return {
            "total_vulnerabilities": 0,
            "errors": [str(exc)],
            "vulnerabilities": [],
            "patches_generated": 0,
            "fixes_verified": 0,
            "fixes_attempted": 0,
            "fixes_unverified": 0,
            "fixes_approved": 0,
            "fixes_rejected": 0,
            "false_positives": 0,
            "reports_generated": 0,
        }, log_buffer.getvalue()

    finally:
        # Restore original env
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ═══════════════════════════════════════════════════════════════════════════
# SESSION STATE DEFAULTS
# ═══════════════════════════════════════════════════════════════════════════
for key, default in {
    "pipeline_results": None,
    "pipeline_logs": "",
    "pipeline_ran": False,
    "approval_decisions": {},
    "applied_patches": set(),
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ═══════════════════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════════════════
st.markdown(
    '<div class="main-header">'
    "<h1>🛡️ SecureGuard AI</h1>"
    "<p>AI Security Vulnerability Detection &amp; Code Remediation</p>"
    "</div>",
    unsafe_allow_html=True,
)

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — SIDEBAR: INPUTS & CONFIG
# ═══════════════════════════════════════════════════════════════════════════
defaults = load_env_defaults()

with st.sidebar:
    st.header("📂 Input")

    uploaded_file = st.file_uploader(
        "Upload Scan Report",
        type=["json"],
        help="JSON vulnerability scan report (Bandit, Semgrep, custom, …)",
    )

    repo_path_input = st.text_input(
        "Repository Path",
        value=".",
        help="Absolute or relative path to the target repository",
    )

    # ---- Collapsible config panel ----
    with st.expander("⚙️ Configuration", expanded=False):
        llm_provider = st.selectbox(
            "LLM Provider",
            options=["anthropic", "openai"],
            index=0 if defaults["llm_provider"] == "anthropic" else 1,
        )

        default_models = {
            "anthropic": "claude-sonnet-4-20250514",
            "openai": "gpt-4o",
        }
        llm_model = st.text_input(
            "Model",
            value=defaults["llm_model"] or default_models.get(llm_provider, ""),
        )

        max_tokens = st.slider(
            "Max Tokens (LLM response)",
            min_value=512,
            max_value=4096,
            value=defaults["max_tokens"],
            step=256,
            help="Higher = better fixes but more expensive",
        )

        max_retries = st.slider(
            "Max Retries",
            min_value=1,
            max_value=5,
            value=defaults["max_retries"],
        )

        review_mode = st.selectbox(
            "Review Mode",
            options=["automatic", "interactive"],
            index=0 if defaults["review_mode"] == "automatic" else 1,
            help="'interactive' lets you approve/reject each fix in the UI",
        )

        fp_threshold = st.slider(
            "FP Confidence Threshold",
            min_value=0.0,
            max_value=1.0,
            value=defaults["fp_threshold"],
            step=0.05,
        )

    st.divider()

    # ---- RUN BUTTON ----
    run_clicked = st.button(
        "🚀 Run SecureGuard",
        type="primary",
        use_container_width=True,
        disabled=uploaded_file is None,
    )

    if uploaded_file is None:
        st.caption("⬆️ Upload a scan report to enable the pipeline.")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — EXECUTE PIPELINE
# ═══════════════════════════════════════════════════════════════════════════
if run_clicked and uploaded_file is not None:
    # Validate repo path
    repo_abs = Path(repo_path_input).resolve()
    if not repo_abs.exists():
        st.error(f"Repository path does not exist: `{repo_abs}`")
        st.stop()

    # Save uploaded file to a temp location
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=".json", prefix="secureguard_scan_"
    ) as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_scan_path = tmp.name

    cfg = {
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "max_tokens": max_tokens,
        "max_retries": max_retries,
        "review_mode": "automatic",  # Always auto in backend; UI handles interactive
        "fp_threshold": fp_threshold,
        "output_dir": str(PROJECT_ROOT / defaults["output_dir"]),
    }

    # Reset previous state
    st.session_state.pipeline_results = None
    st.session_state.pipeline_logs = ""
    st.session_state.pipeline_ran = False
    st.session_state.approval_decisions = {}
    st.session_state.applied_patches = set()
    st.session_state.review_mode = review_mode  # Save the user's choice

    with st.spinner("Running SecureGuard AI pipeline…"):
        results, logs = execute_pipeline(tmp_scan_path, str(repo_abs), cfg)

    # Store repo path for later patch application
    results["_repo_path"] = str(repo_abs)

    st.session_state.pipeline_results = results
    st.session_state.pipeline_logs = logs
    st.session_state.pipeline_ran = True

    # Cleanup temp file
    try:
        os.unlink(tmp_scan_path)
    except OSError:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# SECTIONS 3-6 — DISPLAY RESULTS  (only when pipeline has been run)
# ═══════════════════════════════════════════════════════════════════════════
if not st.session_state.pipeline_ran:
    st.info("Upload a scan report and click **Run SecureGuard** to get started.")
    st.stop()

results = st.session_state.pipeline_results
logs = st.session_state.pipeline_logs
user_review_mode = st.session_state.get("review_mode", "automatic")

# ── Quick error banner ────────────────────────────────────────────────────
if results.get("errors"):
    for err in results["errors"]:
        st.error(f"Pipeline error: {err}")

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — EXECUTION LOGS
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("---")
st.subheader("📜 Execution Logs")

with st.expander("View full logs", expanded=False):
    st.code(logs if logs else "(no logs captured)", language="text")

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — RESULTS SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("---")
st.subheader("📊 Results")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Vulns", results.get("total_vulnerabilities", 0))
col2.metric("False Positives", results.get("false_positives", 0))
col3.metric("Fixes Attempted", results.get("fixes_attempted", 0))
col4.metric("Verified", results.get("fixes_verified", 0))
col5.metric("Patches", results.get("patches_generated", 0))

duration = results.get("duration_seconds", 0)
if duration:
    dur_str = f"{int(duration // 60)}m {int(duration % 60)}s" if duration >= 60 else f"{duration:.1f}s"
    st.caption(f"⏱️ Duration: {dur_str}")

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 & 6 — DIFF VIEW + APPROVAL  (per vulnerability)
# ═══════════════════════════════════════════════════════════════════════════
vulns = results.get("vulnerabilities", [])
patched_vulns = [v for v in vulns if v.get("patch_file_path")]

if not patched_vulns:
    st.info("No patches were generated in this run.")
    st.stop()

st.markdown("---")
st.subheader("🔍 Patch Review")

for idx, vuln in enumerate(patched_vulns):
    vuln_id = f"vuln_{idx}"
    vuln_type = vuln.get("vuln_type", "unknown")
    file_path = vuln.get("file_path", "unknown")
    line_num = vuln.get("line_number", "?")
    status = vuln.get("status", "UNKNOWN")
    patch_path = vuln.get("patch_file_path", "")
    attempts = vuln.get("attempts", vuln.get("total_attempts", "?"))

    # ---- Card header ----
    badge_cls = (
        "badge-verified" if status == "VERIFIED"
        else "badge-error" if status in ("SYNTAX_ERROR", "ERROR", "AGENT_ERROR")
        else "badge-unverified"
    )
    st.markdown(
        f"### {idx + 1}. `{vuln_type}` — `{file_path}:{line_num}` "
        f'<span class="{badge_cls}">{status}</span>',
        unsafe_allow_html=True,
    )

    # Summary table
    info_cols = st.columns(4)
    info_cols[0].markdown(f"**Severity:** {vuln.get('severity', 'N/A')}")
    info_cols[1].markdown(f"**Attempts:** {attempts}")
    info_cols[2].markdown(f"**Status:** {status}")
    info_cols[3].markdown(f"**Patch:** `{vuln.get('patch_filename', 'N/A')}`")

    # ---- Diff view ----
    diff_text = ""
    if patch_path and Path(patch_path).exists():
        diff_text = Path(patch_path).read_text(encoding="utf-8", errors="replace")

    if diff_text:
        with st.expander("View Patch Diff", expanded=True):
            st.code(diff_text, language="diff")
    else:
        st.warning("Patch file not found.")

    # ---- Report view ----
    report_path = vuln.get("report_file_path", "")
    if report_path and Path(report_path).exists():
        with st.expander("View Report"):
            st.markdown(Path(report_path).read_text(encoding="utf-8", errors="replace"))

    # ---- Approval buttons (only in interactive mode) ----
    if user_review_mode == "interactive":
        already_applied = vuln_id in st.session_state.applied_patches
        already_decided = vuln_id in st.session_state.approval_decisions

        if already_applied:
            st.success("✅ Patch has been applied to the repository.")
        elif already_decided:
            decision = st.session_state.approval_decisions[vuln_id]
            if decision == "approved":
                st.info("Approved — click **Apply** below to apply the patch.")
            else:
                st.warning("Rejected — patch will not be applied.")
        else:
            btn_cols = st.columns([1, 1, 4])
            if btn_cols[0].button("✅ Approve", key=f"approve_{vuln_id}"):
                st.session_state.approval_decisions[vuln_id] = "approved"
                st.rerun()
            if btn_cols[1].button("❌ Reject", key=f"reject_{vuln_id}"):
                st.session_state.approval_decisions[vuln_id] = "rejected"
                st.rerun()

        # Apply button (shown after approval)
        if (
            st.session_state.approval_decisions.get(vuln_id) == "approved"
            and vuln_id not in st.session_state.applied_patches
            and patch_path
        ):
            repo = results.get("_repo_path", ".")
            if st.button("🔧 Apply Patch to Repo", key=f"apply_{vuln_id}"):
                ok, msg = apply_patch(patch_path, repo)
                if ok:
                    st.session_state.applied_patches.add(vuln_id)
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)
    else:
        # Automatic mode — just inform
        st.caption("Mode: **automatic** — patches were auto-approved by the pipeline.")

    st.markdown("---")
