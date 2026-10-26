import os
import json
import streamlit as st
from dotenv import load_dotenv

from scanner import scan_github_repository
from gemma_client import explain_findings

load_dotenv()

st.set_page_config(
    page_title="RepoRescue AI",
    page_icon="🛟",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container {padding-top: 2rem; padding-bottom: 3rem; max-width: 1200px;}
    .hero {padding: 1.5rem 1.7rem; border-radius: 18px; background: linear-gradient(120deg,#eef5ff,#f3f0ff); border: 1px solid #dbe6f7;}
    .hero h1 {color: #1e293b !important; margin: 0;}
    .hero p {color: #334155 !important;}
    .muted {color: #64748b;}
    div[data-testid="stMetric"] {
        border: 1px solid rgba(128,128,128,0.25);
        padding: 14px;
        border-radius: 14px;
        background: rgba(128,128,128,0.08);
    }
    div[data-testid="stMetricValue"] > div {color: inherit !important;}
    div[data-testid="stMetricLabel"] > div {color: inherit !important;}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("🛟 RepoRescue AI")
    st.caption("AI-assisted repository triage")
    st.divider()
    st.markdown("**What it does**")
    st.write("1. Reads a public GitHub repository")
    st.write("2. Runs lightweight static checks")
    st.write("3. Uses Gemma to explain selected findings")
    st.divider()
    st.caption("Safety: repository code is inspected as text, never executed.")
    st.caption("AI findings are suggestions, not proof of a vulnerability.")

st.markdown("""
<div class="hero">
  <h1>RepoRescue AI</h1>
  <p style="font-size:1.08rem;margin:.55rem 0 0 0">
  Find suspicious code patterns, understand why they matter, and get actionable next steps.
  </p>
</div>
""", unsafe_allow_html=True)

st.write("")
default_repo = "https://github.com/psf/requests"
repo_url = st.text_input(
    "Public GitHub repository URL",
    value=default_repo,
    placeholder="https://github.com/owner/repository",
    help="Public repositories only. For a fast demo, try psf/requests or your own small public repository.",
)

col_a, col_b = st.columns([1, 3])
with col_a:
    run_scan = st.button("🔍 Scan repository", type="primary", use_container_width=True)
with col_b:
    st.caption("The quick scan checks ALL source files and common risky patterns.")

if run_scan:
    with st.spinner("Fetching repository files and checking code patterns..."):
        try:
            result = scan_github_repository(repo_url)
            st.session_state["repo_scan_result"] = result
            st.session_state["repo_scan_url"] = repo_url.strip()
            st.session_state.pop("gemma_explanation", None)
        except Exception as exc:
            err = str(exc)
            if "getaddrinfo failed" in err or "NameResolutionError" in err or "Max retries exceeded" in err:
                st.error("❌ Cannot reach GitHub API — DNS resolution failed. Check your internet connection and try again.")
            elif "rate limit" in err.lower() or "403" in err:
                st.error("⚠️ GitHub API rate limit hit. Add GITHUB_TOKEN to .env for 5000 req/hr (vs 60 without token).")
            elif "404" in err:
                st.error("❌ Repository not found. Make sure the URL is correct and the repo is public.")
            else:
                st.error(f"❌ Scan failed: {exc}")

result = st.session_state.get("repo_scan_result")
if result:
    st.divider()
    st.subheader(f"Scan report: {result['full_name']}")

    total_files   = result.get("total_files", result["files_scanned"])
    files_scanned = result["files_scanned"]
    skipped_ext   = result.get("skipped_ext", [])
    skipped_size  = result.get("skipped_size", [])
    scanned_list  = result.get("scanned_list", [])
    truncated     = result.get("tree_truncated", False)

    st.caption(
        f"Branch: **{result['branch']}** · "
        f"Total files in repo: **{total_files}** · "
        f"Scanned: **{files_scanned}** · "
        f"Skipped (unsupported ext): **{len(skipped_ext)}** · "
        f"Skipped (too large): **{len(skipped_size)}**"
    )

    if truncated:
        st.warning("⚠️ GitHub returned a truncated tree — very large repo. Not all files are visible.")

    findings = result["findings"]
    critical = sum(1 for f in findings if f["severity"] == "High")
    medium   = sum(1 for f in findings if f["severity"] == "Medium")
    low      = sum(1 for f in findings if f["severity"] == "Low")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("📁 Total Files", total_files)
    m2.metric("✅ Scanned", files_scanned)
    m3.metric("🔍 Findings", len(findings))
    m4.metric("🔴 High", critical)
    m5.metric("🟡 Med / Low", medium + low)

    # File breakdown expander
    with st.expander(f"📂 File details — {total_files} files found in repo", expanded=False):
        if scanned_list:
            st.markdown("**✅ Files scanned:**")
            for f in scanned_list:
                st.code(f, language=None)
        if skipped_ext:
            st.markdown(f"**⏭️ Skipped (unsupported extension — {len(skipped_ext)} files):**")
            for f in skipped_ext:
                st.code(f, language=None)
        if skipped_size:
            st.markdown(f"**📦 Skipped (file too large — {len(skipped_size)} files):**")
            for f in skipped_size:
                st.code(f, language=None)
        if not scanned_list and not skipped_ext and not skipped_size:
            st.info("No files were found in the repository tree.")

    st.info("A pattern match is a lead for review, not confirmation that the code is exploitable or incorrect.")
    if not findings:
        st.success("No supported patterns were detected in the scanned files. This does not mean the repository is bug-free.")

    for idx, finding in enumerate(findings, start=1):
        sev_icon = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(finding["severity"], "⚪")
        title = f"{sev_icon} {finding['severity']} · {finding['rule']} · {finding['path']}:{finding['line']}"
        with st.expander(title, expanded=(idx <= 3)):
            st.write(finding["description"])
            lang = "python" if finding["path"].endswith(".py") else None
            st.code(finding["evidence"], language=lang)
            st.caption(f"Rule ID: {finding['rule_id']}")

    st.divider()
    st.subheader("Gemma analysis")
    api_key_present = bool(os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY"))
    if not api_key_present:
        st.warning("No Google AI Studio API key detected. Add GOOGLE_API_KEY to .env and restart the app.")
    
    explain_disabled = not findings or not api_key_present
    if st.button("✨ Explain findings with Gemma", disabled=explain_disabled):
        with st.spinner("Asking Gemma to explain the selected findings..."):
            try:
                st.session_state["gemma_explanation"] = explain_findings(
                    full_name=result["full_name"],
                    findings=findings[:12],
                )
            except Exception as exc:
                st.error(f"❌ Gemma request failed: {exc}")

    if st.session_state.get("gemma_explanation"):
        st.markdown(st.session_state["gemma_explanation"])

    report = {
        "repository":   result["full_name"],
        "branch":       result["branch"],
        "total_files":  total_files,
        "files_scanned": files_scanned,
        "scanned_list": scanned_list,
        "skipped_ext":  skipped_ext,
        "skipped_size": skipped_size,
        "findings":     findings,
    }
    st.download_button(
        "⬇️ Download scan report (JSON)",
        data=json.dumps(report, indent=2),
        file_name="reporescue-report.json",
        mime="application/json",
    )

st.divider()
st.caption("RepoRescue AI · Hackathon MVP · Public repositories only · No repository code execution")
