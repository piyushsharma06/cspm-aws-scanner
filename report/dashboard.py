"""
dashboard.py
Streamlit dashboard that renders a Mini-CSPM report.json as a browsable
risk report — the "Report" step from the architecture diagram.

Run with:
    streamlit run report/dashboard.py
"""

import json
import os
import sys

import streamlit as st

st.set_page_config(page_title="Mini-CSPM Dashboard", page_icon="🛡️", layout="wide")

SEVERITY_COLOR = {
    "Critical": "#e02424",
    "High": "#f05252",
    "Medium": "#f59e0b",
    "Low": "#3b82f6",
    "Info": "#10b981",
    "N/A": "#6b7280",
}


@st.cache_data
def load_report(path: str):
    with open(path) as f:
        return json.load(f)


def grade_color(score: float) -> str:
    if score >= 90:
        return "#10b981"
    if score >= 75:
        return "#3b82f6"
    if score >= 50:
        return "#f59e0b"
    if score >= 25:
        return "#f05252"
    return "#e02424"


def main():
    st.title("🛡️ Mini-CSPM — AWS Cloud Security Posture Report")
    st.caption("Read-only scan of S3, EC2 Security Groups and IAM, scored against a CIS-style benchmark")

    default_path = "sample_report.json"
    report_path = st.sidebar.text_input("Report JSON path", value=default_path)

    if not os.path.exists(report_path):
        st.error(f"Could not find `{report_path}`. Run `python main.py` first, or point to a report file.")
        st.stop()

    report = load_report(report_path)

    meta = report.get("metadata", {})
    st.sidebar.markdown("### Scan Info")
    st.sidebar.write(f"**Region:** {meta.get('region', 'N/A')}")
    st.sidebar.write(f"**Profile:** {meta.get('profile', 'N/A')}")
    st.sidebar.write(f"**Scanned at:** {meta.get('scanned_at', 'N/A')}")

    col1, col2, col3, col4 = st.columns(4)
    score = report["risk_score"]
    col1.metric("Risk Score", f"{score}/100")
    col2.metric("Grade", report["grade"].split(" ")[0])
    col3.metric("Checks Run", report["totals"]["total_checks"])
    col4.metric("Failed Checks", report["totals"]["failed"])

    st.markdown(
        f"""
        <div style="background:{grade_color(score)}22;border-left:6px solid {grade_color(score)};
        padding:12px 18px;border-radius:6px;margin:10px 0 20px 0;">
        <strong>Overall posture: {report['grade']}</strong>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("Findings by Severity")
    sev_counts = report["severity_counts"]
    sev_cols = st.columns(4)
    for col, sev in zip(sev_cols, ["Critical", "High", "Medium", "Low"]):
        col.markdown(
            f"<div style='text-align:center;padding:10px;border-radius:8px;"
            f"background:{SEVERITY_COLOR[sev]}22;'>"
            f"<span style='font-size:28px;font-weight:700;color:{SEVERITY_COLOR[sev]}'>{sev_counts[sev]}</span><br>"
            f"<span>{sev}</span></div>",
            unsafe_allow_html=True,
        )

    attack_paths = report.get("attack_paths", [])
    if attack_paths:
        st.subheader("🔗 Correlated Attack Paths")
        st.caption("Multiple findings linked into a single higher-impact risk — investigate these first.")
        for p in attack_paths:
            st.error(f"**[{p['severity'].upper()}] {p['title']}**")
            st.code(p["chain"], language=None)
            st.markdown(f"**Why it matters:** {p['explanation']}")
            st.markdown(f"**Fix:** {p['fix']}")
    else:
        st.subheader("🔗 Correlated Attack Paths")
        st.success("No correlated attack path found — isolated findings only.")

    st.subheader("All Findings")
    status_filter = st.multiselect(
        "Filter by status", ["FAIL", "WARN", "PASS", "ERROR"], default=["FAIL", "WARN", "ERROR"]
    )

    findings = [f for f in report["findings"] if f["status"] in status_filter]
    findings.sort(key=lambda f: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "N/A": 5}.get(f["severity"], 6))

    if not findings:
        st.success("No findings match the selected filters.")

    for f in findings:
        color = SEVERITY_COLOR.get(f["severity"], "#6b7280")
        with st.expander(f"[{f['status']}] {f['resource']} — {f['check']}  ({f['severity']})"):
            st.markdown(f"**CIS Control:** {f['cis_control']}")
            st.markdown(f"**Detail:** {f['detail']}")
            if f.get("fix"):
                st.markdown(f"**Recommended fix:** {f['fix']}")


if __name__ == "__main__":
    main()
