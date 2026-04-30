import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from analyzer.rule_checker import check_firewall_rules
from analyzer.risk_scoring import calculate_risk_score
from analyzer.report_generator import generate_pdf_report

# Page Config
st.set_page_config(
    page_title="Firewall Rule Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Sidebar
st.sidebar.title("🛡️ Firewall Rule Analyzer")

st.sidebar.markdown("""
### Features

- Any to Any Detection
- Dangerous Ports Detection
- Missing Logging Detection
- Duplicate Rules Detection
- Disabled Risky Rules
- Risk Score Dashboard
- Severity Visualization
- Downloadable CSV Report
- Downloadable PDF Audit Report
- Human-Friendly Recommendations
- Severity Summary Cards
""")

# Sample Files in Sidebar
st.sidebar.markdown("## 📁 Sample CSV Files")

sample_files = {
    "⬇ Safe Rules": "data/sample_safe_rules.csv",
    "⬇ High Risk": "data/sample_high_risk.csv",
    "⬇ Critical Risk": "data/sample_critical_risk.csv",
    "⬇ Duplicate Rules": "data/sample_duplicate_rules.csv",
    "⬇ Missing Logging": "data/sample_missing_logging.csv",
    "⬇ Disabled Risky Rules": "data/sample_disabled_risky_rules.csv"
}

for label, file_path in sample_files.items():
    with open(file_path, "rb") as file:
        st.sidebar.download_button(
            label=label,
            data=file,
            file_name=file_path.split("/")[-1],
            mime="text/csv"
        )

# Security Score Guide
st.sidebar.markdown("## 📊 Security Score Guide")

st.sidebar.markdown("""
- **80–100** → Low Risk  
- **60–79** → Medium Risk  
- **40–59** → High Risk  
- **0–39** → Critical Risk
""")

st.sidebar.info("Built using Python + Streamlit")

# Main Title
st.title("🛡️ Firewall Rule Analyzer for Security Misconfiguration Detection")

st.markdown("""
This tool helps identify risky firewall configurations and security misconfigurations
that may expose systems to cyber threats.

Upload your firewall policy CSV file and get:

- Security findings
- Risk score
- Severity distribution
- Top recommended actions
- Downloadable CSV report
- Downloadable PDF audit report
""")

st.divider()

# File Upload Section
uploaded_file = st.file_uploader(
    "Upload Firewall Rules CSV File",
    type=["csv"]
)

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    st.success("CSV uploaded successfully!")

    # Firewall Rules Preview
    st.subheader("📄 Firewall Rules Preview")
    st.dataframe(df, use_container_width=True)

    # Run Analysis
    findings_df = check_firewall_rules(df)
    score, risk_level = calculate_risk_score(findings_df)

    st.divider()

    # Security Dashboard
    st.subheader("📊 Security Dashboard")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Security Score", f"{score}/100")

    with col2:
        st.metric("Risk Level", risk_level)

    # Top Recommended Actions
    if not findings_df.empty:
        st.subheader("🛠 Top Recommended Actions")

        recommendations = findings_df["Recommendation"].unique()

        for i, rec in enumerate(recommendations[:5], 1):
            st.write(f"{i}. {rec}")

    st.divider()

    if not findings_df.empty:

        # Severity Summary Cards
        st.subheader("🚦 Severity Summary")

        critical_count = len(
            findings_df[findings_df["Severity"] == "Critical"]
        )

        high_count = len(
            findings_df[findings_df["Severity"] == "High"]
        )

        medium_count = len(
            findings_df[findings_df["Severity"] == "Medium"]
        )

        low_count = len(
            findings_df[findings_df["Severity"] == "Low"]
        )

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            st.error(f"🔴 Critical: {critical_count}")

        with c2:
            st.warning(f"🟠 High: {high_count}")

        with c3:
            st.info(f"🟡 Medium: {medium_count}")

        with c4:
            st.success(f"🟢 Low: {low_count}")

        st.divider()

        # Severity Distribution Chart
        st.subheader("📈 Severity Distribution")

        severity_counts = findings_df["Severity"].value_counts()

        fig, ax = plt.subplots()

        ax.bar(
            severity_counts.index,
            severity_counts.values
        )

        ax.set_xlabel("Severity")
        ax.set_ylabel("Number of Findings")
        ax.set_title("Firewall Security Findings by Severity")

        st.pyplot(fig)

        st.divider()

        # Findings Table
        st.subheader("🚨 Security Findings Report")

        st.dataframe(findings_df, use_container_width=True)

        st.warning(
            f"Total Issues Found: {len(findings_df)}"
        )

        # CSV Download Button
        csv = findings_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            label="⬇ Download CSV Security Report",
            data=csv,
            file_name="security_findings_report.csv",
            mime="text/csv"
        )

        # PDF Download Button
        pdf_path = generate_pdf_report(
            score,
            risk_level,
            findings_df
        )

        with open(pdf_path, "rb") as pdf_file:
            st.download_button(
                label="📄 Download PDF Audit Report",
                data=pdf_file,
                file_name="firewall_audit_report.pdf",
                mime="application/pdf"
            )

    else:
        st.success(
            "No security issues found. Firewall looks secure!"
        )

else:
    st.info(
        "Please upload a CSV file to begin analysis."
    )

st.divider()

# Footer
st.caption(
    "Developed By Satyabrata Behera | Firewall Rule Analyzer v1.0"
)
