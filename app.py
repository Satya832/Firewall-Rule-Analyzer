import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from analyzer.rule_checker import check_firewall_rules
from analyzer.risk_scoring import calculate_risk_score

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
- Downloadable audit report
""")

st.divider()

# File Upload
uploaded_file = st.file_uploader(
    "Upload Firewall Rules CSV File",
    type=["csv"]
)

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    st.success("CSV uploaded successfully!")

    st.subheader("📄 Firewall Rules Preview")
    st.dataframe(df, use_container_width=True)

    findings_df = check_firewall_rules(df)
    score, risk_level = calculate_risk_score(findings_df)

    st.divider()

    # Dashboard
    st.subheader("📊 Security Dashboard")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Security Score", f"{score}/100")

    with col2:
        st.metric("Risk Level", risk_level)

    st.divider()

    if not findings_df.empty:
        # Chart
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
        st.warning(f"Total Issues Found: {len(findings_df)}")

        # Download Button
        csv = findings_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="⬇ Download Security Report",
            data=csv,
            file_name="security_findings_report.csv",
            mime="text/csv"
        )

    else:
        st.success("No security issues found. Firewall looks secure!")

else:
    st.info("Please upload a CSV file to begin analysis.")

st.divider()

# Footer
st.caption("Developed By Satyabrata Behera | Firewall Rule Analyzer v1.0")
