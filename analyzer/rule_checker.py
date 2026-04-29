import pandas as pd


def check_firewall_rules(df):
    findings = []

    dangerous_ports = {
        21: ("FTP", "File Transfer Protocol is outdated and often insecure."),
        23: ("Telnet", "Telnet sends data in plain text and is highly insecure."),
        22: ("SSH", "SSH is secure but should be restricted to trusted IPs."),
        445: ("SMB", "SMB is often targeted in ransomware and lateral movement attacks."),
        3389: ("RDP", "RDP can expose remote access and is frequently targeted by attackers."),
        1433: ("MSSQL", "Database ports should never be openly exposed to the internet.")
    }

    # Check 1: Any to Any Access
    for _, row in df.iterrows():
        if (
            str(row["SourceIP"]).strip().lower() == "any"
            and str(row["DestinationIP"]).strip().lower() == "any"
            and str(row["Action"]).strip().lower() == "allow"
        ):
            findings.append({
                "RuleID": row["RuleID"],
                "Issue": "Any to Any Access",
                "Severity": "Critical",
                "Explanation": "Traffic is allowed from any source to any destination without restrictions.",
                "Recommendation": "Restrict source and destination IP ranges immediately."
            })

    # Check 2: Dangerous Open Ports
    for _, row in df.iterrows():
        port = int(row["Port"])

        if port in dangerous_ports and str(row["Action"]).strip().lower() == "allow":
            service, explanation = dangerous_ports[port]

            findings.append({
                "RuleID": row["RuleID"],
                "Issue": f"Dangerous Port Open ({service})",
                "Severity": "High",
                "Explanation": explanation,
                "Recommendation": f"Review and restrict access for port {port}."
            })

    # Check 3: Missing Logging
    for _, row in df.iterrows():
        if str(row["Logging"]).strip().lower() == "no":
            findings.append({
                "RuleID": row["RuleID"],
                "Issue": "Logging Disabled",
                "Severity": "Medium",
                "Explanation": "Without logs, suspicious activities may go unnoticed.",
                "Recommendation": "Enable logging for auditing and incident investigation."
            })

    # Check 4: Duplicate Rules
    duplicates = df[df.duplicated(
        subset=["SourceIP", "DestinationIP", "Port", "Action"],
        keep=False
    )]

    for _, row in duplicates.iterrows():
        findings.append({
            "RuleID": row["RuleID"],
            "Issue": "Duplicate Rule",
            "Severity": "Medium",
            "Explanation": "Duplicate rules increase complexity and may create confusion during audits.",
            "Recommendation": "Remove unnecessary duplicate firewall rules."
        })

    # Check 5: Disabled Risky Rules
    for _, row in df.iterrows():
        if (
            str(row["Enabled"]).strip().lower() == "no"
            and int(row["Port"]) in dangerous_ports
        ):
            findings.append({
                "RuleID": row["RuleID"],
                "Issue": "Disabled Risky Rule",
                "Severity": "Low",
                "Explanation": "Old disabled risky rules should be reviewed and cleaned up.",
                "Recommendation": "Remove unused risky disabled rules."
            })

    return pd.DataFrame(findings)
