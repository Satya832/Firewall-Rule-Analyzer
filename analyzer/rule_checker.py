import pandas as pd


def check_firewall_rules(df):
    findings = []

    dangerous_ports = {
        21: "FTP",
        23: "Telnet",
        22: "SSH",
        445: "SMB",
        3389: "RDP",
        1433: "MSSQL"
    }

    # Check 1: Any to Any Access
    for index, row in df.iterrows():
        if (
            str(row["SourceIP"]).strip().lower() == "any"
            and str(row["DestinationIP"]).strip().lower() == "any"
            and str(row["Action"]).strip().lower() == "allow"
        ):
            findings.append({
                "RuleID": row["RuleID"],
                "Issue": "Any to Any Access",
                "Severity": "Critical",
                "Recommendation": "Restrict source and destination IP ranges"
            })

    # Check 2: Dangerous Open Ports
    for index, row in df.iterrows():
        port = int(row["Port"])

        if port in dangerous_ports and str(row["Action"]).strip().lower() == "allow":
            findings.append({
                "RuleID": row["RuleID"],
                "Issue": f"Dangerous Port Open ({dangerous_ports[port]})",
                "Severity": "High",
                "Recommendation": f"Review access for port {port}"
            })

    # Check 3: Missing Logging
    for index, row in df.iterrows():
        if str(row["Logging"]).strip().lower() == "no":
            findings.append({
                "RuleID": row["RuleID"],
                "Issue": "Logging Disabled",
                "Severity": "Medium",
                "Recommendation": "Enable logging for auditing and monitoring"
            })

    # Check 4: Duplicate Rules
    duplicates = df[df.duplicated(
        subset=["SourceIP", "DestinationIP", "Port", "Action"],
        keep=False
    )]

    for index, row in duplicates.iterrows():
        findings.append({
            "RuleID": row["RuleID"],
            "Issue": "Duplicate Rule",
            "Severity": "Medium",
            "Recommendation": "Remove unnecessary duplicate rules"
        })

    # Check 5: Disabled Risky Rules
    for index, row in df.iterrows():
        if (
            str(row["Enabled"]).strip().lower() == "no"
            and int(row["Port"]) in dangerous_ports
        ):
            findings.append({
                "RuleID": row["RuleID"],
                "Issue": "Disabled Risky Rule",
                "Severity": "Low",
                "Recommendation": "Review and remove unused risky disabled rules"
            })

    return pd.DataFrame(findings)
