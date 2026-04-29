def calculate_risk_score(findings_df):
    score = 100

    severity_weights = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 4
    }

    for _, row in findings_df.iterrows():
        severity = row["Severity"]

        if severity in severity_weights:
            score -= severity_weights[severity]

    if score < 0:
        score = 0

    if score >= 80:
        risk_level = "LOW RISK"
    elif score >= 50:
        risk_level = "MEDIUM RISK"
    else:
        risk_level = "HIGH RISK"

    return score, risk_level
