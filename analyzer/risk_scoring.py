def calculate_risk_score(findings_df):
    score = 100

    severity_weights = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 4
    }

    counted_issues = set()

    for _, row in findings_df.iterrows():
        issue = row["Issue"]
        severity = row["Severity"]

        # Prevent same issue type from over-penalizing
        if issue not in counted_issues:
            if severity in severity_weights:
                score -= severity_weights[severity]

            counted_issues.add(issue)

    if score < 0:
        score = 0

    if score >= 80:
        risk_level = "LOW RISK"
    elif score >= 60:
        risk_level = "MEDIUM RISK"
    elif score >= 40:
        risk_level = "HIGH RISK"
    else:
        risk_level = "CRITICAL RISK"

    return score, risk_level
