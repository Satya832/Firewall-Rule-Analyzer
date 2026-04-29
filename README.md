# 🛡️ Firewall Rule Analyzer

A simulation-based cybersecurity project built using Python and Streamlit to detect firewall security misconfigurations and generate security audit reports.

This tool helps identify risky firewall configurations such as open dangerous ports, Any-to-Any access, missing logging, duplicate rules, and disabled risky rules using structured firewall rule CSV datasets.

It provides a security score, risk level, severity analysis, recommendations, downloadable CSV reports, and PDF audit reports.

---

## 🚀 Live Demo

🔗 Deployed App: https://firewall-rule-analyzer.streamlit.app/

---

## 📌 Features

* Any-to-Any Access Detection
* Dangerous Open Ports Detection
* Missing Logging Detection
* Duplicate Rules Detection
* Disabled Risky Rules Detection
* Security Score Calculation
* Risk Level Classification
* Severity Summary Dashboard
* Severity Distribution Chart
* Human-Friendly Security Recommendations
* Downloadable CSV Security Report
* Downloadable PDF Audit Report
* Downloadable Sample CSV Files for Testing

---

## 📁 Sample Test Files Included

The project includes multiple sample firewall rule datasets for testing different security scenarios.

### 1. sample_safe_rules.csv

Represents a secure firewall configuration with minimal risk.

### 2. sample_high_risk.csv

Contains risky rules such as open RDP, SSH exposure, duplicate rules, and missing logging.

### 3. sample_critical_risk.csv

Represents severe security misconfigurations such as Any-to-Any access, Telnet exposure, dangerous open ports, and logging disabled.

### 4. sample_duplicate_rules.csv

Focused on duplicate firewall policies that increase management complexity and audit confusion.

### 5. sample_missing_logging.csv

Shows firewall rules where logging is disabled, reducing visibility during incident investigation.

### 6. sample_disabled_risky_rules.csv

Contains disabled but dangerous legacy rules that should be reviewed and removed.

These files help simulate real-world firewall auditing scenarios and improve testing coverage.

---

## 🛠️ Tech Stack

* Python
* Streamlit
* Pandas
* Matplotlib
* FPDF
* Git
* GitHub

---

## 📂 Project Structure

```text
Firewall-Rule-Analyzer/
│
├── analyzer/
│   ├── __init__.py
│   ├── rule_checker.py
│   ├── risk_scoring.py
│   └── report_generator.py
│
├── data/
│   ├── sample_safe_rules.csv
│   ├── sample_high_risk.csv
│   ├── sample_critical_risk.csv
│   ├── sample_duplicate_rules.csv
│   ├── sample_missing_logging.csv
│   └── sample_disabled_risky_rules.csv
│
├── assets/
│   └── styles.css
│
├── app.py
├── requirements.txt
└── README.md
```


---

## ⚙️ How to Run Locally

### Step 1: Clone Repository

git clone https://github.com/Satya832/Firewall-Rule-Analyzer.git

cd Firewall-Rule-Analyzer

---

### Step 2: Create Virtual Environment

python3 -m venv venv

source venv/bin/activate

---

### Step 3: Install Requirements

pip install -r requirements.txt

---

### Step 4: Run Application

streamlit run app.py

---

## 📊 How It Works

1. Upload a firewall rule CSV file
2. The analyzer checks for security misconfigurations
3. Risk score and severity level are calculated
4. Security recommendations are generated
5. CSV and PDF audit reports can be downloaded

---

## 🔐 Security Issues Detected

* Any-to-Any Access
* Dangerous Open Ports (RDP, Telnet, FTP, SMB, SSH, etc.)
* Missing Logging
* Duplicate Rules
* Disabled Risky Rules

---

## 📈 Future Improvements

* Real Firewall Integration (pfSense / FortiGate / Windows Firewall)
* Rule Shadowing Detection
* Redundant Rule Detection
* Compliance Score (ISO / NIST / CIS)
* Advanced Risk Scoring Engine
* Direct Firewall Export Parsing

---

## 👨‍💻 Developed By

Satyabrata Behera

Cybersecurity | Network Security | VAPT | Python Security Projects

---

## ⭐ Project Type

Proof-of-Concept / Simulation-Based Cybersecurity Project

Designed for learning, demonstration, and security analysis of firewall rule misconfigurations.
