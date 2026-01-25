#  SecretShield

**SecretShield** is an advanced security scanner designed to detect **hardcoded secrets, API keys, and credentials** within source code repositories.

Unlike traditional scanners that rely solely on pattern matching, SecretShield introduces an **Active Verification Engine** that validates discovered secrets in real time against their respective provider APIs (such as AWS, GitHub, Stripe, and more). This allows it to accurately distinguish between **harmless strings** and **active, exploitable vulnerabilities**.

SecretShield is built as a **resume-grade DevSecOps project**, demonstrating secure coding practices, API integrations, entropy analysis, and professional reporting.

---

##  Key Features

-  **High-Fidelity Secret Detection**
-  **Context-Aware Scanning**
-  **Active Verification Engine**
-  **Professional HTML Reporting**
-  **DevSecOps Ready**

---

##  Supported Providers

| Provider | Detection Method | Active Verification |
|--------|------------------|---------------------|
| AWS | AKIA... + Secret Context | STS GetCallerIdentity |
| GitHub | ghp_... | User API & Rate Limit Check |
| Stripe | sk_live_... | Balance Endpoint |
| GitLab | glpat-... | User / Project Scope |
| Slack | xoxb... / xoxp... | auth.test |
| Google | AIza... | Generic API Validity |
| DigitalOcean | dop_v1_... | Account Info |
| Private Keys | PEM Headers | Detection Only (Critical) |

---

##  How It Works

1. File Crawling  
2. Pattern Matching (Layer 1)  
3. Entropy Analysis  
4. Active Verification  
5. Reporting  

---

##  Installation

### Requirements
- Python 3.10+

```bash
git clone https://github.com/YonatanBiton/SecretShield.git
cd SecretShield
pip install -r requirements.txt
```

---

##  Usage

```bash
python src/main.py <folder_path>
python src/main.py <repo_url>
python src/main.py <folder_or_repo> --html
```

---

##  HTML Report

<img width="1906" height="905" alt="image" src="https://github.com/user-attachments/assets/d918ef87-803c-491b-94a9-8a7fae3e1606" />



```text
[ Screenshot: SecretShield HTML Report ]
```

---

##  Project Structure

```text
SecretShield/
├── src/
├── requirements.txt
└── README.md
```

---

##  Use Cases

- Secure code reviews
- CI/CD scanning
- DevSecOps portfolios

---

##  Author

Yonatan Biton  
https://github.com/YonatanBiton

---

##  License

License

This project is licensed under the MIT License - see the LICENSE file for details.

Disclaimer: This tool is intended for security testing of repositories you own or have explicit permission to scan. Do not use this tool on unauthorized codebases.