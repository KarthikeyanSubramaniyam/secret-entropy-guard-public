# Secret Entropy Guard

<p align="center">
  <img src="https://img.shields.io/badge/Security-Secret%20Detection-red?style=flat" alt="Security Domain">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-T1552.001-orange?style=flat" alt="MITRE ATT&CK">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
</p>

An automated, defensive secret scanner and credential leak prevention engine that inspects source code, configuration manifests, and commit history for exposed API keys, private certificates, and high-entropy authentication tokens using Shannon entropy calculations and high-confidence cryptographic signatures.

---

## 🎯 The Problem It Solves

Accidental credential exposure in source code is one of the most common causes of initial access and cloud account compromise. Static keyword searches generate massive false-positive noise, while basic regex alone misses obfuscated or unstructured secrets.

**Secret Entropy Guard** solves this through a multi-layered inspection strategy:
1. **High-Confidence Signature Matching**: Detects provider-specific tokens (AWS Access Keys, GitHub PATs, Slack Bot Tokens, Stripe Keys, Private Key Headers).
2. **Shannon Entropy Heuristics**: Calculates information entropy in bits per character ($\ge 3.4$) on assignment expressions to catch unpatterned API secrets and high-entropy passwords.
3. **Safe Redaction**: Automatically redacts leaked credentials in logs and outputs (e.g. `AKIA************EXAMPLE`) to prevent secondary leakage during security reporting.
4. **DevSecOps Integration**: Provides structured JSON reporting and non-zero exit codes for pre-commit hooks and CI/CD security quality gates.

---

## 🏗️ System Architecture & Workflow

```
[ Code Repository / Manifests ]
               |
               v
+-------------------------------+
|     1. Recursive File Filter  | -> Skips binary assets, virtualenvs, and lockfiles
|    (Text Extraction Engine)   |    while scanning source scripts and configurations
+--------------+----------------+
               |
               v
+-------------------------------+
|   2. Signature Pattern Match  | -> Scans for high-confidence regex signatures:
|    (AWS, GitHub, Slack, etc.) |    AWS (AKIA), GitHub (ghp_), Private Keys
+--------------+----------------+
               |
               v
+-------------------------------+
|    3. Shannon Entropy Engine  | -> Computes character entropy on variable assignments
|    (Entropy Threshold >= 3.4) |    to uncover raw API tokens and passwords
+--------------+----------------+
               |
               v
+-------------------------------+
|    4. Secret Masker & Redactor| -> Obfuscates raw secret values with asterisks
|     (Safe Forensic Reporting) |    to avoid credential sprawl in triage tickets
+--------------+----------------+
               |
               v
+-------------------------------+
|   5. Posture Summary & Audit  | -> Outputs findings table or structured JSON
|     (DevSecOps CI/CD Gate)    |    with MITRE ATT&CK T1552.001 categorization
+-------------------------------+
```

---

## 🚀 Technical Specifications & Rules

| Rule Identifier | Severity | Target Pattern | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`AWS_ACCESS_KEY`** | `CRITICAL` | `AKIA[0-9A-Z]{16}` | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Exposed AWS IAM user access key |
| **`GITHUB_PAT`** | `CRITICAL` | `ghp_[a-zA-Z0-9]{36}` | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | GitHub personal access token |
| **`STRIPE_API_KEY`** | `CRITICAL` | `sk_live_[0-9a-zA-Z]{24,34}` | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Production payment gateway secret |
| **`PRIVATE_KEY_BLOCK`** | `CRITICAL` | `-----BEGIN * PRIVATE KEY-----` | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | Unencrypted RSA/EC/OpenSSH private key |
| **`SLACK_BOT_TOKEN`** | `HIGH` | `xoxb-[0-9]{11,13}-...` | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Slack bot workspace OAuth token |
| **`HIGH_ENTROPY_CREDENTIAL`** | `HIGH` | Shannon Entropy $\ge 3.4$ | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | High-entropy string assignment |

---

## 💻 CLI Usage & Quickstart

### Scan a Source Repository
```bash
python -m src.secret_guard.cli ./src
```

### Scan with Custom Entropy Threshold & JSON Output
```bash
python -m src.secret_guard.cli ./config --entropy 3.6 --json
```

### Run Unit Tests
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 🔒 Production Code & Architecture Notice

* **Public Repository**: Contains architecture blueprints, entropy calculation formulas, and detection rule specifications.
* **Private Repository**: Maintained in `KarthikeyanSubramaniyam/secret-entropy-guard` with pre-commit hook integrations, Git commit-history blame forensics, and automated vault remediation dispatchers.
