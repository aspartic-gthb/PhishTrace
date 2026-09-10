#  PhishTrace: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

[![SIH Problem Statement](https://img.shields.io/badge/SIH%20Problem%20Statement-SIH26106-blue.svg)](ProblemStatement.txt)
[![Category](https://img.shields.io/badge/Category-Software%20%7C%20Cybersecurity-red.svg)](ProblemStatement.txt)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.12+-green.svg)](backend/)
[![Dashboard](https://img.shields.io/badge/SOC%20Dashboard-Next.js%2016%20%7C%20TailwindCSS-black.svg)](dashboard/)
[![Test Suite](https://img.shields.io/badge/Automated%20Tests-7%2F7%20Passing-brightgreen.svg)](test_forensic_platform.py)

**PhishTrace** is an enterprise-grade cybersecurity platform developed for **SIH26106 (AICTE Cyber Security Cell)**. It combines Natural Language Processing (NLP), multi-layered RFC-5322 email header forensics, hop-by-hop IP geolocation, thin DNS/WHOIS lookalike intelligence, and unsupervised campaign clustering to detect advanced email threats, uncover attacker infrastructure, and generate court-admissible forensic evidence.

---

##  Key Capabilities (Aligned with SIH26106)

```
                                  ┌───────────────────────────┐
                                  │   Incoming Email Stream   │
                                  └─────────────┬─────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
    ┌─────────────────────────┐    ┌─────────────────────────┐    ┌─────────────────────────┐
    │  RFC-5322 Header Parser │    │  Social Engineering ML  │    │  Geo-IP Origin Engine   │
    │ SPF, DKIM, DMARC,       │    │ Urgency, Authority,     │    │ Earliest MTA extraction,│
    │ Return-Path, Message-ID │    │ Fear, Impersonation     │    │ Tor/VPN/Bulletproof ISP │
    └────────────┬────────────┘    └────────────┬────────────┘    └────────────┬────────────┘
                 │                              │                              │
                 └──────────────────────────────┼──────────────────────────────┘
                                                ▼
                                  ┌───────────────────────────┐
                                  │   Forensic Risk Fusion    │
                                  │   Score: 0.0% – 100.0%    │
                                  └─────────────┬─────────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼                                                             ▼
    ┌─────────────────────────┐                                   ┌─────────────────────────┐
    │ Threat Campaign Graph   │                                   │ Evidentiary PDF Report  │
    │ Automated ASN Clustering│                                   │ SHA-256 Evidence Digest │
    └─────────────────────────┘                                   └─────────────────────────┘
```

1. **Multi-Layered Header Forensics**:
   - Parses `Return-Path`, `Reply-To`, `Message-ID`, and `Authentication-Results`.
   - Validates SPF alignment, DKIM cryptographic signatures, and DMARC enforcement policies.
   - Detects display-name spoofing and reply-to discrepancies.

2. **Origin IP Geolocation & Geo-Mismatch Engine**:
   - Reconstructs intermediate `Received:` relays and identifies the **earliest trustworthy sending node**.
   - Resolves origin IP to physical country, city, ISP, ASN, and geographic coordinates.
   - Flags **Origin Mismatches** when claimed sender headquarters (e.g. `@chase.com`, `@infosys.com`) conflicts with physical server locations (e.g. Tor exit nodes or bulletproof hosting in foreign jurisdictions).

3. **Multi-Label Social Engineering NLP Classifier**:
   - Multi-output probabilistic classifier evaluating **4 concurrent psychological attack dimensions**:
     - ⏳ `Urgency`: Artificial countdowns, immediate wire transfer demands.
     - 👔 `Authority`: Executive coercion (CEO, HR Director, Legal Counsel).
     - ⚠️ `Fear`: Account suspension, penalty threats, law enforcement intimidation.
     - 🎭 `Impersonation`: Deceptive brand masquerading.
   - Dual **Random Forest temporal pipeline** that mathematically distinguishes benign promotional marketing urgency from malicious coercive extortion.

4. **Attachment Threat Forensics**:
   - Heuristic inspection detecting double-extension lures (e.g. `Payroll_Bonus_Matrix.pdf.exe`).
   - Flags macro-enabled documents (`.xlsm`, `.docm`), scripts (`.vbs`, `.bat`, `.ps1`), and executable payloads with 99% risk ratings.

5. **Threat Campaign Correlation & Clustering**:
   - Automatically correlates isolated alerts into organized threat operations (e.g. `CAMP-9821` sharing infrastructure, subnets, and ASNs).

6. **Court-Admissible Evidentiary Reports**:
   - Generates tamper-evident forensic reports with cryptographic **SHA-256 evidence digests** in both JSON and signed PDF formats suitable for legal review and cybercrime law enforcement.

7. **Next.js 16 SOC Analyst Dashboard**:
   - **Entity Relationship Node Graph**: Interactive 2D SVG topology connecting Senders, Origin IPs, Return-Paths, and Target Domains.
   - **Geo Threat World Map**: Interactive cyber dark-mode vector map displaying origin nodes, flight arc trajectories, and mismatch banners.
   - **Hop Relay Timeline**: Step-by-step RFC-5322 relay chain breakdown.

8. **Privacy & Legal Safeguards (DPDP Act & GDPR)**:
   - Automated client-side PII regex redaction (credit cards, Aadhaar/SSN, bank accounts, emails).
   - Local **Fernet AES-256 field-level encrypted** database persistence.

---

## 📁 Repository Structure

```
proto_final/
├── backend/                   # FastAPI backend server
│   ├── app/
│   │   ├── database.py        # SQLite engine configuration
│   │   ├── models.py          # SQLAlchemy models (ScanResult, PII, Encryption)
│   │   ├── routes/            # REST API endpoints (/email-scans, /analysis, etc.)
│   │   ├── schemas/           # Pydantic data schemas
│   │   └── services/          # Forensics, Geo-IP, DNS, Reports, ML, PII
│   ├── data/                  # Sentinel event store
│   ├── main.py                # Monolithic application entry point
│   └── requirements.txt       # Python dependencies
├── dashboard/                 # Next.js 16 SOC Analyst Workspace
│   ├── src/app/               # App router pages (/gmail, /activity, /privacy, /settings)
│   └── src/components/        # GeoThreatMap, EntityRelationshipGraph, LiveEmailFeed
├── data/                      # Training & validation datasets
│   └── processed/train.csv    # Multi-label social engineering dataset (1,345 samples)
├── extension-final/           # Chrome Extension (Manifest V3)
│   ├── manifest.json          # Extension configuration & Gmail scopes
│   ├── popup.html / popup.js  # User threat banner & quick controls
│   └── src/content/           # gmail-scanner.js (live email DOM extractor)
├── models/                    # Serialized Machine Learning artifacts
│   ├── model_v6.joblib        # MultiOutputClassifier (Logistic Regression)
│   ├── vectorizer_v6.joblib   # TF-IDF Feature Extractor (572 vocabulary tokens)
│   └── temporal_analysis_v1.pkl # Random Forest temporal urgency classifier & regressor
├── encryption.key             # Master Fernet AES-256 database encryption key
├── start_platform.sh          # Unified One-Click Platform Launcher
├── start_server.py            # Standalone FastAPI server launcher (port 8005)
├── evaluate_dataset.py        # CLI suite to evaluate models on external datasets
├── seed_email_forensics.py    # Database seeder for realistic threats & campaigns
├── test_forensic_platform.py  # 7-point master automated test suite
├── test_encryption.py         # AES-256 encryption verification test
├── sample_threat_email.eml    # Sample court-admissible forensic test lure
├── SIH_PITCH_AND_DEMO_GUIDE.md# Official 3-minute pitch & demo script for jury panels
└── ProblemStatement.txt       # Official SIH26106 problem statement text
```

---

## 🚀 Quick Start Guide

### 1. One-Click Platform Launch (Recommended)
Boot the entire platform (FastAPI backend + Next.js dashboard + database seeder) with a single command:
```bash
./start_platform.sh
```

The script will automatically:
- Bind to the active Python virtual environment.
- Clear ports `8005` (Backend) and `3001` (Dashboard).
- Seed the database with realistic attack vectors and campaign clusters.
- Launch the backend API at **`http://localhost:8005`**.
- Launch the SOC Analyst Dashboard at **`http://localhost:3001`**.

*Press `Ctrl+C` at any time to cleanly stop all platform services.*

---

### 2. Access Points
- **SOC Analyst Forensic Feed**: [`http://localhost:3001/gmail`](http://localhost:3001/gmail)
- **SOC Overview Dashboard**: [`http://localhost:3001`](http://localhost:3001)
- **Privacy & Encryption Center**: [`http://localhost:3001/privacy`](http://localhost:3001/privacy)
- **Interactive OpenAPI / Swagger Docs**: [`http://localhost:8005/docs`](http://localhost:8005/docs)

---

### 3. Load the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle on **"Developer mode"** in the top-right corner.
3. Click **"Load unpacked"**.
4. Select the `extension-final` directory inside this repository.
5. Open Gmail: The extension will passively inspect email headers and display real-time safety banners above suspicious emails.

---

## 🧪 Testing & Verification

Run the master automated forensic test suite:
```bash
python test_forensic_platform.py
```

**Expected Output:**
```
✓ Header Parser & Auth Scoring: PASS
✓ IP Geolocation & Origin Mismatch Engine: PASS
✓ Thin DNS/WHOIS & Lookalike Detection: PASS
✓ Forensic Risk Fusion: PASS (Score: 100.0%)
✓ Forensic Report JSON & Signed PDF Export: PASS
✓ Suspicious Attachment Forensics: PASS
✓ Threat Campaign Clustering: PASS (2 campaigns clustered)
------------------------------------------------------
Ran 7 tests in 1.65s (OK)
```

---

## 📊 How to Evaluate with Other Datasets

We provide a dedicated CLI tool, [evaluate_dataset.py](file:///home/aspartic/Desktop/SIH/proto_final/evaluate_dataset.py), to evaluate any external dataset (e.g. Enron, Nazario, Kaggle Phishing, or custom enterprise dumps).

### 1. Basic Evaluation
Run evaluation on any CSV or JSON file:
```bash
python evaluate_dataset.py --dataset path/to/your_dataset.csv
```

### 2. Specifying a Custom Text Column
If your dataset uses a different column name for email bodies (e.g. `body`, `email_content`, `message`):
```bash
python evaluate_dataset.py --dataset custom_emails.csv --text-col email_content
```

### 3. Exporting Predictions to CSV
To export model risk scores, risk levels, and predicted threat vectors for further analysis:
```bash
python evaluate_dataset.py --dataset custom_emails.csv --output evaluated_results.csv
```

### 4. Ground-Truth Benchmarking
If your dataset includes ground-truth labels, the tool automatically calculates and displays **Accuracy, Precision, Recall, and F1-score**:
- **Multi-Label Columns**: Columns named `urgency`, `authority`, `fear`, `impersonation` (values 0 or 1).
- **Binary Classification Columns**: A column named `label` or `is_phishing` (0 for benign, 1 for phishing).

#### Example Benchmark on `data/processed/train.csv`:
```
============================================================
          PHISHTRACE MODEL EVALUATION REPORT
============================================================
Total Samples Analyzed: 1,345
  • Critical Threats (≥ 70%):   913 (67.9%)
  • Suspicious Emails (40-69%): 49  (3.6%)
  • Safe / Benign (< 40%):      383 (28.5%)
------------------------------------------------------------
Threat Vector Averages Across Dataset:
  • Avg Urgency Score:       67.17%
  • Avg Authority Pressure:  67.67%
  • Avg Fear / Coercion:     57.70%
  • Avg Impersonation Risk:  63.40%
------------------------------------------------------------
📈 Ground Truth Multi-Label Performance Metrics:
  [URGENCY       ] Acc: 97.77% | Prec: 100.00% | Rec: 96.85% | F1: 98.40%
  [AUTHORITY     ] Acc: 98.36% | Prec: 100.00% | Rec: 97.71% | F1: 98.84%
  [FEAR          ] Acc: 98.22% | Prec:  99.74% | Rec: 97.26% | F1: 98.48%
  [IMPERSONATION ] Acc: 98.36% | Prec:  99.89% | Rec: 97.67% | F1: 98.76%
============================================================
```

---

## ⚖️ Legal & Privacy Compliance
- **Evidence Integrity**: All forensic reports include an immutable SHA-256 digest ensuring legal chain-of-custody for cybercrime prosecution.
- **Privacy Standard**: Zero raw PII (credit cards, government IDs, bank credentials) is exposed in plaintext. All data is sanitized on-the-fly and stored with AES-256 encryption.
