# PhishTrace: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence
## 🏆 Official Jury Presentation & Live Demonstration Guide

---

## 1. Problem Statement Compliance Matrix (SIH26106)

| SIH26106 Requirement | Our Implementation | Code Location / Evidence |
| :--- | :--- | :--- |
| **Multi-layered Header Forensics** | Full RFC-5322 extraction of `Return-Path`, `Reply-To`, `Message-ID`, `Authentication-Results`, DKIM alignment & SPF/DMARC status. | `backend/app/services/email_forensics.py` |
| **IP Geolocation & Origin Mismatch** | Hop-by-hop Received chain extraction, physical IP geolocation (City, Country, ISP, ASN), and discrepancy detection between claimed sender HQ vs. origin server. | `backend/app/services/ip_geolocation.py` |
| **Thin DNS & WHOIS Intelligence** | Automated MX lookup, SPF/DMARC DNS records, domain registration age calculation, and Levenshtein lookalike typosquatting detection. | `backend/app/services/dns_analysis.py` |
| **Social Engineering NLP Scoring** | Multi-label ML classifier evaluating Urgency, Fear, Authority Pressure, Financial Coercion, and Impersonation cues. | `backend/main.py` + `models/` |
| **Attachment Threat Forensics** | Heuristic inspection detecting double-extension lures (e.g. `.pdf.exe`), macro documents (`.xlsm`, `.docm`), scripts (`.vbs`, `.bat`), and high-entropy payloads. | `backend/app/services/email_forensics.py` (`assess_filename`) |
| **Threat Campaign Clustering** | Automated graph correlation grouping disparate incidents by shared infrastructure, origin subnet, lookalike domain patterns, and campaign severity. | `backend/app/routes/email_scans.py` (`/campaigns`) |
| **Evidentiary Forensic Reporting** | Cryptographic SHA-256 evidence chain digest with 1-click court-admissible JSON and signed PDF export. | `backend/app/services/forensic_report.py` |
| **Interactive SOC Dashboard** | Modern Next.js 16 SOC workspace featuring Interactive Entity Relationship Node Graph, Geo-IP Threat World Map, and Hop Relay Timeline. | `dashboard/src/components/` |
| **Privacy, Legal & Compliance** | Strict PII redaction engine (credit cards, Aadhaar/SSN, phones, credentials) + Fernet AES-256 field-level encrypted database storage. | `backend/app/services/pii_service.py` + `backend/app/models.py` |

---

## 2. The 3-Minute Winning Jury Pitch

### **[0:00 – 0:45] The Hook & The Problem**
> *"Respected Jury members, email remains the #1 initial breach vector for enterprises, banks, and critical infrastructure. But traditional email gateways rely on static blacklists and basic keyword filters. Today's threat actors use sophisticated techniques: legitimate compromised SMTP relays, freshly registered typosquatted domains, and social engineering urgency cues that bypass perimeter defenses. Most critically, when a breach occurs, incident response teams take hours to trace the origin and gather admissible evidence. Our platform, **PhishTrace**, solves this end-to-end with an AI-Powered Email Forensic Intelligence & GeoLocation Platform."*

### **[0:45 – 1:45] The Architecture & Core Innovation**
> *"PhishTrace combines four synchronized engines:*
> 1. *A **Client-Side Sensor**: A Manifest V3 Chrome Extension that passively inspects email headers in Gmail and enterprise webmail without interfering with user productivity.*
> 2. *A **Multi-Layer Forensic Pipeline**: It parses the entire Received hop relay, validates SPF, DKIM alignment, and DMARC enforcement, computes domain age, and flags lookalike domains.*
> 3. *An **IP Geo-Origin Mismatch Engine**: It detects when an email claiming to be from Chase Bank or Infosys originates from a Tor exit node or bulletproof hosting server in an unauthorized jurisdiction.*
> 4. *A **Social Engineering Classifier & Attachment Inspector**: It scores psychological manipulation triggers (urgency, authority pressure) and catches dangerous evasion techniques like double-extension `.pdf.exe` lures."*

### **[1:45 – 2:30] Campaign Correlation & Court-Admissible Reporting**
> *"Rather than treating attacks as isolated alerts, PhishTrace automatically correlates incidents into **Threat Campaigns** sharing common ASNs, subnets, and sender patterns. With a single click, an analyst can generate a **Cryptographically Signed PDF Forensic Report** featuring a SHA-256 tamper-evident digest suitable for court submission and cybercrime law enforcement."*

### **[2:30 – 3:00] Compliance & Live Demonstration**
> *"Unlike standard tools that risk leaking employee data, PhishTrace features built-in **PII Redaction** and **AES-256 Field Encryption**, complying fully with privacy regulations like the DPDP Act and GDPR. Let me now show you PhishTrace live in action."*

---

## 3. Step-by-Step Live Demonstration Protocol

### Pre-Demo Startup (One-Click)
Open a terminal in the project directory and execute:
```bash
./start_platform.sh
```
*The script automatically checks Python & Node.js environments, seeds the forensic database with realistic attacks and campaign clusters, launches the FastAPI backend on port `8005`, and starts the Next.js SOC Analyst dashboard on port `3001`.*

---

### Demonstration Flow

#### Step 1: Open the SOC Analyst Dashboard
- Navigate to: **`http://localhost:3001/gmail`**
- **Point out to Jury:**
  - The top summary cards: Total Scans, High Risk Incidents, Geographic Mismatches Flagged, and Authentication Failures.
  - The real-time live incident stream showing incoming parsed emails.

#### Step 2: Inspect a Sophisticated Threat
- Click on the top critical incident: **`URGENT: Executive Wire Transfer Authorization Required`** or **`Immediate Action Required - Compensation Confirmation`**.
- **Show the Multi-Layered Analysis:**
  1. **Authentication Badge Matrix:**
     - Point out: `SPF: FAIL`, `DKIM: FAIL`, `DMARC: FAIL`.
  2. **Social Engineering Urgency Analysis:**
     - Point out the NLP classifier scores: `Urgency: 98%`, `Authority Pressure: 92%`, `Fear / Coercion: 85%`.
  3. **Attachment Forensics:**
     - Show the attachment card highlighting: `Q3_Executive_Payroll_Bonus_Matrix.pdf.exe` flagged as `DOUBLE_EXTENSION_SPOOF` with `99% Risk`.

#### Step 3: Demonstrate the 3 Relational Views
Toggle through the three visualization modes in the detail drawer:
1. **Entity Node Graph:**
   - Interactive 2D topology showing connections between the Sender, Origin IP, Return-Path, and Target Domain.
2. **Geo Threat Map:**
   - Interactive cyber world map showing the pulsating origin marker in Russia/Tor Network, the flight arc trajectory to the victim inbox in the US, and the Origin Mismatch warning banner.
3. **Hop Relay Timeline:**
   - Step-by-step breakdown of every intermediate MTA hop with timestamp, delay, and IP.

#### Step 4: Campaign Clustering & Case Management
- At the top of the feed, click **`Campaign Cases`**.
- Show how PhishTrace automatically clustered isolated alerts into:
  - **`CAMP-9821`** (Executive Wire Phishing Campaign - 4 incidents sharing `AS208323`).
  - **`CAMP-3304`** (Brand Credential Harvesting Campaign - 3 incidents targeting enterprise employees).

#### Step 5: Export Evidence-Grade Forensic Report
- In the incident detail drawer, click the **`Export Forensic PDF`** button.
- The platform downloads a signed forensic report with:
  - Official Case ID & Timestamp.
  - SHA-256 Cryptographic Evidence Digest.
  - Full hop-by-hop forensic trace for legal/law enforcement submission.

#### Step 6: Highlight Privacy Mode & Field Encryption
- Navigate to: **`http://localhost:3001/privacy`**
- Demonstrate how employee PII (Bank account numbers, Aadhaar/SSN, emails, credit cards) is automatically masked prior to persistence and encrypted at rest with AES-256.

---

## 4. Frequently Asked Questions by Jury Panels

**Q1: How do you detect origin IP when attackers use proxy or VPN services?**
> *Answer:* We parse the entire RFC-5322 Received chain from innermost (origin MTA) to outermost (recipient boundary). Even when attackers proxy the web connection, the earliest trustworthy SMTP hop reveals the injection MTA. Furthermore, our IP intelligence engine explicitly flags Tor exit nodes, known VPN blocks, and bulletproof ASNs.

**Q2: What is your approach to handling privacy and compliance?**
> *Answer:* Traditional security solutions send raw email contents to remote cloud servers. PhishTrace implements edge-based PII regex masking before storing or indexing data, and sensitive database columns are encrypted with Fernet AES-256 keys managed locally.

**Q3: How does your social engineering detection differ from basic keyword filters?**
> *Answer:* Rather than searching for static words like "urgent", our model evaluates multi-label contextual vectors trained specifically on phishing datasets (`train.csv`), extracting structural and temporal urgency indicators alongside sender authority mismatches.

**Q4: Can this integrate with existing SOC tools like Splunk or Sentinel?**
> *Answer:* Yes. All forensic outputs are exposed via RESTful JSON endpoints (`/api/v1/email-scans/export/json`), following standard STIX/TAXII-compatible schemas for direct ingestion into enterprise SIEMs.
