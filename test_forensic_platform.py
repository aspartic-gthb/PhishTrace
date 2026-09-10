import sys, os
sys.path.append('backend')
sys.path.append('.')

import unittest
import json
from app.services.email_forensics import parse_raw_email_headers, calculate_auth_score
from app.services.ip_geolocation import geolocate_ip, evaluate_origin_mismatch
from app.services.dns_analysis import analyze_sender_domain_dns
from app.services.email_risk import fuse_email_risk_scores
from app.services.forensic_report import build_structured_forensic_report, generate_forensic_pdf, compute_evidence_hash
from app.database import SessionLocal
from app import models

class TestForensicPlatform(unittest.TestCase):

    def test_01_header_parser(self):
        raw = """From: "JPMorgan Chase Security" <alerts@chase.com>
To: victim@company.com
Reply-To: harvest@scammer-relay.xyz
Subject: Urgent Security Action Required: Unusual Activity Detected
Return-Path: <bounce@scammer-relay.xyz>
Message-ID: <threat-id-9988@scammer-relay.xyz>
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bounce@scammer-relay.xyz; dkim=fail; dmarc=fail
Received: from mail.scammer-relay.xyz (unknown [185.220.101.5]) by mx.google.com with ESMTPS; Wed, 10 Sep 2026 14:20:00 -0700
Received: from internal-node (unknown [192.168.1.10]) by mail.scammer-relay.xyz with HTTP; Wed, 10 Sep 2026 14:19:00 -0700

Please verify your credentials immediately."""

        parsed = parse_raw_email_headers(raw)
        self.assertEqual(parsed["origin_ip"], "185.220.101.5")
        self.assertTrue(parsed["reply_to_mismatch"])
        self.assertEqual(parsed["spf_status"], "FAIL")
        self.assertEqual(parsed["dmarc_status"], "FAIL")
        self.assertEqual(len(parsed["hop_details"]), 2)

        auth_score = calculate_auth_score(parsed)
        self.assertGreater(auth_score, 0.7)
        print("✓ Header Parser & Auth Scoring: PASS")

    def test_02_ip_geolocation_and_mismatch(self):
        geo = geolocate_ip("185.220.101.5")
        self.assertEqual(geo["country"], "Russia")
        self.assertEqual(geo["city"], "Moscow")

        mismatch = evaluate_origin_mismatch("chase.com", geo)
        self.assertTrue(mismatch["mismatch"])
        self.assertIn("JPMorgan Chase", mismatch["reason"])
        self.assertIn("Moscow, Russia", mismatch["reason"])

        # Test Indian domain with non-Indian source
        geo_ng = geolocate_ip("102.89.23.10")
        mismatch_in = evaluate_origin_mismatch("rvce.edu.in", geo_ng)
        self.assertTrue(mismatch_in["mismatch"])
        print("✓ IP Geolocation & Origin Mismatch Engine: PASS")

    def test_03_dns_whois_intelligence(self):
        dns_res = analyze_sender_domain_dns("paypal.com")
        self.assertTrue(dns_res["has_mx"])
        self.assertFalse(dns_res["is_lookalike"])

        dns_lookalike = analyze_sender_domain_dns("chase-online-login.xyz")
        self.assertTrue(dns_lookalike["is_lookalike"])
        print("✓ Thin DNS/WHOIS & Lookalike Detection: PASS")

    def test_04_forensic_risk_fusion(self):
        auth_fake = {
            "spf_status": "FAIL",
            "dkim_status": "FAIL",
            "dmarc_status": "FAIL",
            "dkim_aligned": False,
            "reply_to_mismatch": True,
            "reply_to": "attacker@evil.com"
        }
        dns_fake = {
            "has_mx": False,
            "has_spf": False,
            "has_dmarc": False,
            "is_fresh_domain": True,
            "domain_age_days": 3,
            "is_lookalike": True,
            "lookalike_reason": "Contains chase"
        }
        mismatch = {
            "mismatch": True,
            "reason": "Origin IP in Russia for US Bank"
        }
        signals = {
            "urgency": 0.95,
            "fear": 0.90,
            "authority": 0.92,
            "impersonation": 0.98
        }
        fused = fuse_email_risk_scores(
            ml_content_score=0.95,
            ml_signals=signals,
            auth_summary=auth_fake,
            dns_summary=dns_fake,
            impersonation_score=0.98,
            origin_mismatch=mismatch,
            email_context={"subject": "Wire Transfer", "text": "Pay now", "sender_domain": "chase-fake.xyz"}
        )
        self.assertEqual(fused["risk_level"], "CRITICAL")
        self.assertGreaterEqual(fused["final_email_score"], 0.88)
        print(f"✓ Forensic Risk Fusion: PASS (Score: {fused['final_email_score']*100:.1f}%)")

    def test_05_forensic_report_generation(self):
        sample_record = {
            "id": 999,
            "subject": "Wire Transfer Verification [PHONE_REDACTED]",
            "sender": "ceo@chase.com",
            "domain": "chase.com",
            "reply_to": "hacker@relay.ru",
            "reply_to_mismatch": True,
            "return_path": "bounce@relay.ru",
            "message_id": "<999@relay.ru>",
            "timestamp": "2026-09-10T14:00:00Z",
            "risk_score": 0.94,
            "risk_level": "CRITICAL",
            "category": "BUSINESS_EMAIL_COMPROMISE",
            "explanation": "Executive impersonation with origin mismatch.",
            "origin_ip": "185.220.101.5",
            "origin_country": "Russia",
            "origin_city": "Moscow",
            "origin_isp": "Tor Exit Router Network",
            "origin_asn": "AS208323",
            "geo_mismatch": 1,
            "geo_mismatch_reason": "Origin in Russia.",
            "spf_status": "FAIL",
            "dkim_status": "FAIL",
            "dkim_aligned": False,
            "dmarc_status": "FAIL",
            "domain_age": "28 Years",
            "domain_age_days": 10500,
            "whois_registrar": "CSC",
            "is_fresh_domain": False,
            "is_lookalike": False
        }
        rep = build_structured_forensic_report(sample_record)
        self.assertIn("report_metadata", rep)
        self.assertIn("evidence_sha256_hash", rep["report_metadata"])
        self.assertEqual(rep["report_metadata"]["compliance_safeguard"], "PII Masked (DPDP & GDPR Compliant Evidence Preservation)")

        pdf_bytes = generate_forensic_pdf(rep)
        self.assertGreater(len(pdf_bytes), 1000)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        print(f"✓ Forensic Report JSON & Signed PDF Export: PASS ({len(pdf_bytes)} bytes)")

    def test_06_suspicious_attachment_analysis(self):
        from app.services.email_forensics import assess_filename, extract_attachment_metadata
        
        att_double = assess_filename("Q3_Wire_Transfer_Form.pdf.exe")
        self.assertTrue(att_double["is_dangerous"])
        self.assertTrue(att_double["is_double_extension"])
        self.assertEqual(att_double["danger_category"], "DOUBLE_EXTENSION_SPOOF")

        att_macro = assess_filename("Fee_Payment_Voucher.docm")
        self.assertTrue(att_macro["is_dangerous"])
        self.assertEqual(att_macro["danger_category"], "MACRO_ENABLED_DOCUMENT")

        att_clean = assess_filename("Official_Report.pdf")
        self.assertFalse(att_clean["is_dangerous"])
        self.assertEqual(att_clean["danger_category"], "STANDARD_DOCUMENT")
        print("✓ Suspicious Attachment Forensics: PASS")

    def test_07_campaign_clustering(self):
        from app.routes.email_scans import get_email_campaigns
        import asyncio

        db = SessionLocal()
        async def run_camps():
            camps = await get_email_campaigns(db)
            self.assertGreaterEqual(len(camps), 1)
            first = camps[0]
            self.assertIn("campaign_id", first)
            self.assertIn("threat_actor_profile", first)
            self.assertGreaterEqual(first["incident_count"], 1)
            print(f"✓ Threat Campaign Clustering: PASS ({len(camps)} campaigns clustered)")
        
        asyncio.run(run_camps())
        db.close()

if __name__ == "__main__":
    unittest.main()
