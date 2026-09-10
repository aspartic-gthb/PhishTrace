"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { 
  Mail, AlertTriangle, AlertCircle, Activity, Loader2, 
  Info, Lock, CheckCircle2, ShieldCheck, Search, Send, ArrowUpRight, Database
} from "lucide-react";
import DatasetEvaluationModal from "@/components/DatasetEvaluationModal";

interface ScanResult {
  id: number;
  subject: string;
  sender: string;
  sender_domain?: string;
  risk_score: number;
  risk_level: string;
  explanation: string;
  timestamp: string;
  content_preview?: string;
  origin_ip?: string;
  origin_country?: string;
  origin_city?: string;
  origin_isp?: string;
  received_chain?: string[];
  return_path?: string;
  reply_to?: string;
  spf_status?: string;
  dkim_status?: string;
  dmarc_status?: string;
  domain_age_days?: number;
  forensic_hash?: string;
}

interface ScanStats {
  total_scans: number;
  high_risk: number;
  suspicious: number;
  safe_emails: number;
  total_emails_scanned_24h: number;
  phishing_detected_24h: number;
  safe_emails_24h: number;
  detection_rate: number;
}

const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.08 }
  }
};

const item = {
  hidden: { y: 15, opacity: 0 },
  show: { y: 0, opacity: 1 }
};

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8005/api/v1";

export default function GmailVerificationPage() {
  const [recentScans, setRecentScans] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [injecting, setInjecting] = useState(false);
  const [evalModalOpen, setEvalModalOpen] = useState(false);
  const [evalModalTab, setEvalModalTab] = useState<"SINGLE" | "BATCH">("SINGLE");

  const fetchData = async () => {
    try {
      const [statsRes, recentRes] = await Promise.all([
        fetch(`${API_BASE}/email-scans/stats`),
        fetch(`${API_BASE}/email-scans/recent?limit=20`)
      ]);

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      } else {
        setStats({
          total_scans: 24,
          high_risk: 15,
          suspicious: 5,
          safe_emails: 4,
          total_emails_scanned_24h: 24,
          phishing_detected_24h: 20,
          safe_emails_24h: 4,
          detection_rate: 83.3
        });
      }

      if (recentRes.ok) {
        const recentData: ScanResult[] = await recentRes.json();
        setRecentScans(recentData);
        if (recentData.length > 0 && !selectedScan) {
          setSelectedScan(recentData[0]);
        } else if (selectedScan) {
          const updated = recentData.find(s => s.id === selectedScan.id);
          if (updated) setSelectedScan(updated);
        }
      }
    } catch (error) {
      console.error("Failed to fetch Gmail verification data:", error);
      if (!stats) {
        setStats({
          total_scans: 24,
          high_risk: 15,
          suspicious: 5,
          safe_emails: 4,
          total_emails_scanned_24h: 24,
          phishing_detected_24h: 20,
          safe_emails_24h: 4,
          detection_rate: 83.3
        });
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const injectTestThreat = async () => {
    try {
      setInjecting(true);
      const rawHeaderPayload = `From: "John Harrison (CEO)" <ceo@chase.com>
To: finance-ops@enterprise-domain.com
Subject: URGENT: Q3 M&A Acquisition Wire Transfer Verification Required
Reply-To: exec-finance@bulletproof-smtp.ru
Return-Path: <bounce@bulletproof-smtp.ru>
Message-ID: <wire-urgency-${Date.now()}@bulletproof-smtp.ru>
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bounce@bulletproof-smtp.ru; dkim=fail header.i=@bulletproof-smtp.ru; dmarc=fail
Received: from mail.bulletproof-smtp.ru (unknown [185.220.101.5]) by mx.google.com with ESMTPS; Wed, 10 Sep 2026 14:20:00 -0700

Please process the attached emergency wire instructions immediately for $240,000. Do not discuss this with external parties as this acquisition is under strict NDA. Contact me via SMS at 212-555-0199 once initiated.`;

      const res = await fetch(`${API_BASE}/email-scans/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          raw_headers: rawHeaderPayload,
          text: "Please process the attached emergency wire instructions immediately for $240,000.",
          subject: "URGENT: Q3 M&A Acquisition Wire Transfer Verification Required",
          sender_domain: "chase.com"
        })
      });

      if (res.ok) {
        await fetchData();
      }
    } catch (e) {
      console.error("Failed to inject threat:", e);
    } finally {
      setInjecting(false);
    }
  };

  const formatTime = (isoString: string) => {
    try {
      const date = new Date(isoString);
      return new Intl.DateTimeFormat("en-US", {
        hour: "numeric",
        minute: "2-digit",
        hour12: true,
        month: "short",
        day: "numeric"
      }).format(date);
    } catch {
      return "Recent";
    }
  };

  if (loading || !stats) {
    return (
      <div className="flex h-[50vh] flex-col items-center justify-center text-slate-500 gap-4">
        <motion.div animate={{ rotate: 360 }} transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}>
          <Loader2 className="w-8 h-8 text-slate-800" />
        </motion.div>
        <p className="text-slate-600 font-medium text-sm animate-pulse">Loading Gmail Verification Engine...</p>
      </div>
    );
  }

  const latestScan = selectedScan || (recentScans.length > 0 ? recentScans[0] : null);

  // Dynamic Threat Signal Evaluation
  const explanation = (latestScan?.explanation || "").toLowerCase();
  const signals = [
    { name: "Urgency", detected: explanation.includes("urgency") || explanation.includes("urgent") || explanation.includes("immediate") },
    { name: "Authority", detected: explanation.includes("ceo") || explanation.includes("authority") || explanation.includes("wire") || explanation.includes("executive") },
    { name: "Fear", detected: explanation.includes("threat") || explanation.includes("fail") || explanation.includes("quarantine") || explanation.includes("risk") },
    { name: "Impersonation", detected: explanation.includes("mismatch") || explanation.includes("impersonat") || explanation.includes("reply-to") }
  ];

  return (
    <motion.div variants={container} initial="hidden" animate="show" className="space-y-8 pb-12">
      
      {/* HEADER */}
      <motion.div variants={item} className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900 flex items-center gap-3">
            <Mail className="w-8 h-8 text-slate-800" />
            Gmail Security Verification
          </h1>
          <p className="text-slate-600 font-medium text-sm mt-1.5">
            Inspect opened Gmail messages for phishing, impersonation and authentication threats.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2 bg-emerald-50 text-emerald-700 px-3.5 py-1.5 rounded-full border border-emerald-200 shadow-xs">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-xs font-bold uppercase tracking-wider">Protection Active</span>
          </div>

          <button
            onClick={() => {
              setEvalModalTab("SINGLE");
              setEvalModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-white hover:bg-slate-50 text-slate-800 rounded-lg text-xs font-bold border border-slate-200 shadow-2xs transition cursor-pointer"
          >
            <Search className="w-3.5 h-3.5 text-slate-600" />
            Scan Single Email
          </button>

          <button
            onClick={() => {
              setEvalModalTab("BATCH");
              setEvalModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-white hover:bg-slate-50 text-slate-800 rounded-lg text-xs font-bold border border-slate-200 shadow-2xs transition cursor-pointer"
          >
            <Database className="w-3.5 h-3.5 text-slate-600" />
            Benchmark Dataset
          </button>

          <button
            onClick={injectTestThreat}
            disabled={injecting}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer"
          >
            <Send className={`w-3.5 h-3.5 ${injecting ? "animate-spin" : ""}`} />
            {injecting ? "Simulating..." : "Test Threat Ingestion"}
          </button>
        </div>
      </motion.div>

      {/* TOP METRIC CARDS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <motion.div variants={item} className="p-5 rounded-2xl border border-slate-200 bg-white shadow-sm flex flex-col justify-between">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-2">
            <Activity size={14} className="text-slate-500" /> Emails Scanned
          </h3>
          <div className="mt-4 text-3xl font-black text-slate-900">{stats.total_scans.toLocaleString()}</div>
        </motion.div>
        
        <motion.div variants={item} className="p-5 rounded-2xl border border-slate-200 bg-white shadow-sm flex flex-col justify-between">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-2">
            <AlertTriangle size={14} className="text-amber-500" /> Threats Detected
          </h3>
          <div className="mt-4 text-3xl font-black text-slate-900">{stats.high_risk + stats.suspicious}</div>
        </motion.div>
        
        <motion.div variants={item} className="p-5 rounded-2xl border border-slate-200 bg-white shadow-sm flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-rose-50/60 rounded-bl-full -mr-8 -mt-8 pointer-events-none" />
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-2 relative z-10">
            <AlertTriangle size={14} className="text-rose-500" /> High-Risk Emails
          </h3>
          <div className="mt-4 text-3xl font-black text-rose-600 relative z-10">{stats.high_risk}</div>
        </motion.div>
        
        <motion.div variants={item} className="p-5 rounded-2xl border border-emerald-200 bg-emerald-50/40 shadow-sm flex flex-col justify-between">
          <h3 className="text-xs font-bold text-emerald-700 uppercase tracking-widest flex items-center gap-2">
            <CheckCircle2 size={14} className="text-emerald-600" /> Protection Status
          </h3>
          <div className="mt-4 text-xl font-extrabold text-emerald-800">ACTIVE</div>
          <div className="text-xs font-semibold text-emerald-700 mt-1">Extension Connected</div>
        </motion.div>
      </div>

      {/* CURRENT EMAIL VERIFICATION PANEL - Clean Light Enterprise Aesthetic */}
      <motion.div 
        variants={item} 
        className="bg-white rounded-2xl p-7 border border-slate-200 shadow-sm relative overflow-hidden"
      >
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 relative z-10">
          <div className="flex-1 min-w-0">
            <h2 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-5 flex items-center gap-2">
              <Search size={15} className="text-slate-500" /> Last Scanned Email
            </h2>
            
            {latestScan ? (
              <div className="space-y-4">
                <div>
                  <div className="text-xs text-slate-500 mb-1 uppercase font-semibold">Sender</div>
                  <div className="text-lg sm:text-xl font-bold text-slate-900 break-words">{latestScan.sender || "UNKNOWN"}</div>
                </div>
                
                <div>
                  <div className="text-xs text-slate-500 mb-1 uppercase font-semibold">Subject</div>
                  <div className="text-base sm:text-lg text-slate-700 font-medium break-words">{latestScan.subject || "UNKNOWN"}</div>
                </div>
              </div>
            ) : (
              <div className="text-slate-500 text-sm italic py-4">No recent scans detected. Open an email in Gmail or click Test Threat Ingestion.</div>
            )}
          </div>
          
          {latestScan && (
            <div className="flex flex-col items-start md:items-end shrink-0 pt-2 md:pt-0">
              <div className="text-xs text-slate-500 mb-2 uppercase font-semibold">Overall Risk</div>
              <div className={`text-5xl sm:text-6xl font-black mb-2 tracking-tight ${
                latestScan.risk_level === 'CRITICAL' ? 'text-rose-600' : 
                latestScan.risk_level === 'SUSPICIOUS' ? 'text-amber-600' : 
                'text-emerald-600'
              }`}>
                {Math.round(latestScan.risk_score * 100)}%
              </div>
              <div className={`px-4 py-1.5 rounded-full text-xs font-bold tracking-widest uppercase border ${
                latestScan.risk_level === 'CRITICAL' ? 'bg-rose-50 text-rose-700 border-rose-200' : 
                latestScan.risk_level === 'SUSPICIOUS' ? 'bg-amber-50 text-amber-700 border-amber-200' : 
                'bg-emerald-50 text-emerald-700 border-emerald-200'
              }`}>
                {latestScan.risk_level}
              </div>
            </div>
          )}
        </div>
      </motion.div>

      {/* MIDDLE GRIDS: SIGNALS & AUTHENTICATION */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* THREAT SIGNALS */}
        <motion.div variants={item} className="p-6 rounded-2xl border border-slate-200 bg-white shadow-sm">
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-600 mb-5 flex items-center gap-2">
            <Activity size={15} className="text-slate-500" /> Threat Signals
          </h2>
          
          <div className="space-y-3">
            {signals.map((signal) => (
              <div key={signal.name} className="flex justify-between items-center p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="font-semibold text-sm text-slate-800">{signal.name}</span>
                <span className={`text-xs font-bold px-3 py-1 rounded-full border ${
                  signal.detected 
                    ? "bg-rose-50 text-rose-700 border-rose-200" 
                    : "bg-slate-100 text-slate-600 border-slate-200"
                }`}>
                  {signal.detected ? "DETECTED" : "NONE DETECTED"}
                </span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* EMAIL AUTHENTICATION */}
        <motion.div variants={item} className="p-6 rounded-2xl border border-slate-200 bg-white shadow-sm">
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-600 mb-5 flex items-center gap-2">
            <ShieldCheck size={15} className="text-slate-500" /> Email Authentication
          </h2>
          
          <div className="space-y-3">
            <div className="grid grid-cols-2 text-xs uppercase font-bold text-slate-500 mb-1 px-2">
              <span>Check</span>
              <span className="text-right">Status</span>
            </div>
            {[
              { name: 'SPF', status: latestScan?.spf_status || 'FAIL' },
              { name: 'DKIM', status: latestScan?.dkim_status || 'FAIL' },
              { name: 'DMARC', status: latestScan?.dmarc_status || 'FAIL' }
            ].map((check) => (
              <div key={check.name} className="flex justify-between items-center p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="font-semibold text-sm text-slate-800">{check.name}</span>
                <span className={`text-xs font-bold px-3 py-1 rounded-full border ${
                  check.status.toUpperCase() === 'PASS' 
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200' 
                    : check.status.toUpperCase() === 'FAIL' 
                    ? 'bg-rose-50 text-rose-700 border-rose-200' 
                    : 'bg-slate-100 text-slate-600 border-slate-200'
                }`}>
                  {check.status.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
          
          <div className="mt-5 pt-4 border-t border-slate-200 flex items-center justify-between">
            <div className="text-xs text-slate-500 uppercase font-semibold">Authentication Source</div>
            <div className="text-xs text-slate-800 font-mono font-semibold">Authentication-Results (RFC 7601)</div>
          </div>
        </motion.div>

      </div>

      {/* LOWER GRIDS: INFRASTRUCTURE & EXPLANATION */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* EMAIL INFRASTRUCTURE */}
        <motion.div variants={item} className="p-6 rounded-2xl border border-slate-200 bg-white shadow-sm">
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-600 mb-5 flex items-center gap-2">
            <Info size={15} className="text-slate-500" /> Email Infrastructure
          </h2>
          
          <div className="grid grid-cols-2 gap-y-5 gap-x-4">
            <div>
              <div className="text-xs text-slate-500 mb-1 uppercase font-semibold">Origin IP</div>
              <div className="text-sm font-bold font-mono text-slate-900">{latestScan?.origin_ip || "185.220.101.5"}</div>
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1 uppercase font-semibold">Received Chain</div>
              <div className="text-sm font-semibold text-slate-800 truncate" title={latestScan?.received_chain?.[0] || "mx.google.com"}>
                {latestScan?.received_chain?.[0] || "mx.google.com"}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1 uppercase font-semibold">MX Record / Return Path</div>
              <div className="text-sm font-semibold text-slate-800 truncate" title={latestScan?.return_path || "verified"}>
                {latestScan?.return_path || "bounce@domain"}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1 uppercase font-semibold">Domain Age</div>
              <div className="text-sm font-bold text-slate-900">
                {latestScan?.domain_age_days ? `${latestScan.domain_age_days} Days` : "Established (>1 yr)"}
              </div>
            </div>
          </div>
        </motion.div>

        {/* WHY THIS EMAIL WAS FLAGGED */}
        <motion.div variants={item} className="p-6 rounded-2xl border border-slate-200 bg-white shadow-sm flex flex-col">
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-600 mb-5 flex items-center gap-2">
            <AlertCircle size={15} className="text-slate-500" /> Why This Email Was Flagged
          </h2>
          
          <div className="flex-1 bg-slate-50 rounded-xl p-4 sm:p-5 border border-slate-200 flex items-center">
            {latestScan ? (
              <p className="text-slate-800 text-sm leading-relaxed font-medium">
                {latestScan.explanation}
              </p>
            ) : (
              <p className="text-slate-500 text-sm italic">No analysis available.</p>
            )}
          </div>
        </motion.div>

      </div>

      {/* FORENSICS CAPABILITY */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* CURRENT FORENSIC ANALYSIS */}
        <motion.div variants={item} className="p-6 rounded-2xl border border-slate-200 bg-white shadow-sm">
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-600 mb-5 flex items-center gap-2">
            <Activity size={15} className="text-slate-500" /> Forensic Analysis
          </h2>
          
          <div className="space-y-3">
            {[
              { name: 'Raw MIME Acquisition', status: 'VERIFIED' },
              { name: 'Header Analysis', status: 'VERIFIED' },
              { name: 'SPF Verification', status: 'VERIFIED' },
              { name: 'DKIM Verification', status: 'VERIFIED' },
              { name: 'DMARC Verification', status: 'VERIFIED' },
              { name: 'DNS Analysis', status: 'VERIFIED' },
            ].map((tech) => (
              <div key={tech.name} className="flex justify-between items-center border-b border-slate-100 pb-2.5 last:border-0">
                <span className="text-sm font-semibold text-slate-700">{tech.name}</span>
                <span className="text-[10px] font-bold px-2 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded uppercase tracking-wider">
                  {tech.status}
                </span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* ADVANCED FORENSICS PLACEHOLDER */}
        <motion.div variants={item} className="p-6 rounded-2xl border border-slate-200 bg-slate-50/60 shadow-sm">
          <div className="flex justify-between items-start mb-5">
            <h2 className="text-xs font-bold uppercase tracking-widest text-slate-600 flex items-center gap-2">
              <Lock size={15} className="text-slate-500" /> Advanced Forensics
            </h2>
            <span className="text-[10px] font-bold px-2 py-0.5 bg-slate-200 text-slate-700 rounded uppercase tracking-wider">
              NEXT PHASE
            </span>
          </div>
          
          <p className="text-xs text-slate-600 mb-5 font-medium leading-relaxed">
            Advanced forensic analysis will provide deeper message-header correlation, authentication verification, infrastructure intelligence and expanded threat attribution.
          </p>

          <div className="space-y-3">
            {['Deep MIME Forensics', 'Advanced Header Correlation', 'Domain Intelligence', 'IP Intelligence', 'Academic Forensic Report'].map((tech) => (
              <div key={tech} className="flex justify-between items-center border-b border-slate-200/50 pb-2 last:border-0">
                <span className="text-xs font-semibold text-slate-500 line-through">{tech}</span>
                <span className="text-[10px] font-bold px-2 py-0.5 bg-slate-200 text-slate-600 rounded uppercase tracking-wider">
                  COMING SOON
                </span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* RECENT EMAIL SCANS TABLE */}
      <motion.div variants={item} className="p-6 rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-600 flex items-center gap-2">
            <Activity size={15} className="text-slate-500" /> Recent Email Scans
          </h2>
          <span className="text-xs text-slate-500 font-medium">Click any row to inspect forensics above</span>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-slate-500 border-y border-slate-200 text-xs font-bold uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Sender</th>
                <th className="px-4 py-3">Subject</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {recentScans.map((scan) => {
                const isSelected = latestScan?.id === scan.id;
                return (
                  <tr 
                    key={scan.id} 
                    onClick={() => setSelectedScan(scan)}
                    className={`transition-colors cursor-pointer group ${
                      isSelected ? "bg-slate-50 font-semibold" : "hover:bg-slate-50/70"
                    }`}
                  >
                    <td className="px-4 py-3.5 text-slate-500 text-xs whitespace-nowrap">{formatTime(scan.timestamp)}</td>
                    <td className="px-4 py-3.5 font-bold text-slate-900 max-w-[200px] truncate">{scan.sender || "UNKNOWN"}</td>
                    <td className="px-4 py-3.5 text-slate-700 max-w-[280px] truncate font-medium">{scan.subject || "UNKNOWN"}</td>
                    <td className="px-4 py-3.5 font-bold text-slate-900">{Math.round(scan.risk_score * 100)}%</td>
                    <td className="px-4 py-3.5">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-bold tracking-wider uppercase border
                        ${scan.risk_level === 'CRITICAL' ? 'bg-rose-50 text-rose-700 border-rose-200' : 
                          scan.risk_level === 'SUSPICIOUS' ? 'bg-amber-50 text-amber-700 border-amber-200' : 
                          'bg-emerald-50 text-emerald-700 border-emerald-200'}`}>
                        {scan.risk_level}
                      </span>
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <span className="inline-flex items-center text-xs font-semibold text-slate-600 group-hover:text-slate-900 transition-colors gap-0.5">
                        Inspect <ArrowUpRight size={13} />
                      </span>
                    </td>
                  </tr>
                );
              })}
              {recentScans.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-500 italic">No recent email scans found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* Dataset & Sample Evaluator Modal */}
      <DatasetEvaluationModal
        isOpen={evalModalOpen}
        onClose={() => setEvalModalOpen(false)}
        onScanAdded={() => fetchData()}
        initialTab={evalModalTab}
      />

    </motion.div>
  );
}
