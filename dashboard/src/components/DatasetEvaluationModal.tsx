"use client";

import React, { useState } from "react";
import { 
  X, Play, CheckCircle2, AlertTriangle, 
  BarChart2, FileText, Loader2, Database, FileSpreadsheet
} from "lucide-react";

interface DatasetEvaluationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanAdded?: () => void;
  initialTab?: "SINGLE" | "BATCH";
}

interface BenchmarkMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
}

interface BenchmarkResult {
  dataset_name: string;
  total_samples: number;
  critical_count: number;
  suspicious_count: number;
  safe_count: number;
  avg_urgency: number;
  avg_authority: number;
  avg_fear: number;
  avg_impersonation: number;
  metrics: Record<string, BenchmarkMetrics>;
  sample_preview: Array<{
    text: string;
    risk_score: number;
    risk_level: string;
    urgency: number;
    authority: number;
    fear: number;
    impersonation: number;
  }>;
}

const PRESET_SAMPLES = [
  {
    name: "BEC CEO Wire Fraud (Critical Threat)",
    domain: "chase.com",
    sender: '"John Harrison (CEO)" <ceo@chase.com>',
    subject: "URGENT: Q3 M&A Acquisition Wire Transfer Verification Required",
    body: "Please process the attached emergency wire instructions immediately for $240,000. Do not discuss this with external parties as this acquisition is under strict NDA. Contact me via SMS once initiated.",
    headers: `From: "John Harrison (CEO)" <ceo@chase.com>
To: finance-ops@enterprise-domain.com
Subject: URGENT: Q3 M&A Acquisition Wire Transfer Verification Required
Reply-To: exec-finance@bulletproof-smtp.ru
Return-Path: <bounce@bulletproof-smtp.ru>
Message-ID: <wire-urgency-${Date.now()}@bulletproof-smtp.ru>
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bounce@bulletproof-smtp.ru; dkim=fail header.i=@bulletproof-smtp.ru; dmarc=fail
Received: from mail.bulletproof-smtp.ru (unknown [185.220.101.5]) by mx.google.com with ESMTPS; Wed, 10 Sep 2026 14:20:00 -0700`
  },
  {
    name: "Credential Harvesting (PayPal Impersonation)",
    domain: "paypal.com",
    sender: "PayPal Security Team <security-notice@service-paypal-verify.com>",
    subject: "Important: Your account has been temporarily restricted",
    body: "We detected unauthorized login attempts from a new IP address. To restore full access, you must verify your identity and update payment methods within 12 hours, or your account will be permanently locked.",
    headers: `From: "PayPal Security" <security-notice@service-paypal-verify.com>
To: target-user@domain.com
Subject: Important: Your account has been temporarily restricted
Reply-To: phish-collector@disposable-inbox.net
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Received: from mx.disposable-inbox.net (unknown [194.26.29.1]) by mx.google.com with ESMTPS`
  },
  {
    name: "Legitimate Corporate Sync (Benign / Safe)",
    domain: "acme-corp.com",
    sender: "Sarah Jenkins <sjenkins@acme-corp.com>",
    subject: "Weekly Operations Review - Agenda & Slides attached",
    body: "Hi Team, here is the agenda for our upcoming Friday sync. Please review the attached slide deck and let me know if you have any updates to the pipeline before our team meeting.",
    headers: `From: "Sarah Jenkins" <sjenkins@acme-corp.com>
To: team@acme-corp.com
Subject: Weekly Operations Review - Agenda & Slides attached
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
Received: from mail-relay.google.com (mail-relay.google.com [142.250.100.1]) by mx.google.com with ESMTPS`
  },
  {
    name: "Infosys HR Payroll Phish (.EML with Executable)",
    domain: "infosys.com",
    sender: '"Priya Sharma (Director HR)" <priya.sharma@infosys.com>',
    subject: "CRITICAL: Immediate Action Required - Updated Q3 Compensation Confirmation",
    body: `Dear Employee,\n\nOur biometric payroll processing server detected an irregular discrepancy in your employee direct deposit routing credentials.\n\nFailure to verify your banking information within 2 hours will result in automatic withholding of your Q3 compensation cycle.\n\nPlease review the attached document immediately:\nhttps://portal-infosys-employee-verify.com/login`,
    headers: `From: "Priya Sharma (Director HR)" <priya.sharma@infosys.com>
To: target-employee@enterprise-org.in
Subject: CRITICAL: Immediate Action Required - Updated Q3 Compensation Confirmation
Date: Wed, 10 Sep 2026 14:15:32 +0530
Message-ID: <payroll-override-98234@darknet-mailer-09.ru>
Reply-To: security-override@darknet-mailer-09.ru
Return-Path: <bounce@darknet-mailer-09.ru>
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bounce@darknet-mailer-09.ru; dkim=fail header.i=@darknet-mailer-09.ru; dmarc=fail header.from=infosys.com
Received: from mail.darknet-mailer-09.ru (unknown [185.220.101.5]) by mx.google.com with ESMTPS
Content-Type: multipart/mixed; boundary="----=_Part_98234_18923482"`
  }
];

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8005/api/v1";

export default function DatasetEvaluationModal({ isOpen, onClose, onScanAdded, initialTab = "SINGLE" }: DatasetEvaluationModalProps) {
  const [activeTab, setActiveTab] = useState<"SINGLE" | "BATCH">(initialTab);

  React.useEffect(() => {
    if (isOpen) {
      setActiveTab(initialTab);
    }
  }, [isOpen, initialTab]);

  // Single sample form state
  const [sender, setSender] = useState(PRESET_SAMPLES[0].sender);
  const [subject, setSubject] = useState(PRESET_SAMPLES[0].subject);
  const [domain, setDomain] = useState(PRESET_SAMPLES[0].domain);
  const [bodyText, setBodyText] = useState(PRESET_SAMPLES[0].body);
  const [headers, setHeaders] = useState(PRESET_SAMPLES[0].headers);
  const [emlFileName, setEmlFileName] = useState<string | null>(null);
  const [analyzingSingle, setAnalyzingSingle] = useState(false);
  const [singleSuccess, setSingleSuccess] = useState<string | null>(null);

  const parseEmlString = (emlText: string) => {
    const parts = emlText.split(/\r?\n\r?\n/);
    const headerSection = parts[0] || "";
    const bodySection = parts.slice(1).join("\n\n") || "";

    let parsedSubject = "";
    let parsedSender = "";
    let parsedDomain = "";

    const lines = headerSection.split(/\r?\n/);
    for (const line of lines) {
      if (line.toLowerCase().startsWith("subject:")) {
        parsedSubject = line.substring(8).trim();
      } else if (line.toLowerCase().startsWith("from:")) {
        parsedSender = line.substring(5).trim();
        const atIdx = parsedSender.lastIndexOf("@");
        if (atIdx !== -1) {
          parsedDomain = parsedSender.substring(atIdx + 1).replace(/[>\]\s]/g, "");
        }
      }
    }

    setHeaders(headerSection);
    if (parsedSubject) setSubject(parsedSubject);
    if (parsedSender) setSender(parsedSender);
    if (parsedDomain) setDomain(parsedDomain);
    if (bodySection) setBodyText(bodySection);
  };

  const handleEmlFileSelect = async (file: File) => {
    try {
      const text = await file.text();
      parseEmlString(text);
      setEmlFileName(file.name);
      setSingleSuccess(`Successfully loaded ${file.name} (${(file.size / 1024).toFixed(1)} KB). Ready for analysis.`);
    } catch (e) {
      console.error("Error reading EML file:", e);
      setSingleSuccess("Failed to read .EML file.");
    }
  };

  // Batch evaluation state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [evaluatingBatch, setEvaluatingBatch] = useState(false);
  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkResult | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSelectPreset = (preset: typeof PRESET_SAMPLES[0]) => {
    setSender(preset.sender);
    setSubject(preset.subject);
    setDomain(preset.domain);
    setBodyText(preset.body);
    setHeaders(preset.headers);
    setSingleSuccess(null);
  };

  const handleAnalyzeSingle = async () => {
    try {
      setAnalyzingSingle(true);
      setSingleSuccess(null);

      const res = await fetch(`${API_BASE}/email-scans/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          raw_headers: headers,
          text: bodyText,
          subject: subject,
          sender_domain: domain
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSingleSuccess(`Scan complete! Risk: ${Math.round(data.risk_score * 100)}% (${data.risk_level}). Added to Live Feed.`);
        if (onScanAdded) onScanAdded();
      } else {
        setSingleSuccess("Failed to complete scan. Please verify backend status.");
      }
    } catch (err) {
      console.error("Single scan error:", err);
      setSingleSuccess("Network error: Could not reach forensic backend.");
    } finally {
      setAnalyzingSingle(false);
    }
  };

  const handleRunBenchmark = async (useDefault = false) => {
    try {
      setEvaluatingBatch(true);
      setBatchError(null);
      setBenchmarkResult(null);

      let payload: Record<string, string> = {};

      if (!useDefault && selectedFile) {
        const fileContent = await selectedFile.text();
        payload = {
          csv_content: fileContent,
          filename: selectedFile.name
        };
      }

      const res = await fetch(`${API_BASE}/email-scans/evaluate-dataset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        const data: BenchmarkResult = await res.json();
        setBenchmarkResult(data);
      } else {
        const errData = await res.json().catch(() => ({ detail: "Evaluation failed" }));
        setBatchError(errData.detail || "Error evaluating dataset.");
      }
    } catch (err) {
      console.error("Batch evaluation error:", err);
      setBatchError("Network error: Could not evaluate dataset.");
    } finally {
      setEvaluatingBatch(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
      <div className="bg-white rounded-2xl border border-slate-200 shadow-xl max-w-4xl w-full max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        
        {/* MODAL HEADER */}
        <div className="p-5 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-slate-900 text-white shadow-xs">
                <Database size={16} />
              </span>
              <h2 className="text-base font-bold text-slate-900">
                Dataset & Custom Sample Evaluator
              </h2>
            </div>
            <p className="text-xs text-slate-500 mt-1 font-medium">
              Test external datasets (Kaggle, Nazario, Enron) or inspect custom raw email headers against the forensic ML models.
            </p>
          </div>
          
          <button 
            onClick={onClose}
            className="w-8 h-8 rounded-lg hover:bg-slate-200 text-slate-500 hover:text-slate-800 flex items-center justify-center transition cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        {/* TAB SWITCHER */}
        <div className="flex border-b border-slate-200 px-5 pt-3 bg-white gap-3">
          <button
            onClick={() => setActiveTab("SINGLE")}
            className={`pb-3 text-xs font-bold uppercase tracking-wider border-b-2 transition flex items-center gap-2 cursor-pointer ${
              activeTab === "SINGLE"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700"
            }`}
          >
            <FileText size={15} />
            Test Custom Email / Raw Headers
          </button>

          <button
            onClick={() => setActiveTab("BATCH")}
            className={`pb-3 text-xs font-bold uppercase tracking-wider border-b-2 transition flex items-center gap-2 cursor-pointer ${
              activeTab === "BATCH"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700"
            }`}
          >
            <BarChart2 size={15} />
            Batch CSV Dataset Benchmark
          </button>
        </div>

        {/* MODAL BODY */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6">
          
          {/* TAB 1: SINGLE SAMPLE TESTER */}
          {activeTab === "SINGLE" && (
            <div className="space-y-5">

              {/* EML File Upload Dropzone */}
              <div className="p-4 border-2 border-dashed border-slate-200 hover:border-slate-400 rounded-xl bg-slate-50/70 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs transition">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-white border border-slate-200 text-slate-700 shadow-2xs">
                    <FileText size={20} />
                  </div>
                  <div className="text-left">
                    <div className="font-bold text-slate-900">
                      {emlFileName ? `Loaded: ${emlFileName}` : "Upload or Drop a Single .EML File"}
                    </div>
                    <div className="text-[11px] text-slate-500 font-medium">
                      Select any raw .eml export (e.g. from Gmail, Outlook, or Thunderbird).
                    </div>
                  </div>
                </div>

                <label className="px-3.5 py-1.5 bg-white hover:bg-slate-50 text-slate-800 text-xs font-bold rounded-lg border border-slate-200 shadow-2xs transition cursor-pointer shrink-0">
                  <input
                    type="file"
                    accept=".eml, .txt, .msg"
                    className="hidden"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        handleEmlFileSelect(e.target.files[0]);
                      }
                    }}
                  />
                  Browse .EML File
                </label>
              </div>
              
              {/* Preset Selector */}
              <div>
                <label className="text-xs font-bold uppercase tracking-wider text-slate-600 block mb-2">
                  Or Load Pre-Configured Benchmark Samples
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                  {PRESET_SAMPLES.map((preset, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSelectPreset(preset)}
                      className={`p-2.5 rounded-xl border text-left text-xs transition cursor-pointer ${
                        subject === preset.subject
                          ? "bg-slate-100 border-slate-400 font-semibold text-slate-900 shadow-2xs"
                          : "bg-white border-slate-200 text-slate-600 hover:bg-slate-50"
                      }`}
                    >
                      <div className="font-bold truncate">{preset.name}</div>
                      <div className="text-[10px] text-slate-400 truncate mt-0.5">{preset.domain}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Form Fields */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-bold text-slate-600 uppercase tracking-wider block mb-1">
                    Sender
                  </label>
                  <input
                    type="text"
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs text-slate-900 focus:outline-none focus:border-slate-400 font-medium"
                  />
                </div>

                <div>
                  <label className="text-xs font-bold text-slate-600 uppercase tracking-wider block mb-1">
                    Claimed Domain
                  </label>
                  <input
                    type="text"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs text-slate-900 focus:outline-none focus:border-slate-400 font-medium"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-bold text-slate-600 uppercase tracking-wider block mb-1">
                  Subject Line
                </label>
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs text-slate-900 focus:outline-none focus:border-slate-400 font-medium"
                />
              </div>

              <div>
                <label className="text-xs font-bold text-slate-600 uppercase tracking-wider block mb-1">
                  Email Body Content
                </label>
                <textarea
                  rows={3}
                  value={bodyText}
                  onChange={(e) => setBodyText(e.target.value)}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs text-slate-900 focus:outline-none focus:border-slate-400 font-medium"
                />
              </div>

              <div>
                <label className="text-xs font-bold text-slate-600 uppercase tracking-wider block mb-1">
                  Raw RFC 5322 MIME Headers (Optional, for Deep Forensics)
                </label>
                <textarea
                  rows={4}
                  value={headers}
                  onChange={(e) => setHeaders(e.target.value)}
                  placeholder="From: ...\nTo: ...\nAuthentication-Results: ...\nReceived: from ... by ..."
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-mono text-[11px] text-slate-800 focus:outline-none focus:border-slate-400"
                />
              </div>

              {/* Status Alert */}
              {singleSuccess && (
                <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 font-medium flex items-center gap-2">
                  <CheckCircle2 size={16} className="text-emerald-600 shrink-0" />
                  <span>{singleSuccess}</span>
                </div>
              )}

              {/* Action Button */}
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-700 rounded-lg text-xs font-semibold border border-slate-200 transition cursor-pointer"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={handleAnalyzeSingle}
                  disabled={analyzingSingle}
                  className="flex items-center gap-2 px-5 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-bold shadow-xs transition cursor-pointer disabled:opacity-50"
                >
                  {analyzingSingle ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                  {analyzingSingle ? "Running Forensic Engine..." : "Analyze & Add to Live Feed"}
                </button>
              </div>

            </div>
          )}

          {/* TAB 2: BATCH CSV DATASET BENCHMARK */}
          {activeTab === "BATCH" && (
            <div className="space-y-6">
              
              {/* File Upload Zone */}
              <div className="p-6 border-2 border-dashed border-slate-200 hover:border-slate-400 rounded-2xl bg-slate-50/50 flex flex-col items-center justify-center text-center transition">
                <FileSpreadsheet className="w-10 h-10 text-slate-400 mb-2" />
                <h3 className="text-sm font-bold text-slate-800">
                  {selectedFile ? selectedFile.name : "Select or Drop a CSV Dataset"}
                </h3>
                <p className="text-xs text-slate-500 mt-1 max-w-sm">
                  Upload any Kaggle, Nazario, or custom CSV file. The model will automatically classify social engineering threats and calculate metrics.
                </p>

                <div className="mt-4 flex items-center gap-3">
                  <label className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-800 text-xs font-bold rounded-lg border border-slate-200 shadow-2xs transition cursor-pointer">
                    <input
                      type="file"
                      accept=".csv"
                      className="hidden"
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          setSelectedFile(e.target.files[0]);
                          setBenchmarkResult(null);
                        }
                      }}
                    />
                    Browse CSV File
                  </label>

                  <span className="text-xs text-slate-400 font-semibold">or</span>

                  <button
                    type="button"
                    onClick={() => handleRunBenchmark(true)}
                    disabled={evaluatingBatch}
                    className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold rounded-lg shadow-xs transition cursor-pointer disabled:opacity-50"
                  >
                    Benchmark Built-in Dataset (train.csv)
                  </button>
                </div>
              </div>

              {selectedFile && (
                <div className="flex items-center justify-between p-3.5 bg-slate-100 rounded-xl border border-slate-200">
                  <div className="flex items-center gap-2.5 text-xs text-slate-800 font-medium">
                    <FileText size={16} className="text-slate-600" />
                    <span>Selected: <strong>{selectedFile.name}</strong> ({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                  </div>
                  <button
                    onClick={() => handleRunBenchmark(false)}
                    disabled={evaluatingBatch}
                    className="flex items-center gap-1.5 px-4 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-bold shadow-xs transition cursor-pointer disabled:opacity-50"
                  >
                    {evaluatingBatch ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
                    {evaluatingBatch ? "Evaluating..." : "Run Evaluation"}
                  </button>
                </div>
              )}

              {batchError && (
                <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-800 font-medium flex items-center gap-2">
                  <AlertTriangle size={16} className="text-rose-600 shrink-0" />
                  <span>{batchError}</span>
                </div>
              )}

              {/* BENCHMARK RESULTS REPORT */}
              {benchmarkResult && (
                <div className="space-y-5 animate-in fade-in duration-200">
                  
                  {/* Results Header Summary */}
                  <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                    <div>
                      <h4 className="text-sm font-bold text-slate-900">
                        Evaluation Report: {benchmarkResult.dataset_name}
                      </h4>
                      <p className="text-xs text-slate-500 mt-0.5">
                        {benchmarkResult.total_samples.toLocaleString()} total email samples processed across all multi-label threat heads.
                      </p>
                    </div>
                    <span className="px-2.5 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full text-xs font-bold">
                      Completed
                    </span>
                  </div>

                  {/* Threat Distribution Cards */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs">
                      <span className="text-[11px] font-bold text-rose-600 uppercase tracking-wider block">
                        Critical Threats (&ge; 70%)
                      </span>
                      <div className="mt-2 text-2xl font-black text-slate-900">
                        {benchmarkResult.critical_count}
                        <span className="text-xs font-semibold text-slate-500 ml-1.5">
                          ({((benchmarkResult.critical_count / benchmarkResult.total_samples) * 100).toFixed(1)}%)
                        </span>
                      </div>
                    </div>

                    <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs">
                      <span className="text-[11px] font-bold text-amber-600 uppercase tracking-wider block">
                        Suspicious (40 - 69%)
                      </span>
                      <div className="mt-2 text-2xl font-black text-slate-900">
                        {benchmarkResult.suspicious_count}
                        <span className="text-xs font-semibold text-slate-500 ml-1.5">
                          ({((benchmarkResult.suspicious_count / benchmarkResult.total_samples) * 100).toFixed(1)}%)
                        </span>
                      </div>
                    </div>

                    <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs">
                      <span className="text-[11px] font-bold text-emerald-600 uppercase tracking-wider block">
                        Safe / Benign (&lt; 40%)
                      </span>
                      <div className="mt-2 text-2xl font-black text-slate-900">
                        {benchmarkResult.safe_count}
                        <span className="text-xs font-semibold text-slate-500 ml-1.5">
                          ({((benchmarkResult.safe_count / benchmarkResult.total_samples) * 100).toFixed(1)}%)
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Threat Vector Intensity Bars */}
                  <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
                    <h5 className="text-xs font-bold uppercase tracking-wider text-slate-700">
                      Average Threat Vector Signals Across Dataset
                    </h5>
                    
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                      <div className="p-3 bg-white rounded-lg border border-slate-200 shadow-2xs">
                        <span className="text-slate-500 block font-semibold">Urgency Score</span>
                        <span className="text-lg font-black text-slate-900">{benchmarkResult.avg_urgency}%</span>
                      </div>
                      <div className="p-3 bg-white rounded-lg border border-slate-200 shadow-2xs">
                        <span className="text-slate-500 block font-semibold">Authority Pressure</span>
                        <span className="text-lg font-black text-slate-900">{benchmarkResult.avg_authority}%</span>
                      </div>
                      <div className="p-3 bg-white rounded-lg border border-slate-200 shadow-2xs">
                        <span className="text-slate-500 block font-semibold">Fear / Coercion</span>
                        <span className="text-lg font-black text-slate-900">{benchmarkResult.avg_fear}%</span>
                      </div>
                      <div className="p-3 bg-white rounded-lg border border-slate-200 shadow-2xs">
                        <span className="text-slate-500 block font-semibold">Impersonation Risk</span>
                        <span className="text-lg font-black text-slate-900">{benchmarkResult.avg_impersonation}%</span>
                      </div>
                    </div>
                  </div>

                  {/* Ground Truth Validation Metrics (if present) */}
                  {Object.keys(benchmarkResult.metrics).length > 0 && (
                    <div className="border border-slate-200 rounded-xl overflow-hidden bg-white">
                      <div className="p-3 bg-slate-100 border-b border-slate-200 text-xs font-bold uppercase tracking-wider text-slate-700">
                        Ground Truth Model Performance
                      </div>
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-50 text-slate-500 font-bold border-b border-slate-200">
                          <tr>
                            <th className="px-3.5 py-2.5">Threat Category</th>
                            <th className="px-3.5 py-2.5">Accuracy</th>
                            <th className="px-3.5 py-2.5">Precision</th>
                            <th className="px-3.5 py-2.5">Recall</th>
                            <th className="px-3.5 py-2.5">F1-Score</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 font-medium text-slate-800">
                          {Object.entries(benchmarkResult.metrics).map(([key, m]) => (
                            <tr key={key} className="hover:bg-slate-50">
                              <td className="px-3.5 py-2.5 font-bold uppercase">{key}</td>
                              <td className="px-3.5 py-2.5 font-semibold text-slate-900">{m.accuracy}%</td>
                              <td className="px-3.5 py-2.5">{m.precision}%</td>
                              <td className="px-3.5 py-2.5">{m.recall}%</td>
                              <td className="px-3.5 py-2.5 font-bold text-emerald-700">{m.f1_score}%</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* Top Samples Preview */}
                  {benchmarkResult.sample_preview && benchmarkResult.sample_preview.length > 0 && (
                    <div className="space-y-2">
                      <h5 className="text-xs font-bold uppercase tracking-wider text-slate-600">
                        Evaluated Sample Previews
                      </h5>
                      <div className="space-y-2 max-h-48 overflow-y-auto">
                        {benchmarkResult.sample_preview.map((sample, idx) => (
                          <div key={idx} className="p-3 bg-white rounded-xl border border-slate-200 text-xs flex items-center justify-between gap-4">
                            <p className="text-slate-700 truncate font-medium flex-1">
                              &ldquo;{sample.text}&rdquo;
                            </p>
                            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider shrink-0 border ${
                              sample.risk_level === "CRITICAL"
                                ? "bg-rose-50 text-rose-700 border-rose-200"
                                : sample.risk_level === "SUSPICIOUS"
                                ? "bg-amber-50 text-amber-700 border-amber-200"
                                : "bg-emerald-50 text-emerald-700 border-emerald-200"
                            }`}>
                              {Math.round(sample.risk_score * 100)}% {sample.risk_level}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                </div>
              )}

            </div>
          )}

        </div>

      </div>
    </div>
  );
}
