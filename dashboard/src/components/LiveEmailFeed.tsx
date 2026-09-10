"use client";

import React, { useState, useEffect } from "react";
import { 
  Shield, CheckCircle2, XCircle, Search, 
  ChevronRight, MapPin, Download, FileText, 
  Terminal, RefreshCw, Layers, Briefcase, Users, Globe, Paperclip, 
  FileWarning, Server, ArrowRight, Lock, Network
} from "lucide-react";
import GeoThreatMap from "./GeoThreatMap";
import EntityRelationshipGraph from "./EntityRelationshipGraph";

export interface AttachmentItem {
  filename?: string;
  extension?: string;
  is_dangerous?: boolean;
  is_double_extension?: boolean;
  danger_category?: string;
  risk_score?: number;
  content_type?: string;
}

export interface ScanItem {
  id: number;
  subject: string;
  sender: string;
  sender_domain: string;
  risk_score: number;
  risk_level: string;
  explanation: string;
  timestamp: string;
  spf_status: string;
  dkim_status: string;
  dmarc_status: string;
  auth_results: string;
  trust_score: number;
  category: string;
  domain_age_days: number;
  whois_registrar: string;
  reply_to: string;
  return_path: string;
  message_id: string;
  origin_ip: string;
  origin_country: string;
  origin_city: string;
  origin_isp: string;
  origin_asn: string;
  geo_mismatch: boolean;
  geo_mismatch_reason: string;
  received_chain: string[];
  forensic_hash: string;
  attachments?: AttachmentItem[];
  evidence_data?: Record<string, unknown>;
}

export interface CampaignItem {
  campaign_id: string;
  name: string;
  threat_actor_profile: string;
  severity: string;
  target_brands: string[];
  origin_countries: string[];
  origin_ips: string[];
  reply_to_aliases: string[];
  incident_count: number;
  incidents: ScanItem[];
  first_seen: string;
  last_seen: string;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8005/api/v1";

export default function LiveEmailFeed() {
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignItem[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanItem | null>(null);
  const [selectedCampaign, setSelectedCampaign] = useState<CampaignItem | null>(null);
  const [filter, setFilter] = useState<"ALL" | "CRITICAL" | "MISMATCH" | "SAFE">("ALL");
  const [viewMode, setViewMode] = useState<"INCIDENTS" | "CAMPAIGNS">("INCIDENTS");
  const [traceMode, setTraceMode] = useState<"GRAPH" | "MAP" | "TIMELINE">("GRAPH");
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [rawHeadersOpen, setRawHeadersOpen] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchScans = async () => {
    try {
      setIsRefreshing(true);
      const [recentRes, campsRes] = await Promise.all([
        fetch(`${API_BASE}/email-scans/recent?limit=25`),
        fetch(`${API_BASE}/email-scans/campaigns`)
      ]);

      if (recentRes.ok) {
        const data: ScanItem[] = await recentRes.json();
        setScans(data);
        if (!selectedScan && data.length > 0) {
          setSelectedScan(data[0]);
        } else if (selectedScan) {
          const updated = data.find(s => s.id === selectedScan.id);
          if (updated) setSelectedScan(updated);
        }
      }

      if (campsRes.ok) {
        const campData: CampaignItem[] = await campsRes.json();
        setCampaigns(campData);
        if (!selectedCampaign && campData.length > 0) {
          setSelectedCampaign(campData[0]);
        }
      }
    } catch (err) {
      console.error("Error loading live email scans:", err);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 8000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filteredScans = scans.filter(item => {
    if (filter === "CRITICAL" && item.risk_level !== "CRITICAL" && item.risk_score < 0.7) return false;
    if (filter === "MISMATCH" && !item.geo_mismatch) return false;
    if (filter === "SAFE" && item.risk_level !== "SAFE") return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        item.subject.toLowerCase().includes(q) ||
        item.sender.toLowerCase().includes(q) ||
        item.origin_ip.toLowerCase().includes(q) ||
        item.origin_country.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const downloadJsonReport = async (scanId: number) => {
    try {
      const res = await fetch(`${API_BASE}/email-scans/${scanId}/forensic-report`);
      if (res.ok) {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `forensic_report_incident_${scanId}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error("Failed to download JSON forensic report:", err);
      alert("Failed to download JSON forensic report.");
    }
  };

  const downloadPdfReport = (scanId: number) => {
    window.open(`${API_BASE}/email-scans/${scanId}/forensic-report/pdf`, "_blank");
  };

  const getStatusBadge = (level: string, score: number) => {
    if (level === "CRITICAL" || score >= 0.7) {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">Critical Threat</span>;
    }
    if (level === "SUSPICIOUS" || score >= 0.4) {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">Suspicious</span>;
    }
    return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">Authentic</span>;
  };

  return (
    <div className="space-y-6">
      {/* Top Controller Bar */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-slate-100 text-slate-800 flex items-center justify-center border border-slate-200">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
              Threat Verification & Forensics Stream
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
            </h2>
            <p className="text-xs text-slate-500 font-medium">Header Forensics, Geolocation, Graph Attribution & Campaign Case Clusters</p>
          </div>
        </div>

        {/* View Mode Switcher: Incidents vs Campaigns */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
            <button
              onClick={() => setViewMode("INCIDENTS")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition ${
                viewMode === "INCIDENTS" ? "bg-white text-slate-900 shadow-2xs" : "text-slate-600 hover:text-slate-900"
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              Incidents ({scans.length})
            </button>
            <button
              onClick={() => setViewMode("CAMPAIGNS")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition ${
                viewMode === "CAMPAIGNS" ? "bg-white text-slate-900 shadow-2xs" : "text-slate-600 hover:text-slate-900"
              }`}
            >
              <Briefcase className="w-3.5 h-3.5" />
              Campaign Cases ({campaigns.length})
            </button>
          </div>

          <button 
            onClick={fetchScans}
            disabled={isRefreshing}
            className="p-2 bg-white hover:bg-slate-50 text-slate-700 rounded-lg border border-slate-200 transition shadow-2xs cursor-pointer"
            title="Refresh Feed"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? "animate-spin text-slate-600" : ""}`} />
          </button>
        </div>
      </div>

      {/* VIEW MODE 1: CAMPAIGN CLUSTERING & CASE MANAGEMENT */}
      {viewMode === "CAMPAIGNS" ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Campaign List */}
          <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200 overflow-hidden flex flex-col h-[740px] shadow-xs">
            <div className="p-3.5 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
              <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                <Briefcase className="w-4 h-4 text-slate-600" />
                Active Fraud Campaigns ({campaigns.length})
              </span>
              <span className="text-[11px] text-slate-500 font-medium">Auto-clustered IOCs</span>
            </div>

            <div className="overflow-y-auto flex-1 divide-y divide-slate-100">
              {campaigns.map((camp) => {
                const isSelected = selectedCampaign?.campaign_id === camp.campaign_id;
                return (
                  <div
                    key={camp.campaign_id}
                    onClick={() => setSelectedCampaign(camp)}
                    className={`p-4 cursor-pointer transition border-l-4 ${
                      isSelected ? "bg-slate-50 border-l-slate-900 shadow-2xs" : "hover:bg-slate-50/60 border-l-transparent"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-slate-100 text-slate-700 rounded border border-slate-200">
                        {camp.campaign_id}
                      </span>
                      <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-rose-50 text-rose-700 border border-rose-200">
                        {camp.severity}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-slate-900 mb-1">{camp.name}</h4>
                    <p className="text-xs text-slate-500 line-clamp-2 mb-2 font-medium">{camp.threat_actor_profile}</p>

                    <div className="flex items-center justify-between text-xs text-slate-500 border-t border-slate-100 pt-2 font-medium">
                      <span className="flex items-center gap-1">
                        <Users className="w-3.5 h-3.5 text-slate-400" />
                        {camp.incident_count} Incidents Grouped
                      </span>
                      <span className="flex items-center gap-1 font-mono text-[11px]">
                        <Globe className="w-3 h-3 text-slate-400" />
                        {camp.origin_countries.join(", ") || "Global"}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Campaign Case File Details */}
          <div className="lg:col-span-7 bg-white rounded-xl border border-slate-200 p-6 flex flex-col gap-6 shadow-xs">
            {selectedCampaign ? (
              <>
                <div className="border-b border-slate-200 pb-4">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-mono font-bold text-slate-500">{selectedCampaign.campaign_id}</span>
                    <span className="text-slate-300">•</span>
                    <span className="text-xs text-slate-500 font-medium">{selectedCampaign.incident_count} Intercepted Incidents</span>
                  </div>
                  <h3 className="text-2xl font-bold text-slate-900">{selectedCampaign.name}</h3>
                  <p className="text-xs text-slate-600 mt-1 font-medium">{selectedCampaign.threat_actor_profile}</p>
                </div>

                {/* Campaign IOC Grid */}
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <span className="text-slate-500 block mb-1 font-medium">Associated Threat IPs</span>
                    <div className="font-mono font-bold text-rose-700">
                      {selectedCampaign.origin_ips.join(", ") || "Dynamic Proxies"}
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <span className="text-slate-500 block mb-1 font-medium">Reply-To Divergence</span>
                    <div className="font-mono text-slate-800 font-semibold truncate" title={selectedCampaign.reply_to_aliases.join(", ")}>
                      {selectedCampaign.reply_to_aliases.join(", ") || "None"}
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <span className="text-slate-500 block mb-1 font-medium">Targeted Entities</span>
                    <div className="font-semibold text-slate-900">
                      {selectedCampaign.target_brands.join(", ") || "Enterprise"}
                    </div>
                  </div>
                </div>

                {/* Linked Incidents Table */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-3 flex items-center gap-2">
                    <Layers className="w-3.5 h-3.5 text-slate-500" />
                    Correlated Incidents in Campaign Case
                  </h4>

                  <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden bg-white">
                    {selectedCampaign.incidents.map((inc) => (
                      <div 
                        key={inc.id}
                        onClick={() => {
                          setSelectedScan(inc);
                          setViewMode("INCIDENTS");
                        }}
                        className="p-3.5 hover:bg-slate-50 cursor-pointer flex items-center justify-between gap-4 transition"
                      >
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs font-bold text-slate-900">{inc.subject}</span>
                            {getStatusBadge(inc.risk_level, inc.risk_score)}
                          </div>
                          <div className="text-[11px] text-slate-500 font-medium">
                            Sender: <span className="font-mono text-slate-800 font-semibold">{inc.sender}</span> | Origin: {inc.origin_city}, {inc.origin_country} ({inc.origin_ip})
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              downloadPdfReport(inc.id);
                            }}
                            className="px-2.5 py-1 bg-white hover:bg-slate-50 text-slate-700 rounded text-xs font-semibold border border-slate-200 shadow-2xs"
                          >
                            Export PDF
                          </button>
                          <ChevronRight className="w-4 h-4 text-slate-400" />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-slate-400 text-sm font-medium">
                Select a campaign from the left pane to view the case file.
              </div>
            )}
          </div>
        </div>
      ) : (
        /* VIEW MODE 2: INDIVIDUAL INCIDENTS STREAM (Standard View) */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Email Threat Stream */}
          <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200 overflow-hidden flex flex-col h-[740px] shadow-xs">
            {/* Filter & Search Header */}
            <div className="p-3.5 border-b border-slate-200 bg-slate-50 space-y-2.5">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search by subject, sender, IP, or country..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-4 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-slate-400 font-medium shadow-2xs"
                />
              </div>

              <div className="flex bg-slate-100 p-1 rounded-lg border border-slate-200 text-[11px]">
                <button
                  onClick={() => setFilter("ALL")}
                  className={`flex-1 py-1 rounded font-semibold transition ${filter === "ALL" ? "bg-white text-slate-900 shadow-2xs" : "text-slate-600 hover:text-slate-900"}`}
                >
                  All ({scans.length})
                </button>
                <button
                  onClick={() => setFilter("CRITICAL")}
                  className={`flex-1 py-1 rounded font-semibold transition ${filter === "CRITICAL" ? "bg-white text-rose-700 shadow-2xs" : "text-slate-600 hover:text-slate-900"}`}
                >
                  Threats
                </button>
                <button
                  onClick={() => setFilter("MISMATCH")}
                  className={`flex-1 py-1 rounded font-semibold transition ${filter === "MISMATCH" ? "bg-white text-amber-700 shadow-2xs" : "text-slate-600 hover:text-slate-900"}`}
                >
                  Mismatch
                </button>
                <button
                  onClick={() => setFilter("SAFE")}
                  className={`flex-1 py-1 rounded font-semibold transition ${filter === "SAFE" ? "bg-white text-emerald-700 shadow-2xs" : "text-slate-600 hover:text-slate-900"}`}
                >
                  Authentic
                </button>
              </div>
            </div>

            {/* Email Items List */}
            <div className="overflow-y-auto flex-1 divide-y divide-slate-100">
              {loading ? (
                <div className="p-8 text-center text-slate-500 text-sm font-medium">Loading security feed...</div>
              ) : filteredScans.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-sm font-medium">No email scans match the current filter.</div>
              ) : (
                filteredScans.map((item) => {
                  const isSelected = selectedScan?.id === item.id;
                  const scorePercent = Math.round(item.risk_score * 100);

                  return (
                    <div
                      key={item.id}
                      onClick={() => setSelectedScan(item)}
                      className={`p-4 cursor-pointer transition-colors border-l-4 ${
                        isSelected
                          ? "bg-slate-50 border-l-slate-900 shadow-2xs"
                          : "hover:bg-slate-50/60 border-l-transparent"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2 mb-1.5">
                        <div className="flex items-center gap-2">
                          {getStatusBadge(item.risk_level, item.risk_score)}
                          {item.geo_mismatch && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-200">
                              Geo Mismatch
                            </span>
                          )}
                        </div>
                        <span className="text-[11px] font-mono font-bold text-slate-600">
                          {scorePercent}%
                        </span>
                      </div>

                      <h4 className="text-sm font-bold text-slate-900 line-clamp-1 mb-1">
                        {item.subject}
                      </h4>

                      <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
                        <span className="truncate max-w-[200px]" title={item.sender}>
                          {item.sender}
                        </span>
                        <span className="flex items-center gap-1 text-[11px] text-slate-500">
                          <MapPin className="w-3.5 h-3.5 text-slate-400" />
                          {item.origin_country || "Unknown"}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Right Column: Deep Forensic Dossier */}
          <div className="lg:col-span-7 bg-white rounded-xl border border-slate-200 p-6 flex flex-col gap-6 shadow-xs">
            {selectedScan ? (
              <>
                {/* Dossier Header */}
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-5 border-b border-slate-200">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono font-bold text-slate-500">INCIDENT #{selectedScan.id}</span>
                      <span className="text-slate-300">•</span>
                      <span className="text-xs text-slate-500 font-medium">{new Date(selectedScan.timestamp).toLocaleString()}</span>
                    </div>
                    <h3 className="text-xl font-bold text-slate-900">{selectedScan.subject}</h3>
                    <p className="text-xs text-slate-500 mt-1 font-medium">
                      Claimed Sender: <span className="font-mono text-slate-900 font-bold">{selectedScan.sender}</span>
                    </p>
                  </div>

                  <div className="flex items-center gap-2 self-end md:self-center">
                    <button
                      onClick={() => downloadJsonReport(selectedScan.id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 rounded-lg text-xs font-semibold border border-slate-200 shadow-2xs transition cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5 text-slate-500" />
                      JSON
                    </button>
                    <button
                      onClick={() => downloadPdfReport(selectedScan.id)}
                      className="flex items-center gap-1.5 px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer"
                    >
                      <FileText className="w-3.5 h-3.5 text-slate-300" />
                      Export PDF
                    </button>
                  </div>
                </div>

                {/* Fraud Score & Threat Classification Banner */}
                <div className={`p-4 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
                  selectedScan.risk_score >= 0.7 
                    ? "bg-rose-50 border-rose-200 text-rose-900" 
                    : selectedScan.risk_score >= 0.4
                    ? "bg-amber-50 border-amber-200 text-amber-900"
                    : "bg-emerald-50 border-emerald-200 text-emerald-900"
                }`}>
                  <div className="flex items-center gap-4">
                    <div className={`w-14 h-14 rounded-xl flex items-center justify-center font-black text-2xl text-white shadow-xs ${
                      selectedScan.risk_score >= 0.7
                        ? "bg-rose-600"
                        : selectedScan.risk_score >= 0.4
                        ? "bg-amber-600"
                        : "bg-emerald-600"
                    }`}>
                      {Math.round(selectedScan.risk_score * 100)}%
                    </div>
                    <div>
                      <div className="text-xs uppercase font-bold tracking-wider opacity-75">
                        Threat Classification
                      </div>
                      <div className="text-base font-extrabold">
                        {selectedScan.category ? selectedScan.category.replace(/_/g, " ") : "THREAT ANALYSIS"}
                      </div>
                      <div className="text-xs mt-0.5 font-medium leading-relaxed opacity-90">
                        {selectedScan.explanation}
                      </div>
                    </div>
                  </div>

                  <div className="text-right text-xs shrink-0">
                    <div className="text-slate-500 font-mono">Evidence SHA-256</div>
                    <div className="font-mono text-[11px] font-bold truncate max-w-[160px]" title={selectedScan.forensic_hash}>
                      {selectedScan.forensic_hash ? selectedScan.forensic_hash.substring(0, 16) + "..." : "UNHASHED"}
                    </div>
                  </div>
                </div>

                {/* Suspicious Attachment Card (If attachments detected) */}
                {selectedScan.attachments && selectedScan.attachments.length > 0 && (
                  <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
                        <Paperclip className="w-3.5 h-3.5 text-slate-500" />
                        Attachment Forensics ({selectedScan.attachments.length} Detected)
                      </span>
                      {selectedScan.attachments.some((a) => a.is_dangerous) && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-700 border border-rose-200 flex items-center gap-1">
                          <FileWarning className="w-3 h-3" /> Malicious Payload
                        </span>
                      )}
                    </div>

                    <div className="divide-y divide-slate-200">
                      {selectedScan.attachments.map((att, idx: number) => (
                        <div key={idx} className="py-2 flex items-center justify-between gap-3 text-xs">
                          <div className="flex items-center gap-2">
                            {att.is_dangerous ? (
                              <XCircle className="w-4 h-4 text-rose-600 shrink-0" />
                            ) : (
                              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                            )}
                            <div>
                              <span className="font-mono font-bold text-slate-900">{att.filename}</span>
                              {att.is_double_extension && (
                                <span className="ml-2 px-1.5 py-0.5 bg-rose-100 text-rose-700 rounded text-[9px] font-bold">
                                  DOUBLE EXTENSION SPOOF
                                </span>
                              )}
                            </div>
                          </div>
                          <span className={`text-[11px] font-semibold ${att.is_dangerous ? "text-rose-700" : "text-slate-600"}`}>
                            {att.danger_category}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Protocol Authentication Grid */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-3 flex items-center gap-2">
                    <Shield className="w-3.5 h-3.5 text-slate-500" />
                    Sender Authentication & Protocol Verification
                  </h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {/* SPF */}
                    <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                      <div className="text-xs text-slate-500 font-medium">SPF Record</div>
                      <div className={`text-sm font-bold mt-1 flex items-center gap-1.5 ${
                        selectedScan.spf_status === "PASS" ? "text-emerald-700" : "text-rose-700"
                      }`}>
                        {selectedScan.spf_status === "PASS" ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                        {selectedScan.spf_status}
                      </div>
                    </div>

                    {/* DKIM */}
                    <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                      <div className="text-xs text-slate-500 font-medium">DKIM Signature</div>
                      <div className={`text-sm font-bold mt-1 flex items-center gap-1.5 ${
                        selectedScan.dkim_status === "PASS" ? "text-emerald-700" : "text-rose-700"
                      }`}>
                        {selectedScan.dkim_status === "PASS" ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                        {selectedScan.dkim_status}
                      </div>
                    </div>

                    {/* DMARC */}
                    <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                      <div className="text-xs text-slate-500 font-medium">DMARC Policy</div>
                      <div className={`text-sm font-bold mt-1 flex items-center gap-1.5 ${
                        selectedScan.dmarc_status === "PASS" ? "text-emerald-700" : "text-rose-700"
                      }`}>
                        {selectedScan.dmarc_status === "PASS" ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                        {selectedScan.dmarc_status}
                      </div>
                    </div>

                    {/* Domain Age */}
                    <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                      <div className="text-xs text-slate-500 font-medium">Domain Age</div>
                      <div className={`text-sm font-bold mt-1 ${
                        selectedScan.domain_age_days >= 0 && selectedScan.domain_age_days < 30 ? "text-rose-700" : "text-slate-900"
                      }`}>
                        {selectedScan.domain_age_days >= 0 ? `${selectedScan.domain_age_days} Days` : "Unknown"}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Trace Analysis Switcher: Graph vs Map vs Timeline */}
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
                      <Network className="w-3.5 h-3.5 text-slate-500" />
                      Attribution & Relational Visualizer
                    </h4>

                    <div className="flex bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
                      <button
                        onClick={() => setTraceMode("GRAPH")}
                        className={`px-2.5 py-1 rounded font-semibold transition ${
                          traceMode === "GRAPH" ? "bg-white text-slate-900 shadow-2xs" : "text-slate-600 hover:text-slate-900"
                        }`}
                      >
                        Entity Graph
                      </button>
                      <button
                        onClick={() => setTraceMode("MAP")}
                        className={`px-2.5 py-1 rounded font-semibold transition ${
                          traceMode === "MAP" ? "bg-white text-slate-900 shadow-2xs" : "text-slate-600 hover:text-slate-900"
                        }`}
                      >
                        Geo Threat Map
                      </button>
                      <button
                        onClick={() => setTraceMode("TIMELINE")}
                        className={`px-2.5 py-1 rounded font-semibold transition ${
                          traceMode === "TIMELINE" ? "bg-white text-slate-900 shadow-2xs" : "text-slate-600 hover:text-slate-900"
                        }`}
                      >
                        Relay Timeline
                      </button>
                    </div>
                  </div>

                  {traceMode === "GRAPH" ? (
                    <EntityRelationshipGraph scan={selectedScan} />
                  ) : traceMode === "MAP" ? (
                    <GeoThreatMap scan={selectedScan} />
                  ) : (
                    /* Linear Hop Trace */
                    <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-4">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs border-b border-slate-200 pb-3">
                        <div>
                          <span className="text-slate-500 block font-medium">Originating IP</span>
                          <span className="font-mono font-bold text-slate-900">{selectedScan.origin_ip}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block font-medium">Physical Location</span>
                          <span className="font-semibold text-slate-900">{selectedScan.origin_city}, {selectedScan.origin_country}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block font-medium">ISP Network</span>
                          <span className="font-semibold text-slate-900 truncate block" title={selectedScan.origin_isp}>{selectedScan.origin_isp}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block font-medium">Autonomous System</span>
                          <span className="font-mono font-semibold text-slate-900">{selectedScan.origin_asn}</span>
                        </div>
                      </div>

                      <div className="flex flex-col md:flex-row items-start md:items-center gap-2 text-xs">
                        <div className="p-2.5 rounded-lg bg-white border border-slate-200 flex items-center gap-2 w-full md:w-auto shadow-2xs">
                          <Server className="w-4 h-4 text-rose-600" />
                          <div>
                            <div className="text-[10px] text-slate-500 uppercase font-semibold">Origin Hop (Earliest IP)</div>
                            <div className="font-mono text-xs text-slate-900 font-bold">{selectedScan.origin_ip}</div>
                          </div>
                        </div>

                        <ArrowRight className="w-4 h-4 text-slate-400 hidden md:block shrink-0" />

                        <div className="p-2.5 rounded-lg bg-white border border-slate-200 flex items-center gap-2 w-full md:w-auto shadow-2xs">
                          <Server className="w-4 h-4 text-blue-600" />
                          <div>
                            <div className="text-[10px] text-slate-500 uppercase font-semibold">Gateway Relay</div>
                            <div className="font-mono text-xs text-slate-900 font-medium">
                              {selectedScan.received_chain && selectedScan.received_chain.length > 1
                                ? selectedScan.received_chain[0]
                                : "mail-relay.internal"}
                            </div>
                          </div>
                        </div>

                        <ArrowRight className="w-4 h-4 text-slate-400 hidden md:block shrink-0" />

                        <div className="p-2.5 rounded-lg bg-white border border-slate-200 flex items-center gap-2 w-full md:w-auto shadow-2xs">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                          <div>
                            <div className="text-[10px] text-slate-500 uppercase font-semibold">Destination Gateway</div>
                            <div className="font-mono text-xs text-slate-900 font-medium">mx.google.com</div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Privacy, Legal, and Compliance Safeguards Strip */}
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-2.5 text-slate-700">
                    <Lock className="w-4 h-4 text-emerald-600 shrink-0" />
                    <div>
                      <span className="font-bold text-slate-900">Privacy Safeguards: </span>
                      <span className="text-slate-600">Personal data redacted; immutable SHA-256 evidence preserved (DPDP/GDPR).</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-emerald-50 text-emerald-700 rounded border border-emerald-200 text-[10px] font-bold">
                      Evidence Preserved
                    </span>
                    <span className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded border border-slate-200 text-[10px] font-mono font-medium">
                      Chain of Custody
                    </span>
                  </div>
                </div>

                {/* RFC Headers Toggle */}
                <div>
                  <button
                    onClick={() => setRawHeadersOpen(!rawHeadersOpen)}
                    className="text-xs text-slate-700 hover:text-slate-900 font-semibold flex items-center gap-1 transition cursor-pointer"
                  >
                    <ChevronRight className={`w-3.5 h-3.5 transition-transform ${rawHeadersOpen ? "rotate-90" : ""}`} />
                    {rawHeadersOpen ? "Hide Raw RFC Headers" : "Inspect Raw RFC 5322 Headers"}
                  </button>

                  {rawHeadersOpen && (
                    <div className="mt-2 p-3.5 bg-slate-900 text-slate-100 rounded-lg border border-slate-800 font-mono text-[11px] overflow-x-auto max-h-48 space-y-1 shadow-xs">
                      <div>Return-Path: {selectedScan.return_path}</div>
                      <div>Message-ID: {selectedScan.message_id}</div>
                      <div>Reply-To: {selectedScan.reply_to}</div>
                      <div>Authentication-Results: {selectedScan.auth_results}</div>
                      <div>Origin-IP: {selectedScan.origin_ip}</div>
                      <div>Forensic-SHA256: {selectedScan.forensic_hash}</div>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="h-[400px] flex items-center justify-center text-slate-400 text-sm font-medium">
                Select an email scan from the live stream to inspect forensics.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
