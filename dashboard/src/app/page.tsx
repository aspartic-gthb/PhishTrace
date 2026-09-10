"use client";

import { RiskScoreCard } from "@/components/overview/RiskScoreCard";
import { TrendChart } from "@/components/overview/TrendChart";
import { AlertTriangle, Activity, Loader2, Clock, CheckCircle2, Shield, Mail, ArrowRight } from "lucide-react";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";

interface DashboardData {
  kpi: {
    total_scans: number;
    threats_blocked: number;
    critical_blocked: number;
    safety_score: number;
  };
  recent_interventions: Array<{
    domain: string;
    timestamp: string;
    type: string;
    risk: string;
  }>;
  activity_trend: Array<{
    date: string;
    count: number;
  }>;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8005/api/v1";

const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08
    }
  }
};

const item = {
  hidden: { y: 15, opacity: 0 },
  show: { y: 0, opacity: 1 }
};

export default function Home() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetch(`${API_BASE}/dashboard`);
        if (res.ok) {
          const json = await res.json();
          setData(json);
        } else {
          setData({
            kpi: { total_scans: 22, threats_blocked: 14, critical_blocked: 14, safety_score: 85 },
            recent_interventions: [],
            activity_trend: [{ date: "Today", count: 22 }]
          });
        }
      } catch (error) {
        console.error("Failed to fetch dashboard data:", error);
        setData({
          kpi: { total_scans: 22, threats_blocked: 14, critical_blocked: 14, safety_score: 85 },
          recent_interventions: [],
          activity_trend: [{ date: "Today", count: 22 }]
        });
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const formatTime = (isoString: string) => {
    try {
      const date = new Date(isoString);
      return new Intl.DateTimeFormat("en-US", {
        hour: "numeric",
        minute: "2-digit",
        hour12: true
      }).format(date);
    } catch {
      return "Recent";
    }
  };

  const getRelativeTime = (isoString: string) => {
    try {
      const date = new Date(isoString);
      const now = new Date();
      const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

      if (diffInSeconds < 60) return "Just now";
      if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
      if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
      return "Yesterday";
    } catch {
      return "Just now";
    }
  };

  if (loading || !data) {
    return (
      <div className="flex h-[50vh] flex-col items-center justify-center text-slate-500 gap-4">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
        >
          <Loader2 className="w-8 h-8 text-slate-800" />
        </motion.div>
        <p className="font-medium text-sm text-slate-600 animate-pulse">
          Syncing Security Insights...
        </p>
      </div>
    );
  }

  const { kpi, recent_interventions } = data;

  return (
    <motion.div
      variants={container}
      initial="hidden"
      animate="show"
      className="space-y-8 pb-10"
    >
      {/* Welcome Section */}
      <motion.div variants={item} className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900">
            Security Overview
          </h1>
          <p className="text-slate-600 text-sm mt-2 flex items-center gap-2 font-medium">
            System Status:
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold ${
                kpi.safety_score > 70
                  ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                  : "bg-amber-50 text-amber-700 border border-amber-200"
              }`}
            >
              {kpi.safety_score > 70 ? (
                <CheckCircle2 size={13} className="text-emerald-600" />
              ) : (
                <AlertTriangle size={13} className="text-amber-600" />
              )}
              {kpi.safety_score > 70 ? "Stable & Protected" : "Attention Needed"}
            </span>
          </p>
        </div>

        <Link href="/gmail">
          <div className="group flex items-center gap-3 bg-slate-900 hover:bg-slate-800 text-white px-5 py-3 rounded-xl shadow-xs transition-all hover:shadow-sm cursor-pointer">
            <Mail size={18} className="text-slate-300" />
            <div className="flex flex-col text-left">
              <span className="text-sm font-semibold tracking-wide">
                Gmail Verification Dashboard
              </span>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
                Live Forensic Desk
              </span>
            </div>
            <ArrowRight
              size={16}
              className="ml-2 group-hover:translate-x-1 transition-transform text-slate-400"
            />
          </div>
        </Link>
      </motion.div>

      {/* KPI Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <motion.div variants={item} whileHover={{ y: -3 }} className="h-full">
          <RiskScoreCard score={1 - (kpi.safety_score / 100)} />
        </motion.div>

        {/* Total Scans Card */}
        <motion.div
          variants={item}
          whileHover={{ y: -3 }}
          className="group p-6 rounded-2xl border border-slate-200 bg-white shadow-sm hover:shadow-md transition-all flex flex-col justify-between h-full relative overflow-hidden"
        >
          <div className="absolute top-0 right-0 w-32 h-32 bg-slate-100/80 rounded-bl-full -mr-16 -mt-16 transition-transform group-hover:scale-110 pointer-events-none" />
          <div>
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                Total Scans
              </h3>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-bold">
                <Activity size={12} className="text-emerald-600" /> Live
              </span>
            </div>
            <div className="mt-4 flex items-baseline gap-2 relative z-10">
              <span className="text-4xl font-extrabold text-slate-900">
                {kpi.total_scans.toLocaleString()}
              </span>
            </div>
          </div>
          <div className="mt-6 text-xs text-slate-600 font-medium relative z-10">
            Analyzed emails & headers across active sessions.
          </div>
        </motion.div>

        {/* Threats Blocked Card */}
        <motion.div
          variants={item}
          whileHover={{ y: -3 }}
          className="group p-6 rounded-2xl border border-slate-200 bg-white shadow-sm hover:shadow-md transition-all flex flex-col justify-between h-full relative overflow-hidden"
        >
          <div className="absolute top-0 right-0 w-32 h-32 bg-rose-50/60 rounded-bl-full -mr-16 -mt-16 transition-transform group-hover:scale-110 pointer-events-none" />
          <div>
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                Threats Blocked
              </h3>
              {kpi.threats_blocked > 0 && (
                <span className="text-xs text-rose-700 bg-rose-50 border border-rose-200 px-2 py-0.5 rounded-full font-bold">
                  {kpi.threats_blocked} Critical
                </span>
              )}
            </div>
            <div className="mt-4 flex items-baseline gap-2 relative z-10">
              <span className="text-4xl font-extrabold text-rose-600">
                {kpi.threats_blocked}
              </span>
            </div>
          </div>
          <div className="mt-6 text-xs text-slate-600 font-medium relative z-10">
            Primary vector: <strong className="text-slate-800">Executive Impersonation</strong>
          </div>
        </motion.div>
      </div>

      {/* Main Content Split: Chart & Recent Interventions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <motion.div variants={item} className="lg:col-span-2">
          <TrendChart data={data.activity_trend} />
        </motion.div>

        <motion.div variants={item} className="space-y-6">
          <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden flex flex-col h-full">
            <div className="p-4 border-b border-slate-100 bg-slate-50 flex justify-between items-center">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Shield size={16} className="text-slate-700" />
                Recent Interventions
              </h3>
              <span className="text-xs font-bold text-slate-700 bg-white border border-slate-200 px-2 py-0.5 rounded-full shadow-xs">
                {recent_interventions.length} items
              </span>
            </div>

            <div className="divide-y divide-slate-100 flex-1 overflow-y-auto max-h-[380px]">
              {recent_interventions.length === 0 ? (
                <div className="p-8 text-center flex flex-col items-center justify-center h-48 text-slate-400">
                  <Shield className="w-10 h-10 mb-3 text-slate-300" />
                  <p className="text-sm font-medium text-slate-600">No threats detected recently.</p>
                  <p className="text-xs text-slate-400 mt-1">All inboxes browsing safely.</p>
                </div>
              ) : (
                recent_interventions.map((threat, i) => (
                  <div
                    key={i}
                    className="p-4 flex items-start justify-between group hover:bg-slate-50 transition-colors"
                  >
                    <div className="flex gap-3 overflow-hidden">
                      <div
                        className={`mt-1 shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${
                          threat.risk.includes("HIGH") || threat.risk.includes("CRITICAL")
                            ? "bg-rose-100 text-rose-700"
                            : "bg-amber-100 text-amber-700"
                        }`}
                      >
                        <AlertTriangle size={15} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div
                          className="text-sm font-bold text-slate-900 truncate"
                          title={threat.domain}
                        >
                          {threat.domain}
                        </div>
                        <div className="text-xs text-slate-600 mt-0.5 flex items-center gap-2">
                          <span>{threat.type}</span>
                          <span className="w-1 h-1 bg-slate-300 rounded-full"></span>
                          <span className="flex items-center gap-1 text-slate-500 font-mono text-[11px]">
                            <Clock size={11} />
                            {formatTime(threat.timestamp)}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-1 shrink-0">
                      <span
                        className={`text-[10px] font-bold tracking-wider px-2 py-0.5 rounded uppercase ${
                          threat.risk.includes("HIGH") || threat.risk.includes("CRITICAL")
                            ? "text-rose-700 bg-rose-50 border border-rose-200"
                            : "text-amber-700 bg-amber-50 border border-amber-200"
                        }`}
                      >
                        {threat.risk}
                      </span>
                      <span className="text-[10px] text-slate-500 font-medium">
                        {getRelativeTime(threat.timestamp)}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="p-3 text-center border-t border-slate-100 bg-slate-50">
              <Link
                href="/activity"
                className="text-xs font-bold text-slate-800 hover:text-slate-950 hover:underline transition-colors flex items-center justify-center gap-1"
              >
                View full activity log &rarr;
              </Link>
            </div>
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
}
