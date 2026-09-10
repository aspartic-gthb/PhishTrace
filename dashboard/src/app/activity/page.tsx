"use client";

import { Shield, Globe, Clock, AlertTriangle, Loader2, Download } from "lucide-react";
import { useEffect, useState } from "react";

interface ActivityItem {
  id: number;
  domain: string;
  timestamp: string;
  risk_score: number;
  risk_level: string;
  status: string;
  category: string;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8005/api/v1";

export default function ActivityPage() {
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchActivity = async () => {
      try {
        const res = await fetch(`${API_BASE}/activity`);
        if (res.ok) {
          const data = await res.json();
          setActivity(data);
        }
      } catch (error) {
        console.error("Failed to fetch activity:", error);
      } finally {
        setLoading(false);
      }
    };
    fetchActivity();
    const interval = setInterval(fetchActivity, 12000);
    return () => clearInterval(interval);
  }, []);

  const formatTime = (isoString: string) => {
    try {
      const date = new Date(isoString);
      return new Intl.DateTimeFormat("en-US", {
        hour: "numeric",
        minute: "2-digit",
        month: "short",
        day: "numeric"
      }).format(date);
    } catch {
      return "Recent";
    }
  };

  if (loading) {
    return (
      <div className="flex h-[50vh] flex-col items-center justify-center text-slate-500 gap-4">
        <Loader2 className="w-8 h-8 text-slate-800 animate-spin" />
        <p className="font-medium text-sm text-slate-600">Loading Activity Log...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Activity Insights
          </h1>
          <p className="text-sm text-slate-600 font-medium mt-0.5">
            Detailed chronological log of scanned interactions and blocked threats.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => {
              const headers = "ID,Domain,Timestamp,Category,Status,RiskScore\n";
              const rows = activity.map(a => `${a.id},${a.domain},${a.timestamp},${a.category},${a.status},${a.risk_score}`).join("\n");
              const blob = new Blob([headers + rows], { type: "text/csv" });
              const url = URL.createObjectURL(blob);
              const link = document.createElement("a");
              link.href = url;
              link.download = "phistrace_activity_log.csv";
              link.click();
              URL.revokeObjectURL(url);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 shadow-xs transition-colors cursor-pointer"
          >
            <Download size={14} /> Export CSV
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden shadow-sm">
        <table className="w-full text-sm text-left">
          <thead className="bg-slate-50 border-b border-slate-200 text-slate-700 font-bold text-xs">
            <tr>
              <th className="px-6 py-3.5">Timestamp</th>
              <th className="px-6 py-3.5">Domain / Subject</th>
              <th className="px-6 py-3.5">Category</th>
              <th className="px-6 py-3.5">Verdict Status</th>
              <th className="px-6 py-3.5 text-right">Risk Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {activity.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-slate-500 font-medium">
                  No activity recorded yet. Scans will automatically appear here.
                </td>
              </tr>
            ) : (
              activity.map((item) => (
                <tr key={item.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-3.5 flex items-center gap-2 text-slate-500 text-xs font-mono whitespace-nowrap">
                    <Clock size={14} className="text-slate-400" /> {formatTime(item.timestamp)}
                  </td>
                  <td className="px-6 py-3.5 font-bold text-slate-900 text-sm">
                    {item.domain}
                  </td>
                  <td className="px-6 py-3.5">
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-slate-100 text-xs font-semibold text-slate-700 border border-slate-200">
                      <Globe size={11} className="text-slate-500" /> {item.category}
                    </span>
                  </td>
                  <td className="px-6 py-3.5">
                    {item.status === "SAFE" && (
                      <span className="text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 rounded-full flex w-fit items-center gap-1 font-bold text-xs">
                        <Shield size={11} /> Safe
                      </span>
                    )}
                    {item.status === "BLOCKED" && (
                      <span className="text-rose-700 bg-rose-50 border border-rose-200 px-2.5 py-0.5 rounded-full flex w-fit items-center gap-1 font-bold text-xs">
                        <Shield size={11} fill="currentColor" /> Blocked
                      </span>
                    )}
                    {item.status === "WARNED" && (
                      <span className="text-amber-700 bg-amber-50 border border-amber-200 px-2.5 py-0.5 rounded-full flex w-fit items-center gap-1 font-bold text-xs">
                        <AlertTriangle size={11} /> Suspicious
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-3.5 text-right font-mono font-bold">
                    <span className={item.risk_score >= 0.7 ? "text-rose-600 font-extrabold" : item.risk_score >= 0.4 ? "text-amber-600 font-bold" : "text-emerald-600"}>
                      {(item.risk_score * 100).toFixed(0)}%
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        <div className="p-3 border-t border-slate-100 text-center text-xs text-slate-500 bg-slate-50 font-medium">
          Showing {activity.length} verified security events.
        </div>
      </div>
    </div>
  );
}
