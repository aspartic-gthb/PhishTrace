"use client";

import { motion } from "framer-motion";
import { ShieldCheck, ShieldAlert, Shield } from "lucide-react";
import { cn } from "@/lib/utils";

export function RiskScoreCard({ score }: { score: number }) {
  const safetyScore = Math.round((1 - score) * 100);

  let riskLevel = "Safe";
  let color = "text-emerald-600";
  let bgColor = "bg-emerald-50 text-emerald-700 border border-emerald-200";
  let barColor = "bg-emerald-500";
  let Icon = ShieldCheck;

  if (score > 0.7) {
    riskLevel = "Critical";
    color = "text-rose-600";
    bgColor = "bg-rose-50 text-rose-700 border border-rose-200";
    barColor = "bg-rose-500";
    Icon = ShieldAlert;
  } else if (score > 0.4) {
    riskLevel = "Moderate";
    color = "text-amber-600";
    bgColor = "bg-amber-50 text-amber-700 border border-amber-200";
    barColor = "bg-amber-500";
    Icon = Shield;
  }

  return (
    <div className="p-6 rounded-2xl border border-slate-200 bg-white shadow-sm relative overflow-hidden h-full flex flex-col justify-between">
      <div>
        <div className="flex justify-between items-start mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">
              Safety Health
            </h3>
            <p className="text-xs text-slate-500 mt-1 font-medium">
              Based on active threat analysis
            </p>
          </div>
          <div className={cn("p-2 rounded-lg", bgColor)}>
            <Icon className="w-5 h-5" />
          </div>
        </div>

        <div className="flex items-baseline gap-2 mt-2">
          <span className={cn("text-4xl font-extrabold tracking-tight", color)}>
            {safetyScore}
          </span>
          <span className="text-sm font-medium text-slate-500">/ 100</span>
        </div>
      </div>

      <div className="mt-6">
        <div className="h-2.5 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${safetyScore}%` }}
            transition={{ duration: 1, ease: "easeOut" }}
            className={cn("h-full rounded-full", barColor)}
          />
        </div>
        <div className="mt-2.5 flex justify-between text-xs font-semibold">
          <span className={color}>{riskLevel} Status</span>
          <span className="text-slate-500">Nominal Protection</span>
        </div>
      </div>
    </div>
  );
}
