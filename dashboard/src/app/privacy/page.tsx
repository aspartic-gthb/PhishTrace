"use client";

import { EyeOff, Hash, FileJson, ShieldCheck } from "lucide-react";

export default function PrivacyPage() {
  return (
    <div className="space-y-8 max-w-3xl">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
            DPDP & GDPR COMPLIANT
          </span>
        </div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          Privacy Center & Data Sovereignty
        </h1>
        <p className="text-sm text-slate-600 font-medium mt-1">
          Transparency report and cryptographic safeguards protecting enterprise and personal data.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-5 rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="w-10 h-10 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center mb-3">
            <EyeOff className="w-5 h-5" />
          </div>
          <h3 className="font-bold text-slate-900 text-base">No PII Stored Plaintext</h3>
          <p className="text-xs text-slate-600 mt-1 font-medium leading-relaxed">
            All scanned emails, headers, and usernames undergo automatic redaction before database persistence or forensic report generation.
          </p>
        </div>

        <div className="p-5 rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="w-10 h-10 rounded-lg bg-slate-100 text-slate-800 flex items-center justify-center mb-3">
            <Hash className="w-5 h-5" />
          </div>
          <h3 className="font-bold text-slate-900 text-base">Cryptographic Chain-of-Custody</h3>
          <p className="text-xs text-slate-600 mt-1 font-medium leading-relaxed">
            Each threat report is stamped with an immutable SHA-256 digital forensic hash, ensuring legal admissible evidence verification.
          </p>
        </div>
      </div>

      <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-sm space-y-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-600" />
          <h3 className="text-base font-bold text-slate-900">Local Evidence Vault</h3>
        </div>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3.5 bg-slate-50 rounded-lg border border-slate-200">
            <div className="flex items-center gap-3">
              <FileJson size={18} className="text-slate-700" />
              <div>
                <span className="text-sm font-mono font-bold text-slate-900">forensic_scans.db</span>
                <span className="text-xs text-slate-500 block">AES-256 Encrypted SQLite Storage</span>
              </div>
            </div>
            <div className="text-xs font-mono font-bold text-slate-600">Active Vault</div>
          </div>
          <p className="text-xs text-slate-600 font-medium leading-relaxed">
            Your encrypted database stores only anonymized indicators of compromise (IOCs), sender domain reputation scores, and verification timestamps.
          </p>
        </div>
      </div>
    </div>
  );
}
