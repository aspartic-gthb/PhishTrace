"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";

function SimpleSwitch({ checked, onCheckedChange }: { checked: boolean; onCheckedChange: (c: boolean) => void }) {
  return (
    <button 
      className={cn("w-11 h-6 rounded-full transition-colors relative cursor-pointer", checked ? "bg-emerald-600" : "bg-slate-300")}
      onClick={() => onCheckedChange(!checked)}
    >
      <div className={cn("w-5 h-5 bg-white rounded-full absolute top-0.5 transition-transform shadow-sm", checked ? "left-[22px]" : "left-0.5")} />
    </button>
  );
}

export default function SettingsPage() {
  const [sensitivity, setSensitivity] = useState(50);
  const [autoBlock, setAutoBlock] = useState(true);
  const [dataCollection, setDataCollection] = useState(true);

  return (
    <div className="space-y-8 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          Controls & Preferences
        </h1>
        <p className="text-sm text-slate-600 font-medium mt-1">
          Customize how PhishTrace protects your browsing and email stream.
        </p>
      </div>

      {/* Sensitivity */}
      <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-sm">
        <h3 className="text-base font-bold text-slate-900 mb-1">Detection Sensitivity</h3>
        <p className="text-sm text-slate-600 font-medium mb-6">
          Adjust how aggressive the ML threat engine should be when flagging suspicious headers.
        </p>
        
        <div className="space-y-4">
          <input 
            type="range" 
            min="0" 
            max="100" 
            value={sensitivity} 
            onChange={(e) => setSensitivity(parseInt(e.target.value))}
            className="w-full h-2 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900" 
          />
          <div className="flex justify-between text-xs text-slate-600 font-bold uppercase tracking-wider">
            <span>Conservative</span>
            <span className="text-slate-900 font-extrabold">Balanced (50%)</span>
            <span>Aggressive</span>
          </div>
        </div>
      </div>

      {/* Toggles */}
      <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-sm space-y-6 divide-y divide-slate-100">
        <div className="flex items-center justify-between pt-2">
          <div>
            <h4 className="font-bold text-slate-900 text-sm">Auto-Block High Risk Threats</h4>
            <p className="text-sm text-slate-600 font-medium mt-0.5">
              Automatically flag and quarantine emails with &gt;70% risk score.
            </p>
          </div>
          <SimpleSwitch checked={autoBlock} onCheckedChange={setAutoBlock} />
        </div>

        <div className="flex items-center justify-between pt-6">
          <div>
            <h4 className="font-bold text-slate-900 text-sm">Threat Intelligence Sharing</h4>
            <p className="text-sm text-slate-600 font-medium mt-0.5">
              Sync anonymized malicious IP hashes with the central detection graph.
            </p>
          </div>
          <SimpleSwitch checked={dataCollection} onCheckedChange={setDataCollection} />
        </div>
      </div>
    </div>
  );
}
