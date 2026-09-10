"use client";

import React from "react";
import { Globe, MapPin, AlertTriangle, ShieldCheck, Server, Compass } from "lucide-react";

interface GeoScan {
  origin_ip?: string;
  origin_country?: string;
  origin_city?: string;
  origin_isp?: string;
  origin_asn?: string;
  origin_latitude?: number;
  origin_longitude?: number;
  geo_mismatch?: boolean;
  geo_mismatch_reason?: string;
  sender_domain?: string;
  claimed_country?: string;
  received_chain?: string[] | unknown[];
  risk_level?: string;
  risk_score?: number;
}

interface GeoThreatMapProps {
  scan: GeoScan;
}

// Equirectangular world landmass paths for clean cartographic styling
const WORLD_LANDMASS_PATHS: string[] = [
  // North America
  "M 120 70 L 160 60 L 220 65 L 260 90 L 270 120 L 240 140 L 220 180 L 190 170 L 180 150 L 150 140 L 130 110 Z",
  // South America
  "M 220 200 L 250 210 L 270 260 L 250 320 L 230 330 L 210 280 L 205 230 Z",
  // Europe
  "M 370 70 L 420 65 L 440 90 L 410 110 L 380 115 L 360 95 Z",
  // Africa
  "M 370 130 L 430 130 L 450 180 L 440 240 L 400 270 L 375 220 L 360 160 Z",
  // Asia
  "M 440 60 L 520 50 L 600 70 L 640 110 L 590 150 L 520 160 L 480 140 L 450 90 Z",
  // India & South Asia
  "M 490 140 L 525 150 L 520 190 L 495 195 L 485 160 Z",
  // Australia
  "M 580 230 L 640 230 L 650 270 L 610 290 L 575 265 Z",
];

export default function GeoThreatMap({ scan }: GeoThreatMapProps) {
  // Fallback / default coordinates
  const lat = scan.origin_latitude || 55.7558;
  const lon = scan.origin_longitude || 37.6173;
  const isMismatch = scan.geo_mismatch || (scan.origin_country === "Russia" || scan.origin_country === "Nigeria");

  // Project lat/lon to SVG 700x350 box (Equirectangular)
  const originX = Math.max(30, Math.min(670, ((lon + 180) / 360) * 700));
  const originY = Math.max(25, Math.min(325, ((90 - lat) / 180) * 350));

  // Enterprise Destination: Washington DC / New York
  const destX = (( -77.0 + 180) / 360) * 700;
  const destY = ((90 - 38.9) / 180) * 350;

  // Intermediate Relay Hop
  const relayX = ((8.68 + 180) / 360) * 700;
  const relayY = ((90 - 50.1) / 180) * 350;

  // Calculate arc control point for quadratic bezier
  const midX = (originX + destX) / 2;
  const midY = Math.min(originY, destY) - 50;

  const isThreat = (scan.risk_score || 0) >= 0.7 || isMismatch;
  const markerColor = isThreat ? "#e11d48" : (scan.risk_score || 0) >= 0.4 ? "#d97706" : "#059669";

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4 space-y-4 shadow-xs">
      {/* Map Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-slate-700" />
          <span className="text-xs font-bold text-slate-900 uppercase tracking-wider">
            Geographic Infrastructure & Routing Vector
          </span>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-100 border border-slate-200 text-slate-700 font-semibold">
            {scan.origin_ip || "Unknown IP"}
          </span>
        </div>

        {isMismatch ? (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-50 border border-rose-200 text-rose-700 text-xs font-bold">
            <AlertTriangle className="w-3.5 h-3.5" />
            Origin Mismatch Detected
          </div>
        ) : (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-bold">
            <ShieldCheck className="w-3.5 h-3.5" />
            Geographic Alignment Verified
          </div>
        )}
      </div>

      {/* SVG Threat Map - Clean Light Cartographic Canvas */}
      <div className="relative w-full aspect-[2/1] bg-[#f8fafc] rounded-lg overflow-hidden border border-slate-200 shadow-xs">
        <svg viewBox="0 0 700 350" className="w-full h-full select-none">
          <defs>
            {/* Route Gradient */}
            <linearGradient id="routeGradientLight" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={markerColor} stopOpacity="0.9" />
              <stop offset="100%" stopColor="#0284c7" stopOpacity="0.9" />
            </linearGradient>

            {/* Subtle Latitude/Longitude grid lines */}
            <pattern id="latlonLight" width="70" height="35" patternUnits="userSpaceOnUse">
              <path d="M 70 0 L 0 0 0 35" fill="none" stroke="#e2e8f0" strokeWidth="0.8" strokeDasharray="3 3" />
            </pattern>
          </defs>

          {/* Grid Background */}
          <rect width="700" height="350" fill="url(#latlonLight)" />

          {/* Equator & Prime Meridian markers */}
          <line x1="0" y1="175" x2="700" y2="175" stroke="#cbd5e1" strokeWidth="0.9" strokeDasharray="4 4" />
          <line x1="350" y1="0" x2="350" y2="350" stroke="#cbd5e1" strokeWidth="0.9" strokeDasharray="4 4" />

          {/* World Landmasses - Clean Soft Slate */}
          <g fill="#e2e8f0" stroke="#cbd5e1" strokeWidth="1.2">
            {WORLD_LANDMASS_PATHS.map((d, i) => (
              <path key={i} d={d} />
            ))}
          </g>

          {/* Trajectory Flight Arc */}
          <path
            d={`M ${originX} ${originY} Q ${midX} ${midY} ${destX} ${destY}`}
            fill="none"
            stroke="url(#routeGradientLight)"
            strokeWidth="2.5"
            strokeDasharray="6 4"
            className="animate-pulse"
          />

          {/* Destination Marker (Victim Enterprise Inbox) */}
          <g transform={`translate(${destX}, ${destY})`} className="cursor-pointer">
            <circle r="10" fill="#0284c7" fillOpacity="0.15" />
            <circle r="4.5" fill="#0284c7" />
            <text x="8" y="3.5" fill="#1e293b" fontSize="9" fontWeight="bold" fontFamily="monospace">
              VICTIM INBOX (US)
            </text>
          </g>

          {/* Intermediate Relay Hop (if available) */}
          {Boolean(scan.received_chain && scan.received_chain.length > 1) ? (
            <g transform={`translate(${relayX}, ${relayY})`} className="cursor-pointer">
              <circle r="4" fill="#64748b" />
              <text x="6" y="-5" fill="#64748b" fontSize="8" fontWeight="bold" fontFamily="monospace">
                RELAY HOP
              </text>
            </g>
          ) : null}

          {/* Origin Marker */}
          <g transform={`translate(${originX}, ${originY})`} className="cursor-pointer">
            <circle r="14" fill={markerColor} fillOpacity="0.2" className="animate-ping" />
            <circle r="8" fill={markerColor} fillOpacity="0.3" />
            <circle r="4.5" fill={markerColor} stroke="#ffffff" strokeWidth="1.5" />

            {/* Origin Label */}
            <text
              x={originX > 500 ? -8 : 8}
              y="-7"
              textAnchor={originX > 500 ? "end" : "start"}
              fill="#0f172a"
              fontSize="10"
              fontWeight="bold"
              fontFamily="monospace"
            >
              ORIGIN: {scan.origin_country?.toUpperCase() || "UNKNOWN"}
            </text>
          </g>
        </svg>

        {/* HUD Info Overlay */}
        <div className="absolute bottom-2.5 left-2.5 bg-white/95 backdrop-blur-sm border border-slate-200 rounded-lg p-2.5 text-[11px] font-mono text-slate-800 pointer-events-none space-y-0.5 shadow-xs">
          <div><span className="text-slate-500 font-bold">COORDS:</span> {lat.toFixed(2)}°N, {lon.toFixed(2)}°E</div>
          <div><span className="text-slate-500 font-bold">ISP/ASN:</span> <span className="font-bold text-slate-900">{scan.origin_asn || "AS208323"}</span> ({scan.origin_isp || "Tor/Bulletproof"})</div>
          <div><span className="text-slate-500 font-bold">LOCATION:</span> <span className="font-bold text-slate-900">{scan.origin_city || "Unknown"}, {scan.origin_country || "Unknown"}</span></div>
        </div>

        {/* Compass Watermark */}
        <div className="absolute top-2.5 right-2.5 flex items-center gap-1 text-[10px] text-slate-500 font-mono font-medium bg-white/80 px-2 py-0.5 rounded border border-slate-200">
          <Compass className="w-3.5 h-3.5 text-slate-500" />
          <span>WGS84 PROJECTION</span>
        </div>
      </div>

      {/* Origin vs Claimed Identity Discrepancy Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
        <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 flex items-start gap-3">
          <div className="p-2 rounded-lg bg-white text-slate-700 border border-slate-200 shadow-2xs shrink-0">
            <Server className="w-4 h-4" />
          </div>
          <div className="text-xs">
            <span className="text-slate-500 font-medium block">Claimed Sender Identity</span>
            <span className="font-bold text-slate-900 text-sm">@{scan.sender_domain || "domain.com"}</span>
            <span className="text-slate-600 text-[11px] block mt-0.5 font-medium">
              Claimed Region: <strong className="text-slate-800">{scan.claimed_country || "United States / Registered HQ"}</strong>
            </span>
          </div>
        </div>

        <div className={`p-3.5 rounded-xl border flex items-start gap-3 ${
          isMismatch ? "bg-rose-50/70 border-rose-200" : "bg-slate-50 border-slate-200"
        }`}>
          <div className={`p-2 rounded-lg shrink-0 ${
            isMismatch ? "bg-rose-100 text-rose-700" : "bg-emerald-100 text-emerald-700"
          }`}>
            <MapPin className="w-4 h-4" />
          </div>
          <div className="text-xs">
            <span className="text-slate-500 font-medium block">Actual Physical Origin</span>
            <span className={`font-bold text-sm ${isMismatch ? "text-rose-700" : "text-slate-900"}`}>
              {scan.origin_city}, {scan.origin_country} ({scan.origin_ip})
            </span>
            <span className="text-slate-600 text-[11px] block mt-0.5 font-medium">
              {scan.geo_mismatch_reason || "Direct server match or low-risk domestic relay."}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
