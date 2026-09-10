"use client";

import React, { useState } from "react";
import { ScanItem } from "./LiveEmailFeed";

interface Props {
  scan: ScanItem;
}

export default function EntityRelationshipGraph({ scan }: Props) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const hasMismatch = scan.geo_mismatch;
  const replyToMismatch = scan.reply_to && scan.reply_to !== "unknown" && !scan.reply_to.includes(scan.sender_domain);
  const attachments = scan.attachments || [];
  const hasDangerousAttachment = attachments.some((a) => Boolean(a?.is_dangerous));

  return (
    <div className="bg-white p-4 rounded-xl border border-slate-200 space-y-3 shadow-xs">
      <div className="flex items-center justify-between border-b border-slate-100 pb-2">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-blue-600" />
          <span className="text-xs font-bold uppercase tracking-wider text-slate-900">
            Entity Relationship Topology
          </span>
        </div>
        <span className="text-[11px] text-slate-500 font-medium">
          {hasMismatch ? "Anomalous Routing Detected" : "Nominal Topology"}
        </span>
      </div>

      {/* SVG Network Visualizer - Clean Light Canvas */}
      <div className="relative w-full overflow-hidden bg-slate-50/80 rounded-lg p-2 flex items-center justify-center min-h-[300px] border border-slate-200">
        <svg viewBox="0 0 760 300" className="w-full h-[300px] select-none">
          <defs>
            <marker id="arrowhead" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
              <polygon points="0 0, 6 3, 0 6" fill="#94a3b8" />
            </marker>
            <marker id="arrowhead-red" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
              <polygon points="0 0, 6 3, 0 6" fill="#e11d48" />
            </marker>
          </defs>

          {/* Links / Edges */}
          {/* Sender -> Origin IP */}
          <line 
            x1="130" y1="150" x2="310" y2="150" 
            stroke={hasMismatch ? "#e11d48" : "#0284c7"} 
            strokeWidth={hasMismatch ? "2" : "1.8"} 
            strokeDasharray={hasMismatch ? "4,4" : "none"}
            markerEnd={hasMismatch ? "url(#arrowhead-red)" : "url(#arrowhead)"}
          />

          {/* Sender -> Reply-To Alias */}
          {scan.reply_to && scan.reply_to !== "unknown" && (
            <line 
              x1="130" y1="130" x2="220" y2="55" 
              stroke={replyToMismatch ? "#e11d48" : "#94a3b8"} 
              strokeWidth="1.5" 
              strokeDasharray={replyToMismatch ? "3,3" : "none"}
            />
          )}

          {/* Origin IP -> Geo Location */}
          <line 
            x1="380" y1="130" x2="520" y2="60" 
            stroke={hasMismatch ? "#d97706" : "#0284c7"} 
            strokeWidth="1.8" 
          />

          {/* Origin IP -> ISP / ASN */}
          <line 
            x1="380" y1="170" x2="520" y2="230" 
            stroke="#94a3b8" 
            strokeWidth="1.5" 
          />

          {/* Origin IP -> Destination Gateway */}
          <line 
            x1="390" y1="150" x2="640" y2="150" 
            stroke="#059669" 
            strokeWidth="1.8" 
            markerEnd="url(#arrowhead)"
          />

          {/* Sender -> Attachment */}
          {attachments.length > 0 && (
            <line 
              x1="130" y1="170" x2="220" y2="245" 
              stroke={hasDangerousAttachment ? "#e11d48" : "#94a3b8"} 
              strokeWidth="1.5"
              strokeDasharray={hasDangerousAttachment ? "3,3" : "none"}
            />
          )}

          {/* NODES */}
          {/* Node 1: Sender Domain */}
          <g 
            transform="translate(110, 150)" 
            className="cursor-pointer"
            onMouseEnter={() => setHoveredNode("sender")}
            onMouseLeave={() => setHoveredNode(null)}
          >
            <circle r="36" fill="#ffffff" stroke="#0284c7" strokeWidth="2" />
            <text textAnchor="middle" y="-6" fill="#0284c7" fontSize="8" fontWeight="bold">CLAIMED DOMAIN</text>
            <text textAnchor="middle" y="10" fill="#0f172a" fontSize="10" fontWeight="bold">
              {scan.sender_domain.length > 14 ? scan.sender_domain.substring(0, 12) + "..." : scan.sender_domain}
            </text>
          </g>

          {/* Node 2: Origin IP (Core Pivot) */}
          <g 
            transform="translate(350, 150)" 
            className="cursor-pointer"
            onMouseEnter={() => setHoveredNode("ip")}
            onMouseLeave={() => setHoveredNode(null)}
          >
            <circle r="42" fill="#ffffff" stroke={hasMismatch ? "#e11d48" : "#059669"} strokeWidth="2.5" />
            <text textAnchor="middle" y="-8" fill={hasMismatch ? "#e11d48" : "#059669"} fontSize="8" fontWeight="bold">
              {hasMismatch ? "ANOMALOUS IP" : "ORIGIN IP"}
            </text>
            <text textAnchor="middle" y="10" fill="#0f172a" fontSize="11" fontWeight="bold" fontFamily="monospace">
              {scan.origin_ip}
            </text>
          </g>

          {/* Node 3: Physical Location */}
          <g 
            transform="translate(540, 60)" 
            className="cursor-pointer"
            onMouseEnter={() => setHoveredNode("geo")}
            onMouseLeave={() => setHoveredNode(null)}
          >
            <circle r="32" fill="#ffffff" stroke={hasMismatch ? "#d97706" : "#64748b"} strokeWidth="1.8" />
            <text textAnchor="middle" y="-4" fill="#64748b" fontSize="8" fontWeight="bold">LOCATION</text>
            <text textAnchor="middle" y="10" fill="#0f172a" fontSize="9" fontWeight="bold">
              {scan.origin_country.length > 10 ? scan.origin_country.substring(0, 9) + ".." : scan.origin_country}
            </text>
          </g>

          {/* Node 4: Autonomous System / ISP */}
          <g 
            transform="translate(540, 230)" 
            className="cursor-pointer"
            onMouseEnter={() => setHoveredNode("isp")}
            onMouseLeave={() => setHoveredNode(null)}
          >
            <circle r="32" fill="#ffffff" stroke="#64748b" strokeWidth="1.8" />
            <text textAnchor="middle" y="-4" fill="#64748b" fontSize="8" fontWeight="bold">ISP / ASN</text>
            <text textAnchor="middle" y="10" fill="#0f172a" fontSize="8" fontFamily="monospace" fontWeight="bold">
              {scan.origin_asn && scan.origin_asn !== "N/A" ? scan.origin_asn : "Transit ISP"}
            </text>
          </g>

          {/* Node 5: Reply-To Alias (If present) */}
          {scan.reply_to && scan.reply_to !== "unknown" && (
            <g 
              transform="translate(240, 50)" 
              className="cursor-pointer"
              onMouseEnter={() => setHoveredNode("replyto")}
              onMouseLeave={() => setHoveredNode(null)}
            >
              <rect x="-65" y="-18" width="130" height="36" rx="18" fill="#ffffff" stroke={replyToMismatch ? "#e11d48" : "#0284c7"} strokeWidth="1.8" />
              <text textAnchor="middle" y="-2" fill={replyToMismatch ? "#e11d48" : "#0284c7"} fontSize="8" fontWeight="bold">
                {replyToMismatch ? "DIVERGENT REPLY-TO" : "REPLY-TO ALIAS"}
              </text>
              <text textAnchor="middle" y="11" fill="#0f172a" fontSize="8" fontFamily="monospace" fontWeight="bold">
                {scan.reply_to.length > 18 ? scan.reply_to.substring(0, 16) + "..." : scan.reply_to}
              </text>
            </g>
          )}

          {/* Node 6: Attachment Node (If present) */}
          {attachments.length > 0 && (
            <g 
              transform="translate(240, 245)" 
              className="cursor-pointer"
              onMouseEnter={() => setHoveredNode("attachment")}
              onMouseLeave={() => setHoveredNode(null)}
            >
              <rect x="-65" y="-18" width="130" height="36" rx="8" fill="#ffffff" stroke={hasDangerousAttachment ? "#e11d48" : "#0284c7"} strokeWidth="1.8" />
              <text textAnchor="middle" y="-2" fill={hasDangerousAttachment ? "#e11d48" : "#0284c7"} fontSize="8" fontWeight="bold">
                {hasDangerousAttachment ? "DANGEROUS FILE" : "ATTACHMENT"}
              </text>
              <text textAnchor="middle" y="11" fill="#0f172a" fontSize="8" fontFamily="monospace" fontWeight="bold">
                {(attachments[0]?.filename || "file").length > 16 
                  ? (attachments[0]?.filename || "file").substring(0, 14) + "..." 
                  : (attachments[0]?.filename || "file")}
              </text>
            </g>
          )}

          {/* Node 7: Destination Gateway */}
          <g 
            transform="translate(670, 150)" 
            className="cursor-pointer"
            onMouseEnter={() => setHoveredNode("dest")}
            onMouseLeave={() => setHoveredNode(null)}
          >
            <circle r="34" fill="#ffffff" stroke="#059669" strokeWidth="2" />
            <text textAnchor="middle" y="-6" fill="#059669" fontSize="8" fontWeight="bold">DESTINATION</text>
            <text textAnchor="middle" y="10" fill="#0f172a" fontSize="9" fontWeight="bold">
              mx.google.com
            </text>
          </g>
        </svg>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs pt-1 border-t border-slate-100">
        <div className="flex items-center gap-4 text-slate-600 font-medium">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-blue-600 rounded" /> Nominal Route
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-rose-600 rounded" /> Threat Divergence
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-emerald-600 rounded" /> Verified Delivery
          </span>
        </div>

        <div className="text-slate-500 text-[11px]">
          {hoveredNode ? (
            <span className="text-slate-900 font-semibold uppercase">Selected: {hoveredNode}</span>
          ) : (
            <>Pivot: <span className="font-mono text-slate-800 font-semibold">{scan.origin_ip}</span> ({scan.origin_isp})</>
          )}
        </div>
      </div>
    </div>
  );
}
