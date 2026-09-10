"use client";

import React from "react";
import { Shield, LayoutDashboard, Activity, Settings, Lock, Mail } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  const getBreadcrumb = () => {
    switch (pathname) {
      case "/":
        return "Overview";
      case "/gmail":
        return "Gmail Verification";
      case "/activity":
        return "Activity Insights";
      case "/privacy":
        return "Privacy Center";
      case "/settings":
        return "Controls";
      default:
        return "Overview";
    }
  };

  return (
    <div className="flex h-screen bg-white text-slate-900 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-200 bg-slate-50 flex flex-col shrink-0">
        <div className="p-6 flex items-center gap-2 border-b border-slate-200">
          <div className="w-8 h-8 rounded-lg bg-slate-900 text-white flex items-center justify-center shadow-xs">
            <Shield size={18} />
          </div>
          <span className="font-bold text-base tracking-tight text-slate-900">
            PhishTrace
          </span>
        </div>

        <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
          <NavLink href="/" icon={<LayoutDashboard size={18} />} currentPath={pathname}>
            Overview
          </NavLink>
          <NavLink href="/gmail" icon={<Mail size={18} />} currentPath={pathname}>
            Gmail Verification
          </NavLink>
          <NavLink href="/activity" icon={<Activity size={18} />} currentPath={pathname}>
            Activity Insights
          </NavLink>
          <NavLink href="/privacy" icon={<Lock size={18} />} currentPath={pathname}>
            Privacy Center
          </NavLink>
          <NavLink href="/settings" icon={<Settings size={18} />} currentPath={pathname}>
            Controls
          </NavLink>
        </nav>

        <div className="p-4 border-t border-slate-200">
          <div className="p-3 bg-white rounded-lg border border-slate-200 shadow-xs">
            <div className="text-xs text-slate-500 uppercase font-semibold mb-1">
              Status
            </div>
            <div className="flex items-center gap-2 text-sm font-medium text-emerald-600">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              System Active
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden bg-white">
        <header className="h-16 border-b border-slate-200 flex items-center justify-between px-8 bg-white/80 backdrop-blur sticky top-0 z-10 shrink-0">
          <div className="text-sm text-slate-500 font-medium">
            Console / <span className="text-slate-900 font-semibold">{getBreadcrumb()}</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="w-8 h-8 rounded-full bg-slate-100 text-slate-700 flex items-center justify-center text-xs font-semibold border border-slate-200">
              U
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8 max-w-7xl w-full mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}

function NavLink({
  href,
  icon,
  children,
  currentPath,
}: {
  href: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  currentPath: string;
}) {
  const isActive = currentPath === href;

  return (
    <Link
      href={href}
      className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
        isActive
          ? "bg-slate-200/80 text-slate-900 font-bold"
          : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
      }`}
    >
      <span className={isActive ? "text-slate-900" : "text-slate-500"}>
        {icon}
      </span>
      <span>{children}</span>
    </Link>
  );
}
