"use client";
import React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  AlertTriangle,
  FileWarning,
  Monitor,
  Play,
  Search,
  Users,
  Ticket,
  ScrollText,
  BarChart3,
  Settings,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Flame,
} from "lucide-react";
import { clearAuth, getUser } from "@/lib/auth";

interface SidebarProps {
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  isMobileOpen?: boolean;
  onCloseMobile?: () => void;
}

const navSections = [
  {
    title: "MONITORING",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/threats", label: "Threat Detection", icon: AlertTriangle, badge: "Live" },
      { href: "/incidents", label: "Incident Management", icon: FileWarning },
    ],
  },
  {
    title: "RESPONSE & CONTROL",
    items: [
      { href: "/endpoints", label: "Endpoint Management", icon: Monitor },
      { href: "/playbooks", label: "Automated Playbooks", icon: Play },
      { href: "/forensics", label: "Digital Forensics", icon: Search },
    ],
  },
  {
    title: "OPERATIONS",
    items: [
      { href: "/identity", label: "User & Identity", icon: Users },
      { href: "/jira", label: "Jira Tickets", icon: Ticket },
      { href: "/audit", label: "Audit Logs", icon: ScrollText },
      { href: "/reports", label: "Reports", icon: BarChart3 },
    ],
  },
  {
    title: "SYSTEM",
    items: [
      { href: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export default function Sidebar({
  isCollapsed = false,
  onToggleCollapse,
  isMobileOpen = false,
  onCloseMobile,
}: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const user = getUser();

  const handleLogout = () => {
    clearAuth();
    router.push("/login");
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/60 dark:bg-black/75 backdrop-blur-sm z-40 lg:hidden"
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 bg-white dark:bg-[#0B1220] border-r border-slate-200 dark:border-[#263449] flex flex-col z-50 transition-all duration-300 ease-in-out ${
          isCollapsed ? "w-20" : "w-64"
        } ${isMobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}`}
      >
        {/* Brand Header */}
        <div className="flex items-center justify-between px-5 h-16 border-b border-slate-200 dark:border-[#263449]">
          <Link
            href="/dashboard"
            onClick={onCloseMobile}
            className="flex items-center gap-3 group"
          >
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#2563EB] via-[#3B82F6] to-[#1E40AF] flex items-center justify-center shadow-md flex-shrink-0 group-hover:scale-105 transition-transform">
              <Shield className="w-5 h-5 text-white" />
            </div>
            {!isCollapsed && (
              <div className="overflow-hidden">
                <div className="flex items-center gap-1.5">
                  <h1 className="text-slate-900 dark:text-white font-extrabold text-base tracking-wider font-mono">
                    ZAALIMA
                  </h1>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                </div>
                <p className="text-slate-500 dark:text-[#94A3B8] text-[10px] font-semibold uppercase tracking-widest leading-none">
                  Cyber Orchestrator
                </p>
              </div>
            )}
          </Link>

          {/* Desktop Collapse Toggle */}
          {onToggleCollapse && (
            <button
              onClick={onToggleCollapse}
              className="hidden lg:flex p-1.5 rounded-lg text-slate-400 dark:text-[#64748B] hover:text-slate-700 dark:hover:text-[#F8FAFC] hover:bg-slate-100 dark:hover:bg-[#111B2E] transition-colors"
              title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
            >
              {isCollapsed ? (
                <ChevronRight className="w-4 h-4" />
              ) : (
                <ChevronLeft className="w-4 h-4" />
              )}
            </button>
          )}
        </div>

        {/* Live Threat Bar */}
        {!isCollapsed && (
          <div className="px-4 py-2.5 mx-3 my-2 rounded-xl bg-slate-50 dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] flex items-center justify-between transition-colors">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              <span className="text-[11px] font-mono font-semibold text-slate-800 dark:text-[#F8FAFC]">
                SOC DEFENSE
              </span>
            </div>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 font-bold">
              ACTIVE
            </span>
          </div>
        )}

        {/* Navigation Sections */}
        <nav className="flex-1 px-3 py-2 space-y-4 overflow-y-auto">
          {navSections.map((section) => (
            <div key={section.title} className="space-y-1">
              {!isCollapsed && (
                <p className="px-3 text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-[#64748B] mb-1">
                  {section.title}
                </p>
              )}
              {section.items.map(({ href, label, icon: Icon, badge }: any) => {
                const isActive =
                  pathname === href || pathname.startsWith(href + "/");
                return (
                  <Link
                    key={href}
                    href={href}
                    onClick={onCloseMobile}
                    title={isCollapsed ? label : undefined}
                    className={`flex items-center gap-3 px-3 py-2 rounded-xl text-xs font-medium transition-all duration-150 group relative ${
                      isActive
                        ? "bg-blue-50 dark:bg-blue-600/15 text-blue-600 dark:text-blue-400 font-semibold border border-blue-200 dark:border-blue-500/30 shadow-sm"
                        : "text-slate-600 dark:text-[#94A3B8] hover:bg-slate-100 dark:hover:bg-[#111B2E] hover:text-slate-900 dark:hover:text-[#F8FAFC]"
                    }`}
                  >
                    {/* Active vertical accent indicator */}
                    {isActive && (
                      <span className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-blue-600 dark:bg-[#3B82F6] rounded-r" />
                    )}

                    <Icon
                      className={`w-4 h-4 flex-shrink-0 transition-colors ${
                        isActive
                          ? "text-blue-600 dark:text-[#3B82F6]"
                          : "text-slate-400 dark:text-[#64748B] group-hover:text-slate-600 dark:group-hover:text-[#94A3B8]"
                      }`}
                    />

                    {!isCollapsed && (
                      <span className="truncate flex-1">{label}</span>
                    )}

                    {!isCollapsed && badge && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30">
                        {badge}
                      </span>
                    )}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>

        {/* User Card & Sign Out */}
        <div className="p-3 border-t border-slate-200 dark:border-[#263449] bg-slate-50/50 dark:bg-[#080D19]/60 transition-colors">
          {!isCollapsed && user && (
            <div className="flex items-center gap-3 mb-2 px-2 py-1.5 rounded-lg bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449]">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center text-white text-xs font-bold border border-blue-400/30 shadow-sm flex-shrink-0">
                {user.username ? user.username[0].toUpperCase() : "A"}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-bold text-slate-800 dark:text-[#F8FAFC] truncate">
                  {user.username}
                </p>
                <p className="text-[10px] text-slate-500 dark:text-[#94A3B8] truncate capitalize font-mono">
                  {user.role?.replace("_", " ") || "SOC Analyst"}
                </p>
              </div>
            </div>
          )}

          <button
            onClick={handleLogout}
            className={`flex items-center gap-2.5 w-full py-2 rounded-lg text-xs font-medium text-slate-600 dark:text-[#94A3B8] hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors cursor-pointer ${
              isCollapsed ? "justify-center px-0" : "px-3"
            }`}
            title="Sign out of SOC Console"
          >
            <LogOut className="w-4 h-4 flex-shrink-0" />
            {!isCollapsed && <span>Sign Out</span>}
          </button>
        </div>
      </aside>
    </>
  );
}
