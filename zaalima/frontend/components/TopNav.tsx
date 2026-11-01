"use client";
import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Search,
  Bell,
  Clock,
  Shield,
  CheckCircle2,
  AlertCircle,
  Menu,
  X,
  ChevronDown,
  LogOut,
  User,
  ExternalLink,
} from "lucide-react";
import { getUser, clearAuth } from "@/lib/auth";
import { crowdstrikeAPI } from "@/lib/api";
import ThemeToggle from "@/components/ThemeToggle";

interface TopNavProps {
  onMobileMenuToggle?: () => void;
  isMobileMenuOpen?: boolean;
}

export default function TopNav({
  onMobileMenuToggle,
  isMobileMenuOpen,
}: TopNavProps) {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [csStatus, setCsStatus] = useState<string>("CHECKING");
  const [currentTime, setCurrentTime] = useState<string>("");
  const [utcTime, setUtcTime] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  useEffect(() => {
    setUser(getUser());

    // Update real-time clock
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(
        now.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })
      );
      setUtcTime(
        now.toUTCString().slice(17, 25) + " UTC"
      );
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);

    // Fetch CrowdStrike status
    crowdstrikeAPI
      .status()
      .then((res) => {
        setCsStatus(res.data?.status || "DISCONNECTED");
      })
      .catch(() => setCsStatus("DISCONNECTED"));

    return () => clearInterval(timer);
  }, []);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      router.push(`/threats?search=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  const handleLogout = () => {
    clearAuth();
    router.push("/login");
  };

  return (
    <header className="sticky top-0 z-40 bg-white/95 dark:bg-[#0B1220]/95 backdrop-blur-md border-b border-slate-200 dark:border-[#263449] h-16 flex items-center justify-between px-4 lg:px-8 transition-colors duration-200">
      {/* Left: Mobile hamburger & Global Search */}
      <div className="flex items-center gap-3 flex-1 max-w-xl">
        <button
          onClick={onMobileMenuToggle}
          className="lg:hidden p-2 rounded-lg text-slate-500 hover:text-slate-900 dark:text-[#94A3B8] dark:hover:text-[#F8FAFC] hover:bg-slate-100 dark:hover:bg-[#111B2E] transition-colors"
          aria-label="Toggle Navigation Menu"
        >
          {isMobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>

        <form onSubmit={handleSearchSubmit} className="relative w-full max-w-md hidden sm:block">
          <Search className="w-4 h-4 text-slate-400 dark:text-[#64748B] absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search threats, endpoints, IOCs, CVEs..."
            className="w-full bg-slate-100 dark:bg-[#080D19] border border-slate-200 dark:border-[#263449] rounded-lg pl-9 pr-12 py-1.5 text-xs text-slate-900 dark:text-[#F8FAFC] placeholder-slate-400 dark:placeholder-[#64748B] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all font-sans"
          />
          <kbd className="absolute right-2.5 top-2 text-[10px] font-mono text-slate-500 dark:text-[#64748B] bg-white dark:bg-[#111B2E] px-1.5 py-0.5 rounded border border-slate-200 dark:border-[#263449]">
            ↵
          </kbd>
        </form>
      </div>

      {/* Right: SOC Status Telemetry, Clock, Theme Toggle, Notifications, User */}
      <div className="flex items-center gap-2.5 md:gap-3.5 flex-shrink-0">
        {/* CrowdStrike Falcon Telemetry Pill */}
        <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-100 dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] text-xs transition-colors">
          <span
            className={`w-2 h-2 rounded-full ${
              csStatus === "CONNECTED"
                ? "bg-emerald-500 animate-pulse"
                : "bg-red-500"
            }`}
          />
          <span className="text-[11px] font-mono text-slate-600 dark:text-[#94A3B8]">
            EDR:{" "}
            <span
              className={
                csStatus === "CONNECTED"
                  ? "text-emerald-600 dark:text-emerald-400 font-semibold"
                  : "text-red-600 dark:text-red-400 font-semibold"
              }
            >
              {csStatus === "CONNECTED" ? "FALCON LIVE" : "DISCONNECTED"}
            </span>
          </span>
        </div>

        {/* Real-time Clock */}
        <div className="hidden lg:flex items-center gap-2 text-xs font-mono text-slate-600 dark:text-[#94A3B8] px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-[#080D19] border border-slate-200 dark:border-[#263449]/70 transition-colors">
          <Clock className="w-3.5 h-3.5 text-blue-600 dark:text-[#3B82F6]" />
          <span className="text-slate-900 dark:text-[#F8FAFC] font-semibold">{currentTime}</span>
          <span className="text-slate-400 dark:text-[#64748B]">|</span>
          <span className="text-slate-500 dark:text-[#64748B]">{utcTime}</span>
        </div>

        {/* Global Light/Dark Theme Switcher in Top-Right Corner */}
        <ThemeToggle />

        {/* Notifications Popover Trigger */}
        <div className="relative">
          <button
            onClick={() => {
              setShowNotifications(!showNotifications);
              setShowUserMenu(false);
            }}
            className="relative p-2 rounded-xl bg-white dark:bg-[#111B2E] hover:bg-slate-50 dark:hover:bg-[#15223A] border border-slate-200 dark:border-[#263449] text-slate-600 dark:text-[#94A3B8] hover:text-slate-900 dark:hover:text-[#F8FAFC] transition-colors cursor-pointer shadow-sm"
            title="Active Security Alerts"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl shadow-2xl p-4 z-50 text-xs animate-in fade-in zoom-in-95 duration-100">
              <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-[#263449]">
                <h4 className="font-semibold text-slate-900 dark:text-[#F8FAFC] flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-blue-600 dark:text-[#3B82F6]" />
                  Active Security Alerts
                </h4>
                <span className="text-[10px] font-mono bg-red-500/10 dark:bg-red-500/20 text-red-600 dark:text-red-400 px-1.5 py-0.5 rounded border border-red-500/30">
                  4 Live
                </span>
              </div>
              <div className="mt-3 space-y-2.5 max-h-64 overflow-y-auto">
                <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-[#080D19] border border-red-500/20">
                  <div className="flex items-center justify-between text-red-600 dark:text-red-400 font-semibold text-[11px]">
                    <span>LockBit 3.0 Signature</span>
                    <span className="font-mono text-[10px]">Just now</span>
                  </div>
                  <p className="text-slate-600 dark:text-[#94A3B8] text-[11px] mt-1">
                    vssadmin shadow copy deletion triggered on WS-FIN-01.
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-[#080D19] border border-amber-500/20">
                  <div className="flex items-center justify-between text-amber-600 dark:text-amber-400 font-semibold text-[11px]">
                    <span>Injected Process Detected</span>
                    <span className="font-mono text-[10px]">5m ago</span>
                  </div>
                  <p className="text-slate-600 dark:text-[#94A3B8] text-[11px] mt-1">
                    svchost.exe PID 3844 allocated PAGE_EXECUTE_READWRITE memory.
                  </p>
                </div>
              </div>
              <div className="mt-3 pt-2 border-t border-slate-200 dark:border-[#263449] text-center">
                <button
                  onClick={() => {
                    setShowNotifications(false);
                    router.push("/threats");
                  }}
                  className="text-xs text-blue-600 dark:text-[#3B82F6] hover:underline font-medium"
                >
                  View All Detections →
                </button>
              </div>
            </div>
          )}
        </div>

        {/* User Profile Dropdown */}
        <div className="relative">
          <button
            onClick={() => {
              setShowUserMenu(!showUserMenu);
              setShowNotifications(false);
            }}
            className="flex items-center gap-2.5 pl-2 pr-3 py-1.5 rounded-xl bg-white dark:bg-[#111B2E] hover:bg-slate-50 dark:hover:bg-[#15223A] border border-slate-200 dark:border-[#263449] transition-colors cursor-pointer shadow-sm"
          >
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center text-white text-xs font-bold border border-blue-400/40 shadow-sm">
              {user?.username ? user.username[0].toUpperCase() : "A"}
            </div>
            <div className="text-left hidden sm:block">
              <p className="text-xs font-semibold text-slate-900 dark:text-[#F8FAFC] leading-tight">
                {user?.username || "SOC Analyst"}
              </p>
              <p className="text-[10px] text-slate-500 dark:text-[#94A3B8] capitalize leading-none">
                {user?.role?.replace("_", " ") || "Administrator"}
              </p>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400 dark:text-[#64748B]" />
          </button>

          {showUserMenu && (
            <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl shadow-2xl p-2 z-50 text-xs animate-in fade-in zoom-in-95 duration-100">
              <div className="px-3 py-2 border-b border-slate-200 dark:border-[#263449] mb-1">
                <p className="font-semibold text-slate-900 dark:text-[#F8FAFC]">{user?.username}</p>
                <p className="text-[11px] text-slate-500 dark:text-[#94A3B8] truncate">{user?.email || "soc-analyst@zaalima.io"}</p>
              </div>
              <button
                onClick={() => {
                  setShowUserMenu(false);
                  router.push("/settings");
                }}
                className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-slate-700 dark:text-[#94A3B8] hover:text-slate-900 dark:hover:text-[#F8FAFC] hover:bg-slate-100 dark:hover:bg-[#15223A] transition-colors text-left"
              >
                <User className="w-3.5 h-3.5" />
                Security Profile & API Keys
              </button>
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors text-left"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
