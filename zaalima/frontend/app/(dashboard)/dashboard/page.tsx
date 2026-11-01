"use client";
import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  Monitor,
  Lock,
  RefreshCw,
  ChevronRight,
  ShieldCheck,
  Activity,
  ArrowRight,
  ExternalLink,
} from "lucide-react";
import {
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import PageHeader from "@/components/PageHeader";
import { SeverityBadge, StatusBadge } from "@/components/SeverityBadge";
import { dashboardAPI, crowdstrikeAPI } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#DC2626",
  high: "#EA580C",
  medium: "#D97706",
  low: "#2563EB",
};

export default function DashboardPage() {
  const { isDark } = useTheme();
  const [stats, setStats] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [severity, setSeverity] = useState<any[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [endpointHealth, setEndpointHealth] = useState<any[]>([]);
  const [csStatus, setCsStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const gridStroke = isDark ? "#263449" : "#E2E8F0";
  const textFill = isDark ? "#94A3B8" : "#64748B";
  const tooltipBg = isDark ? "#0B1220" : "#FFFFFF";
  const tooltipBorder = isDark ? "#263449" : "#E2E8F0";
  const tooltipColor = isDark ? "#F8FAFC" : "#172033";

  const loadData = async () => {
    try {
      const [s, t, sv, ra, eh, cs] = await Promise.all([
        dashboardAPI.stats(),
        dashboardAPI.timeline(),
        dashboardAPI.severityDistribution(),
        dashboardAPI.recentAlerts(),
        dashboardAPI.endpointHealth(),
        crowdstrikeAPI.status().catch(() => ({ data: null })),
      ]);
      setStats(s.data);
      setTimeline(t.data || []);
      setSeverity(sv.data || []);
      setRecentAlerts(ra.data || []);
      setEndpointHealth(eh.data || []);
      if (cs?.data) setCsStatus(cs.data);
      setLastUpdated(new Date());
    } catch (e) {
      console.error("Dashboard data load error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  // Calculate endpoint statistics
  const healthyCount = endpointHealth.find((e) => e.status === "healthy")?.count || 0;
  const infectedCount = endpointHealth.find((e) => e.status === "infected")?.count || stats?.infected_endpoints || 0;
  const isolatedCount = endpointHealth.find((e) => e.status === "isolated")?.count || stats?.isolated_endpoints || 0;
  const totalFleet = healthyCount + infectedCount + isolatedCount + (endpointHealth.find((e) => e.status === "suspicious")?.count || 0);

  const formatTimestamp = (ts: string) => {
    if (!ts) return "—";
    try {
      const d = new Date(ts);
      return d.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
    } catch {
      return ts;
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-96 gap-3">
        <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
        <p className="text-xs font-mono text-slate-500 dark:text-[#94A3B8]">
          Loading Security Operations Telemetry...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Section */}
      <PageHeader
        title="Security Operations Overview"
        subtitle="Monitor threats, incidents and endpoint security from one centralized platform."
        breadcrumb="DASHBOARD"
        badge={
          csStatus?.status === "CONNECTED" ? (
            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              CROWDSTRIKE CONNECTED
            </span>
          ) : null
        }
      >
        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono text-slate-500 dark:text-[#64748B]">
            Updated {lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
          </span>
          <button
            onClick={loadData}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white dark:bg-[#111B2E] hover:bg-slate-50 dark:hover:bg-[#15223A] border border-slate-200 dark:border-[#263449] text-xs font-medium text-slate-700 dark:text-[#F8FAFC] transition-colors cursor-pointer shadow-sm"
          >
            <RefreshCw className="w-3.5 h-3.5 text-blue-600 dark:text-[#3B82F6]" />
            Refresh
          </button>
        </div>
      </PageHeader>

      {/* KPI Cards: Exactly Five Focused Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {/* Card 1: Total Security Alerts */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-[#94A3B8]">
              Total Security Alerts
            </span>
            <div className="p-1.5 rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
              {stats?.total_alerts ?? 0}
            </span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400 dark:text-[#64748B]">
            All ingested threat events
          </div>
        </div>

        {/* Card 2: Critical Threats */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-[#94A3B8]">
              Critical Threats
            </span>
            <div className="p-1.5 rounded-md bg-red-500/10 text-red-600 dark:text-red-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-red-600 dark:text-red-400">
              {stats?.critical_threats ?? 0}
            </span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400 dark:text-[#64748B]">
            Immediate containment priority
          </div>
        </div>

        {/* Card 3: Active Incidents */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-[#94A3B8]">
              Active Incidents
            </span>
            <div className="p-1.5 rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-amber-600 dark:text-amber-400">
              {stats?.active_incidents ?? 0}
            </span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400 dark:text-[#64748B]">
            Under active investigation
          </div>
        </div>

        {/* Card 4: Infected Endpoints */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-[#94A3B8]">
              Infected Endpoints
            </span>
            <div className="p-1.5 rounded-md bg-red-500/10 text-red-600 dark:text-red-400">
              <Monitor className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-red-600 dark:text-red-400">
              {stats?.infected_endpoints ?? 0}
            </span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400 dark:text-[#64748B]">
            Confirmed host infection
          </div>
        </div>

        {/* Card 5: Isolated Endpoints */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-[#94A3B8]">
              Isolated Endpoints
            </span>
            <div className="p-1.5 rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400">
              <Lock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-blue-600 dark:text-blue-400">
              {stats?.isolated_endpoints ?? 0}
            </span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400 dark:text-[#64748B]">
            Network contained
          </div>
        </div>
      </div>

      {/* Row 1: Threat Detection Trend (Line Chart) & Incident Severity (Donut Chart) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Section 1: Threat Detection Trend */}
        <div className="lg:col-span-2 bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-5 shadow-sm transition-colors">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100 dark:border-[#263449]/70">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                Threat Detection Trend
              </h3>
              <p className="text-xs text-slate-500 dark:text-[#94A3B8] mt-0.5">
                Ingested alert volume over time
              </p>
            </div>
            <Link
              href="/threats"
              className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
            >
              Detection Details <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="threatTrendGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2563EB" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#2563EB" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} vertical={false} />
              <XAxis dataKey="date" tick={{ fill: textFill, fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: textFill, fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: tooltipBg,
                  borderColor: tooltipBorder,
                  borderRadius: 8,
                  fontSize: 12,
                  color: tooltipColor,
                  boxShadow: "0 4px 16px -2px rgba(0, 0, 0, 0.1)",
                }}
              />
              <Area
                type="monotone"
                dataKey="threats"
                name="Alerts"
                stroke="#2563EB"
                strokeWidth={2}
                fill="url(#threatTrendGrad)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Section 2: Incident Severity (Donut Chart) */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-5 shadow-sm transition-colors">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100 dark:border-[#263449]/70">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                Incident Severity
              </h3>
              <p className="text-xs text-slate-500 dark:text-[#94A3B8] mt-0.5">
                Severity distribution
              </p>
            </div>
            <Link
              href="/incidents"
              className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
            >
              Incidents <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie
                data={severity}
                cx="50%"
                cy="45%"
                innerRadius={50}
                outerRadius={75}
                paddingAngle={3}
                dataKey="count"
                nameKey="severity"
              >
                {severity.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={SEVERITY_COLORS[entry.severity] || "#64748B"}
                    stroke={isDark ? "#111B2E" : "#FFFFFF"}
                    strokeWidth={2}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: tooltipBg,
                  borderColor: tooltipBorder,
                  borderRadius: 8,
                  fontSize: 12,
                  color: tooltipColor,
                  boxShadow: "0 4px 16px -2px rgba(0, 0, 0, 0.1)",
                }}
              />
              <Legend
                formatter={(val) => (
                  <span className="text-xs text-slate-600 dark:text-[#94A3B8] capitalize font-medium">
                    {val}
                  </span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Row 2: Recent Security Alerts & Endpoint Health Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Section 3: Recent Security Alerts (Latest 5) */}
        <div className="lg:col-span-2 bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-5 shadow-sm transition-colors">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100 dark:border-[#263449]/70">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                Recent Security Alerts
              </h3>
              <p className="text-xs text-slate-500 dark:text-[#94A3B8] mt-0.5">
                Latest 5 detections requiring review
              </p>
            </div>
            <Link
              href="/threats"
              className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
            >
              View All <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="text-[11px] font-mono text-slate-500 dark:text-[#64748B] border-b border-slate-200 dark:border-[#263449]">
                <tr>
                  <th className="pb-2.5 font-medium">Threat</th>
                  <th className="pb-2.5 font-medium">Hostname</th>
                  <th className="pb-2.5 font-medium">Severity</th>
                  <th className="pb-2.5 font-medium">Detection Time</th>
                  <th className="pb-2.5 font-medium">Status</th>
                  <th className="pb-2.5 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-[#263449]/50">
                {recentAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-6 text-center text-slate-500 dark:text-[#64748B]">
                      No active security alerts recorded.
                    </td>
                  </tr>
                ) : (
                  recentAlerts.slice(0, 5).map((alert: any) => {
                    const threatName = alert.threat_name || alert.title || "Unknown Threat";
                    return (
                      <tr key={alert.threat_id} className="hover:bg-slate-50 dark:hover:bg-[#15223A] transition-colors">
                        <td className="py-2.5 pr-2">
                          <span className="font-semibold text-slate-800 dark:text-[#F8FAFC] block truncate max-w-[180px]">
                            {threatName}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400 dark:text-[#64748B] block truncate max-w-[180px]">
                            {alert.threat_id}
                          </span>
                        </td>
                        <td className="py-2.5 font-mono text-slate-600 dark:text-[#94A3B8]">
                          {alert.hostname || "—"}
                        </td>
                        <td className="py-2.5">
                          <SeverityBadge severity={alert.severity} />
                        </td>
                        <td className="py-2.5 text-slate-500 dark:text-[#94A3B8] font-mono text-[11px]">
                          {formatTimestamp(alert.detected_at)}
                        </td>
                        <td className="py-2.5">
                          <StatusBadge status={alert.status} />
                        </td>
                        <td className="py-2.5 text-right">
                          <Link
                            href="/threats"
                            className="text-[11px] font-medium text-blue-600 dark:text-blue-400 hover:underline font-mono inline-flex items-center gap-0.5"
                          >
                            Investigate <ArrowRight className="w-3 h-3" />
                          </Link>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 4: Endpoint Health Summary */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-5 shadow-sm transition-colors flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100 dark:border-[#263449]/70">
              <div>
                <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                  Endpoint Health Summary
                </h3>
                <p className="text-xs text-slate-500 dark:text-[#94A3B8] mt-0.5">
                  Host posture & containment state
                </p>
              </div>
              <Link
                href="/endpoints"
                className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
              >
                Fleet <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            {/* Health Metrics List */}
            <div className="space-y-4 my-2">
              {/* Healthy Endpoints */}
              <div>
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <span className="flex items-center gap-1.5 text-slate-700 dark:text-[#F8FAFC] font-medium">
                    <span className="w-2 h-2 rounded-full bg-emerald-500" />
                    Healthy Endpoints
                  </span>
                  <span className="font-mono font-bold text-slate-900 dark:text-white">
                    {healthyCount}
                  </span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-100 dark:bg-[#080D19] overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 rounded-full transition-all duration-500"
                    style={{ width: `${totalFleet ? Math.round((healthyCount / totalFleet) * 100) : 0}%` }}
                  />
                </div>
              </div>

              {/* Infected Endpoints */}
              <div>
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <span className="flex items-center gap-1.5 text-slate-700 dark:text-[#F8FAFC] font-medium">
                    <span className="w-2 h-2 rounded-full bg-red-500" />
                    Infected Endpoints
                  </span>
                  <span className="font-mono font-bold text-red-600 dark:text-red-400">
                    {infectedCount}
                  </span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-100 dark:bg-[#080D19] overflow-hidden">
                  <div
                    className="h-full bg-red-500 rounded-full transition-all duration-500"
                    style={{ width: `${totalFleet ? Math.round((infectedCount / totalFleet) * 100) : 0}%` }}
                  />
                </div>
              </div>

              {/* Isolated Endpoints */}
              <div>
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <span className="flex items-center gap-1.5 text-slate-700 dark:text-[#F8FAFC] font-medium">
                    <span className="w-2 h-2 rounded-full bg-blue-500" />
                    Isolated Endpoints
                  </span>
                  <span className="font-mono font-bold text-blue-600 dark:text-blue-400">
                    {isolatedCount}
                  </span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-100 dark:bg-[#080D19] overflow-hidden">
                  <div
                    className="h-full bg-blue-500 rounded-full transition-all duration-500"
                    style={{ width: `${totalFleet ? Math.round((isolatedCount / totalFleet) * 100) : 0}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-100 dark:border-[#263449]/70 mt-4">
            <Link
              href="/endpoints"
              className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-slate-50 hover:bg-slate-100 dark:bg-[#080D19] dark:hover:bg-[#15223A] border border-slate-200 dark:border-[#263449] text-xs font-semibold text-slate-800 dark:text-slate-200 transition-colors cursor-pointer"
            >
              <span>Manage Fleet Host Isolation</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
