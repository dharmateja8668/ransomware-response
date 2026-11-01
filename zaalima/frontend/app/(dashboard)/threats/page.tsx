"use client";
import React, { useEffect, useState, useMemo } from "react";
import {
  Search,
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  ShieldAlert,
  Flame,
  X,
  ExternalLink,
  ChevronRight,
  Shield,
  Layers,
  Activity,
  BarChart2,
  PieChart as PieIcon,
  Calendar,
} from "lucide-react";
import {
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import PageHeader from "@/components/PageHeader";
import { SeverityBadge, StatusBadge } from "@/components/SeverityBadge";
import { threatsAPI, crowdstrikeAPI } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#DC2626",
  high: "#EA580C",
  medium: "#D97706",
  low: "#2563EB",
};

const CATEGORY_COLORS = ["#2563EB", "#7C3AED", "#DB2777", "#D97706", "#059669"];

export default function ThreatsPage() {
  const { isDark } = useTheme();
  const [threats, setThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [selectedThreat, setSelectedThreat] = useState<any | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [error, setError] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState("");

  const gridStroke = isDark ? "#263449" : "#E2E8F0";
  const textFill = isDark ? "#94A3B8" : "#64748B";
  const tooltipBg = isDark ? "#0B1220" : "#FFFFFF";
  const tooltipBorder = isDark ? "#263449" : "#E2E8F0";
  const tooltipColor = isDark ? "#F8FAFC" : "#172033";

  const loadThreats = async () => {
    setLoading(true);
    setError("");
    try {
      const params: any = {};
      if (search) params.search = search;
      if (severityFilter) params.severity = severityFilter;
      if (statusFilter) params.status = statusFilter;
      const res = await threatsAPI.list(params);
      setThreats(res.data.items || []);
    } catch (err: any) {
      console.error(err);
      setError("Failed to load threats from security feed.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadThreats();
  }, [severityFilter, statusFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadThreats();
  };

  const handleUpdateStatus = async (newStatus: string) => {
    if (!selectedThreat) return;
    setUpdatingStatus(true);
    try {
      await threatsAPI.updateStatus(selectedThreat.threat_id, newStatus);
      setSelectedThreat({ ...selectedThreat, status: newStatus });
      loadThreats();
    } catch (err: any) {
      alert("Failed to update status: " + (err.response?.data?.detail || err.message));
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleSyncCrowdStrike = async () => {
    setSyncing(true);
    setSyncMessage("");
    try {
      const res = await crowdstrikeAPI.sync();
      setSyncMessage(res.data?.message || "Synced CrowdStrike Falcon detections successfully.");
      loadThreats();
    } catch (err: any) {
      alert("Falcon sync failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setSyncing(false);
    }
  };

  // KPIs
  const totalDetections = threats.length;
  const criticalThreats = threats.filter((t) => t.severity === "critical").length;
  const highThreats = threats.filter((t) => t.severity === "high").length;
  const resolvedThreats = threats.filter((t) => t.status === "resolved").length;

  // Chart 1: Detection Timeline (Group by date)
  const timelineData = useMemo(() => {
    const counts: Record<string, number> = {};
    threats.forEach((t) => {
      const dateStr = t.detected_at ? t.detected_at.split("T")[0] : "Recent";
      counts[dateStr] = (counts[dateStr] || 0) + 1;
    });
    return Object.keys(counts)
      .sort()
      .map((date) => ({
        date: date.length > 5 ? date.slice(5) : date,
        detections: counts[date],
      }));
  }, [threats]);

  // Chart 2: Severity Distribution
  const severityData = useMemo(() => {
    const severities = ["critical", "high", "medium", "low"];
    return severities.map((sev) => ({
      name: sev.toUpperCase(),
      count: threats.filter((t) => t.severity === sev).length,
      severity: sev,
    }));
  }, [threats]);

  // Chart 3: Category Distribution
  const categoryData = useMemo(() => {
    const categories: Record<string, number> = {};
    threats.forEach((t) => {
      const cat = t.category || (t.threat_name?.includes("Ransomware") ? "Ransomware" : t.threat_name?.includes("Script") ? "Suspicious Script" : "Malware");
      categories[cat] = (categories[cat] || 0) + 1;
    });
    return Object.keys(categories).map((cat) => ({
      category: cat,
      count: categories[cat],
    }));
  }, [threats]);

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

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Detection Engine"
        subtitle="Real-time ingested telemetry, EDR alerts, MITRE ATT&CK techniques, and IOC correlation"
        breadcrumb="DETECTION"
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-semibold bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
            LIVE TELEMETRY
          </span>
        }
      >
        <div className="flex items-center gap-2">
          <button
            onClick={handleSyncCrowdStrike}
            disabled={syncing}
            className="flex items-center gap-1.5 bg-red-50 dark:bg-red-500/10 hover:bg-red-100 dark:hover:bg-red-500/20 border border-red-200 dark:border-red-500/30 text-red-600 dark:text-red-400 px-3 py-1.5 rounded-lg text-xs font-semibold font-mono transition-colors cursor-pointer disabled:opacity-50"
          >
            <ShieldAlert className={`w-3.5 h-3.5 ${syncing ? "animate-spin" : ""}`} />
            {syncing ? "Syncing Falcon..." : "Sync CrowdStrike"}
          </button>
          <button
            onClick={loadThreats}
            className="flex items-center gap-1.5 bg-white dark:bg-[#111B2E] hover:bg-slate-50 dark:hover:bg-[#15223A] border border-slate-200 dark:border-[#263449] text-slate-700 dark:text-[#F8FAFC] px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer shadow-sm"
          >
            <RefreshCw className="w-3.5 h-3.5 text-blue-600 dark:text-[#3B82F6]" />
            Refresh
          </button>
        </div>
      </PageHeader>

      {syncMessage && (
        <div className="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 text-emerald-700 dark:text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle className="w-4 h-4 flex-shrink-0" />
          <span>{syncMessage}</span>
        </div>
      )}

      {error && (
        <div className="p-3.5 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-xl flex items-center gap-3 text-red-600 dark:text-red-400 text-xs">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* KPI Cards: Exactly 4 Detections Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
          <span className="text-xs font-medium text-slate-500 dark:text-[#94A3B8]">
            Total Detections
          </span>
          <div className="mt-1 text-2xl font-bold font-mono text-slate-900 dark:text-white">
            {totalDetections}
          </div>
          <div className="text-[11px] text-slate-400 dark:text-[#64748B] mt-0.5">
            Ingested security events
          </div>
        </div>

        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
          <span className="text-xs font-medium text-slate-500 dark:text-[#94A3B8]">
            Critical Threats
          </span>
          <div className="mt-1 text-2xl font-bold font-mono text-red-600 dark:text-red-400">
            {criticalThreats}
          </div>
          <div className="text-[11px] text-slate-400 dark:text-[#64748B] mt-0.5">
            Requires immediate action
          </div>
        </div>

        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
          <span className="text-xs font-medium text-slate-500 dark:text-[#94A3B8]">
            High-Severity Threats
          </span>
          <div className="mt-1 text-2xl font-bold font-mono text-orange-600 dark:text-orange-400">
            {highThreats}
          </div>
          <div className="text-[11px] text-slate-400 dark:text-[#64748B] mt-0.5">
            Elevated priority triage
          </div>
        </div>

        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
          <span className="text-xs font-medium text-slate-500 dark:text-[#94A3B8]">
            Resolved Threats
          </span>
          <div className="mt-1 text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400">
            {resolvedThreats}
          </div>
          <div className="text-[11px] text-slate-400 dark:text-[#64748B] mt-0.5">
            Mitigated or closed
          </div>
        </div>
      </div>

      {/* Graphs: 3 Dedicated Threat Detection Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Graph 1: Threat Detection Timeline */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-5 shadow-sm transition-colors">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-1">
            Threat Detection Timeline
          </h3>
          <p className="text-xs text-slate-500 dark:text-[#94A3B8] mb-4">
            Ingestion trend over time
          </p>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} vertical={false} />
              <XAxis dataKey="date" tick={{ fill: textFill, fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: textFill, fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: tooltipBg,
                  borderColor: tooltipBorder,
                  borderRadius: 8,
                  fontSize: 12,
                  color: tooltipColor,
                }}
              />
              <Area type="monotone" dataKey="detections" stroke="#2563EB" fill="#2563EB" fillOpacity={0.15} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Graph 2: Severity Distribution */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-5 shadow-sm transition-colors">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-1">
            Severity Distribution
          </h3>
          <p className="text-xs text-slate-500 dark:text-[#94A3B8] mb-4">
            Alerts by severity rank
          </p>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={45}
                outerRadius={70}
                paddingAngle={3}
                dataKey="count"
                nameKey="name"
              >
                {severityData.map((entry, index) => (
                  <Cell
                    key={index}
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
                }}
              />
              <Legend formatter={(v) => <span className="text-xs text-slate-600 dark:text-[#94A3B8] capitalize">{v}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Graph 3: Threat Category Distribution */}
        <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-5 shadow-sm transition-colors">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-1">
            Threat Categories
          </h3>
          <p className="text-xs text-slate-500 dark:text-[#94A3B8] mb-4">
            Classification Breakdown
          </p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={categoryData} layout="vertical" margin={{ left: 10, right: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} horizontal={false} />
              <XAxis type="number" tick={{ fill: textFill, fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis dataKey="category" type="category" tick={{ fill: textFill, fontSize: 10 }} width={80} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: tooltipBg,
                  borderColor: tooltipBorder,
                  borderRadius: 8,
                  fontSize: 12,
                  color: tooltipColor,
                }}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {categoryData.map((_, index) => (
                  <Cell key={index} fill={CATEGORY_COLORS[index % CATEGORY_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 shadow-sm transition-colors">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 dark:text-[#64748B] absolute left-3.5 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by threat ID, process, hash, hostname, or user..."
              className="w-full bg-slate-50 dark:bg-[#080D19] border border-slate-200 dark:border-[#263449] rounded-lg pl-10 pr-4 py-2 text-xs text-slate-900 dark:text-[#F8FAFC] placeholder-slate-400 dark:placeholder-[#64748B] focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div className="flex gap-2 flex-wrap">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-50 dark:bg-[#080D19] border border-slate-200 dark:border-[#263449] rounded-lg px-3 py-2 text-xs text-slate-700 dark:text-[#94A3B8] focus:outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-50 dark:bg-[#080D19] border border-slate-200 dark:border-[#263449] rounded-lg px-3 py-2 text-xs text-slate-700 dark:text-[#94A3B8] focus:outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="">All Statuses</option>
              <option value="new">New</option>
              <option value="detected">Detected</option>
              <option value="investigating">Investigating</option>
              <option value="contained">Contained</option>
              <option value="resolved">Resolved</option>
            </select>

            <button
              type="submit"
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
            >
              Apply Filter
            </button>
          </div>
        </form>
      </div>

      {/* Threats Table */}
      <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl overflow-hidden shadow-sm transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-slate-50 dark:bg-[#0B1220] text-slate-500 dark:text-[#64748B] text-[10px] uppercase font-mono border-b border-slate-200 dark:border-[#263449]">
              <tr>
                <th className="px-4 py-3">Detection ID</th>
                <th className="px-4 py-3">Threat Name</th>
                <th className="px-4 py-3">Hostname</th>
                <th className="px-4 py-3">Device ID</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Detection Time</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-[#263449]/50">
              {threats.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 dark:text-[#64748B]">
                    No threats found matching the current criteria.
                  </td>
                </tr>
              ) : (
                threats.map((threat) => {
                  const threatName = threat.threat_name || threat.title || "Ransomware Alert";
                  const deviceId = threat.device_id || (threat.threat_id?.includes("ind:") ? threat.threat_id.split(":")[0] : "DEV-CS-9844");
                  return (
                    <tr
                      key={threat.threat_id}
                      onClick={() => setSelectedThreat(threat)}
                      className="hover:bg-slate-50 dark:hover:bg-[#15223A] transition-colors cursor-pointer"
                    >
                      <td className="px-4 py-3 font-mono text-[11px] text-blue-600 dark:text-blue-400 font-semibold truncate max-w-[140px]">
                        {threat.threat_id}
                      </td>
                      <td className="px-4 py-3 font-semibold text-slate-800 dark:text-[#F8FAFC]">
                        {threatName}
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-600 dark:text-[#94A3B8]">
                        {threat.hostname || "—"}
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-500 dark:text-[#64748B] truncate max-w-[120px]">
                        {deviceId}
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={threat.severity} />
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-500 dark:text-[#94A3B8]">
                        {formatTimestamp(threat.detected_at)}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={threat.status} />
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className="text-blue-600 dark:text-blue-400 text-xs font-semibold hover:underline">
                          Triage →
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat Triage Modal */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setSelectedThreat(null)}
              className="absolute top-4 right-4 text-slate-400 dark:text-[#64748B] hover:text-slate-700 dark:hover:text-white p-1 rounded-lg"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-600 dark:text-red-400">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white">
                  {selectedThreat.threat_name || selectedThreat.title || "Threat Triage"}
                </h3>
                <p className="text-xs font-mono text-slate-500 dark:text-[#94A3B8]">
                  ID: {selectedThreat.threat_id}
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs mb-4 p-3.5 rounded-xl bg-slate-50 dark:bg-[#080D19] border border-slate-200 dark:border-[#263449]">
              <div>
                <span className="text-slate-500 dark:text-[#64748B] block">Target Host:</span>
                <span className="font-mono font-semibold text-slate-800 dark:text-white">{selectedThreat.hostname || "—"}</span>
              </div>
              <div>
                <span className="text-slate-500 dark:text-[#64748B] block">Severity:</span>
                <SeverityBadge severity={selectedThreat.severity} />
              </div>
              <div>
                <span className="text-slate-500 dark:text-[#64748B] block">Current Status:</span>
                <StatusBadge status={selectedThreat.status} />
              </div>
              <div>
                <span className="text-slate-500 dark:text-[#64748B] block">Detection Time:</span>
                <span className="font-mono text-slate-700 dark:text-[#94A3B8]">{formatTimestamp(selectedThreat.detected_at)}</span>
              </div>
            </div>

            <div className="mb-6">
              <label className="block text-xs font-semibold text-slate-700 dark:text-[#94A3B8] mb-2 uppercase tracking-wider font-mono">
                Update Threat Containment Status:
              </label>
              <div className="flex gap-2 flex-wrap">
                {["investigating", "contained", "resolved", "false_positive"].map((st) => (
                  <button
                    key={st}
                    onClick={() => handleUpdateStatus(st)}
                    disabled={updatingStatus || selectedThreat.status === st}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold capitalize bg-slate-100 hover:bg-slate-200 dark:bg-[#080D19] dark:hover:bg-[#15223A] border border-slate-300 dark:border-[#263449] text-slate-700 dark:text-slate-200 transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {st.replace("_", " ")}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex justify-end">
              <button
                onClick={() => setSelectedThreat(null)}
                className="px-4 py-2 rounded-lg bg-slate-200 dark:bg-[#263449] hover:bg-slate-300 dark:hover:bg-[#1C2738] text-xs font-semibold text-slate-800 dark:text-white transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
