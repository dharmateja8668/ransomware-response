"use client";
import React, { useEffect, useState, useMemo } from "react";
import {
  ScrollText,
  Search,
  RefreshCw,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  Activity,
  UserCheck,
  Zap,
  AlertCircle,
  TrendingUp,
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
import StatCard from "@/components/StatCard";
import { auditAPI } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

const ACTOR_COLORS = ["#2563EB", "#7C3AED", "#059669", "#D97706", "#DB2777"];

export default function AuditPage() {
  const { isDark } = useTheme();
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [error, setError] = useState("");

  const gridStroke = isDark ? "#263449" : "#E2E8F0";
  const textFill = isDark ? "#94A3B8" : "#64748B";
  const tooltipBg = isDark ? "#0B1220" : "#FFFFFF";
  const tooltipBorder = isDark ? "#263449" : "#E2E8F0";
  const tooltipColor = isDark ? "#F8FAFC" : "#172033";

  const loadAuditLogs = async () => {
    setLoading(true);
    setError("");
    try {
      const params: any = {};
      if (search) params.search = search;
      if (actionFilter) params.action = actionFilter;
      const res = await auditAPI.list(params);
      setLogs(res.data.items || []);
    } catch (err: any) {
      console.error(err);
      setError("Failed to load immutable audit log stream.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAuditLogs();
  }, [actionFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadAuditLogs();
  };

  // 4 KPIs
  const totalLogs = logs.length;
  const adminActions = logs.filter(
    (l) => l.actor === "admin" || (l.action && l.action.includes("user_"))
  ).length;
  const automatedActions = logs.filter(
    (l) => l.actor === "system_soar" || (l.action && (l.action.includes("playbook") || l.action.includes("isolated")))
  ).length;
  const failedOperations = logs.filter(
    (l) => l.status === "failed" || l.status === "error"
  ).length;

  // Graph 1: Timeline
  const timelineData = useMemo(() => {
    const counts: Record<string, number> = {};
    logs.forEach((l) => {
      const date = l.created_at ? l.created_at.split("T")[0] : "Recent";
      counts[date] = (counts[date] || 0) + 1;
    });
    const sorted = Object.keys(counts).sort();
    if (sorted.length === 0) return [{ date: "Today", events: 0 }];
    return sorted.map((d) => ({
      date: d.length > 5 ? d.slice(5) : d,
      events: counts[d],
    }));
  }, [logs]);

  // Graph 2: Action Breakdown
  const actionData = useMemo(() => {
    const counts: Record<string, number> = {};
    logs.forEach((l) => {
      const a = (l.action || "other").replace(/_/g, " ").toUpperCase();
      counts[a] = (counts[a] || 0) + 1;
    });
    return Object.keys(counts)
      .slice(0, 5)
      .map((action) => ({
        action: action.length > 15 ? `${action.slice(0, 12)}...` : action,
        count: counts[action],
      }));
  }, [logs]);

  // Graph 3: Actor Breakdown
  const actorData = useMemo(() => {
    const counts: Record<string, number> = {};
    logs.forEach((l) => {
      const act = l.actor || "system";
      counts[act] = (counts[act] || 0) + 1;
    });
    return Object.keys(counts).map((actor) => ({
      name: actor.toUpperCase(),
      count: counts[actor],
    }));
  }, [logs]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit & Compliance Ledger"
        subtitle="Immutable security audit trail recording all SOC analyst actions, automated SOAR interventions, and API calls."
        breadcrumb="AUDIT"
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            TAMPER-EVIDENT
          </span>
        }
      >
        <button
          onClick={loadAuditLogs}
          className="flex items-center gap-1.5 bg-soc-card hover:bg-soc-border/30 border border-soc-border text-soc-text px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
          Refresh
        </button>
      </PageHeader>

      {/* Exactly 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Events"
          value={totalLogs}
          icon={ScrollText}
          color="blue"
          subtitle="All audit ledger entries"
        />
        <StatCard
          title="Admin Actions"
          value={adminActions}
          icon={UserCheck}
          color="purple"
          subtitle="Manual analyst operations"
        />
        <StatCard
          title="Automated SOAR"
          value={automatedActions}
          icon={Zap}
          color="green"
          subtitle="Orchestrator executions"
        />
        <StatCard
          title="Failed Operations"
          value={failedOperations}
          icon={AlertCircle}
          color="red"
          subtitle="Action execution errors"
        />
      </div>

      {/* Graphs Section: 3 Dedicated Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph 1: Timeline */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Audit Event Velocity</h2>
              <p className="text-xs text-soc-muted">Events recorded over time</p>
            </div>
            <TrendingUp className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="auditColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2563EB" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#2563EB" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis dataKey="date" stroke={textFill} fontSize={11} tickLine={false} />
                <YAxis stroke={textFill} fontSize={11} allowDecimals={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: tooltipBg,
                    borderColor: tooltipBorder,
                    color: tooltipColor,
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  name="Events"
                  stroke="#2563EB"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#auditColor)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Graph 2: Top Actions */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Top Action Types</h2>
              <p className="text-xs text-soc-muted">Frequency by operation</p>
            </div>
            <Activity className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={actionData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis dataKey="action" stroke={textFill} fontSize={10} tickLine={false} />
                <YAxis stroke={textFill} fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: tooltipBg,
                    borderColor: tooltipBorder,
                    color: tooltipColor,
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Bar dataKey="count" name="Count" fill="#059669" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Graph 3: Actor Breakdown */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Actor Distribution</h2>
              <p className="text-xs text-soc-muted">Actions by user or orchestrator</p>
            </div>
            <UserCheck className="w-4 h-4 text-purple-600 dark:text-purple-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={actorData}
                  cx="50%"
                  cy="45%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {actorData.map((entry, index) => (
                    <Cell
                      key={`actor-${index}`}
                      fill={ACTOR_COLORS[index % ACTOR_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: tooltipBg,
                    borderColor: tooltipBorder,
                    color: tooltipColor,
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconType="circle"
                  formatter={(value) => (
                    <span className="text-[11px] font-medium text-soc-muted">{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-4 shadow-sm">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-soc-muted absolute left-3.5 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by actor username, target host/user, or action details..."
              className="w-full bg-soc-bg border border-soc-border rounded-lg pl-10 pr-4 py-2 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div className="flex gap-2">
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="">All Action Types</option>
              <option value="login">User Login</option>
              <option value="logout">User Logout</option>
              <option value="endpoint_isolated">Endpoint Isolated</option>
              <option value="endpoint_restored">Endpoint Restored</option>
              <option value="user_suspended">User Suspended</option>
              <option value="user_activated">User Activated</option>
              <option value="evidence_collected">Evidence Collected</option>
              <option value="playbook_executed">Playbook Executed</option>
              <option value="jira_ticket_created">Jira Ticket Created</option>
            </select>

            <button
              type="submit"
              className="bg-[#2563EB] hover:bg-[#1D4ED8] text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
            >
              Filter
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center gap-3 text-red-600 dark:text-red-400 text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="bg-soc-card border border-soc-border rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-3.5 border-b border-soc-border flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-soc-text">Tamper-Evident Ledger</h2>
            <p className="text-xs text-soc-muted">Chronological cryptographic execution log</p>
          </div>
          <span className="text-xs font-mono text-soc-muted">Showing {logs.length} entries</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-soc-bg text-soc-muted text-[10px] uppercase font-mono border-b border-soc-border">
              <tr>
                <th className="px-5 py-3.5">Action Code</th>
                <th className="px-5 py-3.5">Actor Principal</th>
                <th className="px-5 py-3.5">Target Subject</th>
                <th className="px-5 py-3.5">Audit Event Details</th>
                <th className="px-5 py-3.5">Execution Status</th>
                <th className="px-5 py-3.5 text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-soc-muted">
                    <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
                    <p className="font-mono">Streaming audit ledger records...</p>
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-soc-muted">
                    No audit records matching query.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-soc-border/30 transition-colors">
                    <td className="px-5 py-3.5 font-mono text-[11px]">
                      <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 font-semibold">
                        {log.action}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 font-bold text-soc-text">
                      {log.actor}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-soc-muted">
                      {log.target || "—"}
                    </td>
                    <td
                      className="px-5 py-3.5 text-soc-muted max-w-[320px] truncate leading-relaxed"
                      title={log.details}
                    >
                      {log.details || "—"}
                    </td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold capitalize border ${
                          log.status === "success"
                            ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                            : "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30"
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            log.status === "success" ? "bg-emerald-500" : "bg-red-500"
                          }`}
                        />
                        {log.status || "success"}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-right font-mono text-[11px] text-soc-muted">
                      {log.created_at ? new Date(log.created_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
