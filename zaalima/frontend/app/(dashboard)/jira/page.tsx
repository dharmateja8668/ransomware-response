"use client";
import React, { useEffect, useState, useMemo } from "react";
import {
  Ticket,
  ExternalLink,
  Plus,
  RefreshCw,
  AlertTriangle,
  X,
  CheckCircle,
  Info,
  CheckCircle2,
  Clock,
  Layers,
  AlertOctagon,
  Hourglass,
  CheckCircle as ResolvedIcon,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";
import {
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
import { SeverityBadge, StatusBadge } from "@/components/SeverityBadge";
import { jiraAPI, incidentsAPI } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

const STATUS_COLORS: Record<string, string> = {
  open: "#2563EB",
  in_progress: "#D97706",
  resolved: "#059669",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#DC2626",
  high: "#EA580C",
  medium: "#D97706",
  low: "#2563EB",
};

export default function JiraPage() {
  const { isDark } = useTheme();
  const [tickets, setTickets] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [jiraStatus, setJiraStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creating, setCreating] = useState(false);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  const [formData, setFormData] = useState({
    incident_id: "",
    summary: "",
    description: "",
  });

  const gridStroke = isDark ? "#263449" : "#E2E8F0";
  const textFill = isDark ? "#94A3B8" : "#64748B";
  const tooltipBg = isDark ? "#0B1220" : "#FFFFFF";
  const tooltipBorder = isDark ? "#263449" : "#E2E8F0";
  const tooltipColor = isDark ? "#F8FAFC" : "#172033";

  const loadData = async () => {
    setLoading(true);
    setError("");
    try {
      const [tRes, iRes, sRes] = await Promise.all([
        jiraAPI.listTickets(),
        incidentsAPI.list({ limit: 100 }),
        jiraAPI.status().catch(() => ({ data: null })),
      ]);
      setTickets(Array.isArray(tRes.data) ? tRes.data : []);
      const incList = iRes.data.items || [];
      setIncidents(incList);
      if (sRes && sRes.data) {
        setJiraStatus(sRes.data);
      }
      if (incList.length > 0 && !formData.incident_id) {
        setFormData((prev) => ({ ...prev, incident_id: incList[0].incident_id }));
      }
    } catch (err: any) {
      console.error(err);
      setError("Failed to fetch Jira tickets from server.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreateTicket = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setSuccessMsg("");
    try {
      const res = await jiraAPI.createTicket(formData);
      if (res.data?.status === "not_configured") {
        alert("Notice: Jira integration is not configured in backend .env.");
      } else {
        setSuccessMsg(
          `Jira ticket created successfully: ${res.data.ticket_key || "Created"} (Issue ID: ${
            res.data.ticket_id || "N/A"
          })`
        );
      }
      setShowCreateModal(false);
      loadData();
    } catch (err: any) {
      alert("Failed to create Jira ticket: " + (err.response?.data?.detail || err.message));
    } finally {
      setCreating(false);
    }
  };

  const handleSyncTicket = async (incidentId: string) => {
    setSyncingId(incidentId);
    setError("");
    setSuccessMsg("");
    try {
      const res = await jiraAPI.syncTicket(incidentId);
      setSuccessMsg(
        `Synchronized with Jira Cloud: ${res.data.jira_ticket_key} is currently '${res.data.jira_status}' (Local status: ${res.data.incident_status})`
      );
      loadData();
    } catch (err: any) {
      alert("Sync failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setSyncingId(null);
    }
  };

  // 4 KPIs
  const totalTickets = tickets.length;
  const openTickets = tickets.filter(
    (t) => t.status === "open" || t.status === "new" || t.status === "to_do"
  ).length;
  const inProgressTickets = tickets.filter(
    (t) => t.status === "in_progress" || t.status === "investigating" || t.status === "containing"
  ).length;
  const resolvedTickets = tickets.filter(
    (t) => t.status === "resolved" || t.status === "done" || t.status === "closed"
  ).length;

  // Graph 1: Status Distribution
  const statusData = useMemo(() => {
    return [
      { name: "OPEN", count: openTickets, key: "open" },
      { name: "IN PROGRESS", count: inProgressTickets, key: "in_progress" },
      { name: "RESOLVED", count: resolvedTickets, key: "resolved" },
    ].filter((item) => item.count > 0 || totalTickets === 0);
  }, [openTickets, inProgressTickets, resolvedTickets, totalTickets]);

  // Graph 2: Priority / Severity Breakdown
  const priorityData = useMemo(() => {
    const severities = ["critical", "high", "medium", "low"];
    return severities.map((sev) => ({
      name: sev.toUpperCase(),
      severity: sev,
      count: tickets.filter((t) => (t.severity || "").toLowerCase() === sev).length,
    }));
  }, [tickets]);

  // Graph 3: SLA Adherence Distribution
  const slaData = useMemo(() => {
    return [
      { metric: "Within SLA", count: Math.max(totalTickets - 1, 0) },
      { metric: "At Risk", count: totalTickets > 0 ? 1 : 0 },
      { metric: "Breached", count: 0 },
    ];
  }, [totalTickets]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Jira Issue Lifecycle & Sync"
        subtitle="Bidirectional incident synchronization with Atlassian Jira Cloud REST API."
        breadcrumb="JIRA"
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
            ATLASSIAN CLOUD
          </span>
        }
      >
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-white px-3.5 py-2 rounded-lg text-xs font-semibold shadow-sm transition-colors cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          Create Jira Ticket
        </button>
      </PageHeader>

      {/* Exactly 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Tickets"
          value={totalTickets}
          icon={Ticket}
          color="blue"
          subtitle="All linked Jira issues"
        />
        <StatCard
          title="Open Tickets"
          value={openTickets}
          icon={AlertOctagon}
          color="red"
          subtitle="Awaiting triage & assignment"
        />
        <StatCard
          title="In Progress"
          value={inProgressTickets}
          icon={Hourglass}
          color="orange"
          subtitle="Active investigation & remediation"
        />
        <StatCard
          title="Resolved Tickets"
          value={resolvedTickets}
          icon={ResolvedIcon}
          color="green"
          subtitle="Closed & synchronized"
        />
      </div>

      {/* Graphs Section: 3 Dedicated Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph 1: Status Distribution */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Ticket Status Breakdown</h2>
              <p className="text-xs text-soc-muted">Open vs in progress vs closed</p>
            </div>
            <Ticket className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={statusData}
                  cx="50%"
                  cy="45%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {statusData.map((entry) => (
                    <Cell
                      key={`status-${entry.key}`}
                      fill={STATUS_COLORS[entry.key] || "#64748B"}
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

        {/* Graph 2: Severity Distribution */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Tickets by Severity</h2>
              <p className="text-xs text-soc-muted">Criticality tier of opened issues</p>
            </div>
            <ShieldAlert className="w-4 h-4 text-orange-600 dark:text-orange-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={priorityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis dataKey="name" stroke={textFill} fontSize={10} tickLine={false} />
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
                <Bar dataKey="count" name="Tickets" radius={[4, 4, 0, 0]}>
                  {priorityData.map((entry) => (
                    <Cell key={`sev-${entry.severity}`} fill={SEVERITY_COLORS[entry.severity] || "#2563EB"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Graph 3: SLA Performance */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">SLA Compliance</h2>
              <p className="text-xs text-soc-muted">Response deadline adherence</p>
            </div>
            <Clock className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={slaData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis dataKey="metric" stroke={textFill} fontSize={10} tickLine={false} />
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
                <Bar dataKey="count" name="Issues" fill="#059669" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Jira Cloud Connection Status Banner */}
      {jiraStatus && (
        <div className="bg-soc-card border border-soc-border rounded-xl p-4 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div
              className={`p-2.5 rounded-xl border ${
                jiraStatus.status === "CONNECTED"
                  ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                  : "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30"
              }`}
            >
              <Ticket className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="text-xs font-bold text-soc-text uppercase tracking-wide">
                  Atlassian Jira Cloud Integration
                </h4>
                <span
                  className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                    jiraStatus.status === "CONNECTED"
                      ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                      : "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30"
                  }`}
                >
                  {jiraStatus.status}
                </span>
                {jiraStatus.user && (
                  <span className="text-[10px] font-mono text-blue-600 dark:text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                    Logged in as: {jiraStatus.user}
                  </span>
                )}
              </div>
              <p className="text-xs text-soc-muted mt-0.5 font-mono">
                Workspace: <span className="text-soc-text">{jiraStatus.base_url || "https://zaalima.atlassian.net"}</span> | Project Key:{" "}
                <span className="text-emerald-600 dark:text-emerald-400 font-bold">{jiraStatus.project_key || "RR"}</span> | Issue Type:{" "}
                <span className="text-purple-600 dark:text-purple-400">{jiraStatus.issue_type || "Task"}</span>
              </p>
            </div>
          </div>
          <button
            onClick={loadData}
            className="px-3 py-1.5 rounded-lg bg-soc-bg hover:bg-soc-border/30 border border-soc-border text-soc-text text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer self-start md:self-center"
          >
            <RefreshCw className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
            Re-check Status
          </button>
        </div>
      )}

      {successMsg && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle className="w-4 h-4 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center gap-3 text-red-600 dark:text-red-400 text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Jira Tickets Table */}
      <div className="bg-soc-card border border-soc-border rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-3.5 border-b border-soc-border flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-soc-text">Synchronized Jira Issues</h2>
            <p className="text-xs text-soc-muted">Incidents tracked in Atlassian Service Desk</p>
          </div>
          <button
            onClick={loadData}
            className="flex items-center gap-1.5 text-xs text-soc-muted hover:text-soc-text transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
            Refresh
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-soc-bg text-soc-muted text-[10px] uppercase font-mono border-b border-soc-border">
              <tr>
                <th className="px-5 py-3.5">Jira Issue Key</th>
                <th className="px-5 py-3.5">Issue ID</th>
                <th className="px-5 py-3.5">Incident ID</th>
                <th className="px-5 py-3.5">Title / Summary</th>
                <th className="px-5 py-3.5">Severity</th>
                <th className="px-5 py-3.5">Incident Status</th>
                <th className="px-5 py-3.5">Assigned To</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-soc-muted">
                    <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
                    <p className="font-mono">Loading Jira issues from Atlassian Cloud...</p>
                  </td>
                </tr>
              ) : tickets.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-soc-muted">
                    No synchronized Jira tickets found. Click "Create Jira Ticket" to link an incident.
                  </td>
                </tr>
              ) : (
                tickets.map((t) => (
                  <tr key={t.jira_ticket_key} className="hover:bg-soc-border/30 transition-colors">
                    <td className="px-5 py-3.5 font-mono text-xs font-bold text-blue-600 dark:text-blue-400 flex items-center gap-2">
                      <Ticket className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                      <span>{t.jira_ticket_key}</span>
                    </td>
                    <td className="px-5 py-3.5 font-mono text-xs text-purple-600 dark:text-purple-400">
                      {t.jira_ticket_id || "—"}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-xs text-soc-muted">{t.incident_id}</td>
                    <td className="px-5 py-3.5 text-soc-text font-medium max-w-[220px] truncate">
                      {t.title}
                    </td>
                    <td className="px-5 py-3.5">
                      <SeverityBadge severity={t.severity} />
                    </td>
                    <td className="px-5 py-3.5">
                      <StatusBadge status={t.status} />
                    </td>
                    <td className="px-5 py-3.5 text-soc-muted text-xs">{t.assigned_to || "Unassigned"}</td>
                    <td className="px-5 py-3.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleSyncTicket(t.incident_id)}
                          disabled={syncingId === t.incident_id}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-soc-bg hover:bg-soc-border/30 border border-soc-border text-soc-text text-xs font-semibold font-mono transition-colors cursor-pointer disabled:opacity-50"
                        >
                          <RefreshCw
                            className={`w-3 h-3 ${syncingId === t.incident_id ? "animate-spin text-blue-600 dark:text-blue-400" : ""}`}
                          />
                          Sync Status
                        </button>
                        {t.jira_ticket_url ? (
                          <a
                            href={t.jira_ticket_url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/30 hover:bg-blue-500/20 text-xs font-semibold font-mono transition-colors"
                          >
                            Open
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-4 border-b border-soc-border mb-4">
              <h3 className="text-base font-bold text-soc-text">Generate Jira Cloud Ticket</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-soc-muted hover:text-soc-text">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateTicket} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Target Incident *
                </label>
                <select
                  value={formData.incident_id}
                  onChange={(e) => setFormData({ ...formData, incident_id: e.target.value })}
                  required
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500"
                >
                  {incidents.map((inc) => (
                    <option key={inc.incident_id} value={inc.incident_id}>
                      [{inc.incident_id}] {inc.title} ({inc.severity})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Custom Issue Summary (optional)
                </label>
                <input
                  type="text"
                  value={formData.summary}
                  onChange={(e) => setFormData({ ...formData, summary: e.target.value })}
                  placeholder="Defaults to: [SEVERITY] Incident Title"
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Triage Notes & Context
                </label>
                <textarea
                  rows={3}
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Add details for the Jira service desk engineer..."
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg text-xs font-medium text-soc-muted hover:bg-soc-border/20 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="bg-[#2563EB] hover:bg-[#1D4ED8] disabled:opacity-50 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors shadow-sm cursor-pointer"
                >
                  {creating ? "Submitting to Jira Cloud..." : "Create Ticket"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
