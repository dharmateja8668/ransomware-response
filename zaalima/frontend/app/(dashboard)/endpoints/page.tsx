"use client";
import React, { useEffect, useState, useMemo } from "react";
import {
  Monitor,
  Search,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
  X,
  Lock,
  Unlock,
  CheckCircle2,
  AlertCircle,
  Cpu,
  Layers,
  Shield,
  Laptop,
  Server,
  Activity,
  HardDrive,
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
import { StatusBadge } from "@/components/SeverityBadge";
import { endpointsAPI, crowdstrikeAPI } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

const HEALTH_COLORS: Record<string, string> = {
  healthy: "#059669",
  suspicious: "#D97706",
  infected: "#DC2626",
  isolated: "#7C3AED",
  offline: "#64748B",
};

const OS_COLORS = ["#2563EB", "#059669", "#D97706", "#7C3AED", "#DB2777"];

export default function EndpointsPage() {
  const { isDark } = useTheme();
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [actionEndpoint, setActionEndpoint] = useState<any | null>(null);
  const [actionType, setActionType] = useState<"isolate" | "restore" | null>(null);
  const [reason, setReason] = useState("Suspected ransomware encryption activity");
  const [confirmDevMachine, setConfirmDevMachine] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [error, setError] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [successMsg, setSuccessMsg] = useState("");

  const gridStroke = isDark ? "#263449" : "#E2E8F0";
  const textFill = isDark ? "#94A3B8" : "#64748B";
  const tooltipBg = isDark ? "#0B1220" : "#FFFFFF";
  const tooltipBorder = isDark ? "#263449" : "#E2E8F0";
  const tooltipColor = isDark ? "#F8FAFC" : "#172033";

  const loadEndpoints = async () => {
    setLoading(true);
    setError("");
    try {
      const params: any = {};
      if (search) params.search = search;
      if (statusFilter) params.status = statusFilter;
      const res = await endpointsAPI.list(params);
      setEndpoints(res.data.items || []);
    } catch (err: any) {
      console.error(err);
      setError("Failed to load endpoint roster from server.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEndpoints();
  }, [statusFilter]);

  const handleSyncCrowdStrike = async () => {
    setSyncing(true);
    setSuccessMsg("");
    try {
      const res = await crowdstrikeAPI.sync();
      setSuccessMsg(res.data?.message || "Synced CrowdStrike Falcon devices and alerts.");
      loadEndpoints();
    } catch (err: any) {
      alert("Falcon sync failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setSyncing(false);
    }
  };

  const handleAction = async () => {
    if (!actionEndpoint || !actionType) return;
    setProcessing(true);
    setError("");
    setSuccessMsg("");
    try {
      if (actionEndpoint.edr_provider === "CROWDSTRIKE") {
        if (actionType === "isolate") {
          await crowdstrikeAPI.contain(
            actionEndpoint.edr_agent_id || actionEndpoint.hostname,
            true,
            reason,
            confirmDevMachine
          );
          setSuccessMsg(`CrowdStrike Falcon network containment applied to ${actionEndpoint.hostname}`);
        } else {
          await crowdstrikeAPI.lift(
            actionEndpoint.edr_agent_id || actionEndpoint.hostname,
            true,
            reason
          );
          setSuccessMsg(`CrowdStrike Falcon containment released for ${actionEndpoint.hostname}`);
        }
      } else {
        if (actionType === "isolate") {
          await endpointsAPI.isolate(actionEndpoint.hostname, reason, confirmDevMachine);
          setSuccessMsg(`Simulated isolation applied to ${actionEndpoint.hostname}`);
        } else {
          await endpointsAPI.restore(actionEndpoint.hostname);
          setSuccessMsg(`Endpoint connectivity restored for ${actionEndpoint.hostname}`);
        }
      }
      setActionEndpoint(null);
      setActionType(null);
      setConfirmDevMachine(false);
      loadEndpoints();
    } catch (err: any) {
      alert("Containment operation failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setProcessing(false);
    }
  };

  // 4 KPIs
  const totalEndpoints = endpoints.length;
  const healthyEndpoints = endpoints.filter(
    (e) => (e.status === "healthy" || !e.status) && !e.is_isolated
  ).length;
  const infectedEndpoints = endpoints.filter(
    (e) => e.status === "infected" || e.status === "suspicious"
  ).length;
  const isolatedEndpoints = endpoints.filter(
    (e) => e.is_isolated || e.status === "isolated"
  ).length;

  // Graph 1: Endpoint Health Distribution
  const healthDistribution = useMemo(() => {
    const states = ["healthy", "suspicious", "infected", "isolated", "offline"];
    return states.map((state) => {
      let count = 0;
      if (state === "isolated") {
        count = endpoints.filter((e) => e.is_isolated || e.status === "isolated").length;
      } else if (state === "healthy") {
        count = endpoints.filter((e) => (e.status === "healthy" || !e.status) && !e.is_isolated).length;
      } else {
        count = endpoints.filter((e) => e.status === state && !e.is_isolated).length;
      }
      return {
        name: state.toUpperCase(),
        state,
        count,
      };
    }).filter((item) => item.count > 0 || totalEndpoints === 0);
  }, [endpoints, totalEndpoints]);

  // Graph 2: OS Distribution
  const osDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    endpoints.forEach((ep) => {
      let os = "Windows";
      const rawOs = (ep.operating_system || "").toLowerCase();
      if (rawOs.includes("win")) os = "Windows";
      else if (rawOs.includes("linux") || rawOs.includes("ubuntu") || rawOs.includes("centos") || rawOs.includes("debian")) os = "Linux";
      else if (rawOs.includes("mac") || rawOs.includes("darwin")) os = "macOS";
      else if (ep.operating_system) os = ep.operating_system;
      counts[os] = (counts[os] || 0) + 1;
    });
    return Object.keys(counts).map((os) => ({
      name: os,
      count: counts[os],
    }));
  }, [endpoints]);

  // Graph 3: Sensor & Provider Coverage
  const sensorCoverage = useMemo(() => {
    const providers: Record<string, number> = {};
    endpoints.forEach((ep) => {
      const p = ep.edr_provider || "Standard EDR";
      providers[p] = (providers[p] || 0) + 1;
    });
    return Object.keys(providers).map((prov) => ({
      provider: prov,
      count: providers[prov],
    }));
  }, [endpoints]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Endpoint Fleet & Containment Control"
        subtitle="Manage monitored endpoints, sensor posture, and host isolation protocols."
        breadcrumb="ENDPOINTS"
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
            {endpoints.length} Registered Sensors
          </span>
        }
      >
        <div className="flex items-center gap-2">
          <button
            onClick={handleSyncCrowdStrike}
            disabled={syncing}
            className="flex items-center gap-1.5 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-600 dark:text-red-400 px-3.5 py-2 rounded-lg text-xs font-semibold font-mono transition-colors cursor-pointer disabled:opacity-50"
          >
            <ShieldAlert className={`w-3.5 h-3.5 ${syncing ? "animate-spin" : ""}`} />
            {syncing ? "Querying Falcon..." : "Sync CrowdStrike"}
          </button>
          <button
            onClick={loadEndpoints}
            className="flex items-center gap-1.5 bg-soc-card hover:bg-soc-border/30 border border-soc-border text-soc-text px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
            Refresh
          </button>
        </div>
      </PageHeader>

      {successMsg && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center gap-3 text-red-600 dark:text-red-400 text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Exactly 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Endpoints"
          value={totalEndpoints}
          icon={Monitor}
          color="blue"
          subtitle="Monitored workstations & servers"
        />
        <StatCard
          title="Healthy Endpoints"
          value={healthyEndpoints}
          icon={ShieldCheck}
          color="green"
          subtitle="Nominal operational state"
        />
        <StatCard
          title="Infected / Compromised"
          value={infectedEndpoints}
          icon={AlertCircle}
          color="red"
          subtitle="Active malware or ransomware alert"
        />
        <StatCard
          title="Isolated Endpoints"
          value={isolatedEndpoints}
          icon={Lock}
          color="purple"
          subtitle="Network containment active"
        />
      </div>

      {/* Graphs Section: 3 Dedicated Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph 1: Health Distribution */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Health Distribution</h2>
              <p className="text-xs text-soc-muted">Fleet health & isolation posture</p>
            </div>
            <Activity className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={healthDistribution}
                  cx="50%"
                  cy="45%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {healthDistribution.map((entry) => (
                    <Cell
                      key={`health-${entry.state}`}
                      fill={HEALTH_COLORS[entry.state] || "#64748B"}
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

        {/* Graph 2: OS Distribution */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Operating Systems</h2>
              <p className="text-xs text-soc-muted">Fleet platform breakdown</p>
            </div>
            <Laptop className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={osDistribution} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis dataKey="name" stroke={textFill} fontSize={11} tickLine={false} />
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
                <Bar dataKey="count" name="Endpoints" fill="#2563EB" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Graph 3: Sensor Coverage */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">EDR Sensor Coverage</h2>
              <p className="text-xs text-soc-muted">CrowdStrike Falcon vs Native</p>
            </div>
            <Shield className="w-4 h-4 text-purple-600 dark:text-purple-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sensorCoverage} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis dataKey="provider" stroke={textFill} fontSize={10} tickLine={false} />
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
                <Bar dataKey="count" name="Installed Sensors" fill="#7C3AED" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-soc-muted absolute left-3.5 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && loadEndpoints()}
              placeholder="Search by hostname, IP address, logged-in user, or Falcon device ID..."
              className="w-full bg-soc-bg border border-soc-border rounded-lg pl-10 pr-4 py-2 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div className="flex gap-2">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="">All Health States</option>
              <option value="healthy">Healthy</option>
              <option value="suspicious">Suspicious</option>
              <option value="infected">Infected</option>
              <option value="isolated">Isolated</option>
              <option value="offline">Offline</option>
            </select>

            <button
              onClick={loadEndpoints}
              className="bg-[#2563EB] hover:bg-[#1D4ED8] text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
            >
              Filter
            </button>
          </div>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="bg-soc-card border border-soc-border rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-3.5 border-b border-soc-border flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-soc-text">Managed Host Inventory</h2>
            <p className="text-xs text-soc-muted">Real-time telemetry, agent versions, and containment authorization</p>
          </div>
          <span className="text-xs font-mono text-soc-muted">Showing {endpoints.length} hosts</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-soc-bg text-soc-muted text-[10px] uppercase font-mono border-b border-soc-border">
              <tr>
                <th className="px-5 py-3.5">Hostname</th>
                <th className="px-5 py-3.5">Device ID (AID)</th>
                <th className="px-5 py-3.5">IP Address</th>
                <th className="px-5 py-3.5">Operating System</th>
                <th className="px-5 py-3.5">User Context</th>
                <th className="px-5 py-3.5">Sensor / Agent</th>
                <th className="px-5 py-3.5">Health State</th>
                <th className="px-5 py-3.5">Last Check-In</th>
                <th className="px-5 py-3.5 text-right">Containment Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-soc-muted">
                    <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
                    <p className="font-mono">Querying endpoint sensor inventory...</p>
                  </td>
                </tr>
              ) : endpoints.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-soc-muted">
                    No endpoints registered in inventory.
                  </td>
                </tr>
              ) : (
                endpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-soc-border/30 transition-colors">
                    <td className="px-5 py-3.5 font-medium text-soc-text flex items-center gap-2">
                      <Monitor className="w-4 h-4 text-soc-muted" />
                      <span className="font-mono font-bold">{ep.hostname}</span>
                      {ep.is_isolated && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
                          ISOLATED
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-[11px] text-soc-muted">
                      {ep.edr_agent_id ? (
                        <span className="font-mono text-blue-600 dark:text-blue-400" title={ep.edr_agent_id}>
                          {ep.edr_agent_id.length > 12 ? `${ep.edr_agent_id.substring(0, 10)}...` : ep.edr_agent_id}
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-[11px] text-soc-muted">
                      {ep.ip_address}
                    </td>
                    <td className="px-5 py-3.5 text-soc-muted text-xs">
                      {ep.operating_system}
                    </td>
                    <td className="px-5 py-3.5 text-soc-muted text-xs">
                      {ep.connected_user || "SYSTEM"}
                    </td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                          ep.edr_provider === "CROWDSTRIKE"
                            ? "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30"
                            : "bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/30"
                        }`}
                      >
                        {ep.edr_provider || "DEFENDER"}
                        {ep.agent_version ? ` v${ep.agent_version}` : ""}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <StatusBadge status={ep.is_isolated ? "isolated" : ep.status} />
                    </td>
                    <td className="px-5 py-3.5 font-mono text-[11px] text-soc-muted">
                      {ep.last_seen ? new Date(ep.last_seen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—"}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      {ep.is_isolated ? (
                        <button
                          onClick={() => {
                            setActionEndpoint(ep);
                            setActionType("restore");
                          }}
                          className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-colors cursor-pointer"
                        >
                          <Unlock className="w-3.5 h-3.5" />
                          Lift Containment
                        </button>
                      ) : (
                        <button
                          onClick={() => {
                            setActionEndpoint(ep);
                            setActionType("isolate");
                          }}
                          className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-lg bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30 hover:bg-red-500/20 transition-colors cursor-pointer"
                        >
                          <Lock className="w-3.5 h-3.5" />
                          Contain Host
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Containment Confirmation Modal */}
      {actionEndpoint && actionType && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-4 border-b border-soc-border mb-4">
              <div className="flex items-center gap-2">
                {actionType === "isolate" ? (
                  <ShieldAlert className="w-5 h-5 text-red-500" />
                ) : (
                  <ShieldCheck className="w-5 h-5 text-emerald-500" />
                )}
                <h3 className="text-base font-bold text-soc-text">
                  {actionType === "isolate" ? "Authorize Host Containment" : "Lift Host Containment"}
                </h3>
              </div>
              <button
                onClick={() => {
                  setActionEndpoint(null);
                  setActionType(null);
                  setConfirmDevMachine(false);
                }}
                className="text-soc-muted hover:text-soc-text"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="mb-4">
              <div className="bg-soc-bg p-3 rounded-lg border border-soc-border mb-3 text-xs leading-relaxed">
                {actionEndpoint.edr_provider === "CROWDSTRIKE" ? (
                  <>
                    <span className="font-bold text-red-600 dark:text-red-400 font-mono">[REAL CROWDSTRIKE FALCON] </span>
                    <span className="text-soc-muted">
                      {actionType === "isolate"
                        ? `Warning: This invokes live CrowdStrike Falcon network containment for AID ${actionEndpoint.edr_agent_id || actionEndpoint.hostname}. All outbound and inbound sockets will be severed except Falcon C2 telemetry.`
                        : `This will issue an authorized containment release command via Falcon API for ${actionEndpoint.hostname}.`}
                    </span>
                  </>
                ) : (
                  <>
                    <span className="font-bold text-amber-600 dark:text-amber-400 font-mono">[SIMULATED EDR] </span>
                    <span className="text-soc-muted">
                      {actionType === "isolate"
                        ? "Applies mock containment and records an event in the audit ledger."
                        : "Restores normal network posture for this endpoint."}
                    </span>
                  </>
                )}
              </div>

              <div className="space-y-1.5 text-xs text-soc-muted">
                <p>Target Host: <span className="text-soc-text font-mono font-bold">{actionEndpoint.hostname}</span></p>
                {actionEndpoint.edr_agent_id && (
                  <p>CrowdStrike Device ID: <span className="font-mono text-xs text-blue-600 dark:text-blue-400">{actionEndpoint.edr_agent_id}</span></p>
                )}
                <p>IP Address: <span className="font-mono text-soc-text">{actionEndpoint.ip_address}</span></p>
                <p>Provider: <span className="font-mono text-red-600 dark:text-red-400 font-semibold">{actionEndpoint.edr_provider}</span></p>
              </div>

              {actionType === "isolate" && (
                <div className="mt-3.5 space-y-3">
                  <div>
                    <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                      Isolation Authorization Reason
                    </label>
                    <input
                      type="text"
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                      className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-red-500 font-mono"
                    />
                  </div>

                  {/* Dev machine safety checkbox */}
                  <label className="flex items-start gap-2.5 p-2.5 rounded-lg bg-soc-bg border border-amber-500/30 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={confirmDevMachine}
                      onChange={(e) => setConfirmDevMachine(e.target.checked)}
                      className="mt-0.5 rounded border-soc-border"
                    />
                    <span className="text-soc-muted">
                      <strong className="text-amber-600 dark:text-amber-400 font-mono">Dev Workstation Safety Override:</strong> Check if this endpoint is your primary development workstation to bypass the safety block.
                    </span>
                  </label>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => {
                  setActionEndpoint(null);
                  setActionType(null);
                  setConfirmDevMachine(false);
                }}
                className="px-4 py-2 rounded-lg text-xs font-medium text-soc-muted hover:bg-soc-border/20 cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleAction}
                disabled={processing}
                className={`px-4 py-2 rounded-lg text-xs font-semibold text-white transition-colors cursor-pointer ${
                  actionType === "isolate"
                    ? "bg-red-600 hover:bg-red-700 disabled:opacity-50"
                    : "bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50"
                }`}
              >
                {processing ? "Executing..." : actionType === "isolate" ? "Confirm Containment" : "Confirm Release"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
