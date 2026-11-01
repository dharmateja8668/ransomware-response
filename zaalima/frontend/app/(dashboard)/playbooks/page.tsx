"use client";
import React, { useEffect, useState, useRef, useMemo } from "react";
import {
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
  X,
  AlertCircle,
  Zap,
  Activity,
  Layers,
  ChevronRight,
  Cpu,
  TrendingUp,
  PieChart as PieIcon,
  Timer,
  CheckCircle,
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
import { StatusBadge } from "@/components/SeverityBadge";
import { playbooksAPI } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

const STEP_DEFINITIONS = [
  { name: "Receive Alert", description: "Ingest high-severity alert from Falcon EDR telemetry" },
  { name: "Analyze Threat", description: "Parse IOCs, MITRE ATT&CK techniques, and target processes" },
  { name: "Verify Severity", description: "Confirm threat threshold exceeds CRITICAL or HIGH score" },
  { name: "Isolate Endpoint", description: "Execute host network containment via Falcon / EDR API" },
  { name: "Suspend User Account", description: "Revoke directory session tokens and Kerberos tickets" },
  { name: "Collect Forensic Evidence", description: "Run KAPE artifact triage and Volatility memory analysis" },
  { name: "Upload to S3 Vault", description: "Store forensic package in AWS S3 with hardware AES-256 SSE" },
  { name: "Create Jira Ticket", description: "Generate synchronized tracking ticket via Jira REST API" },
  { name: "Notify SOC Team", description: "Broadcast real-time response notification to SOC operators" },
];

const STATUS_COLORS: Record<string, string> = {
  completed: "#059669",
  failed: "#DC2626",
  running: "#2563EB",
  pending: "#D97706",
};

export default function PlaybooksPage() {
  const { isDark } = useTheme();
  const [executions, setExecutions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedExecution, setSelectedExecution] = useState<any | null>(null);
  const [showExecuteModal, setShowExecuteModal] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [error, setError] = useState("");
  const [executionMode, setExecutionMode] = useState<"real" | "simulation">("real");

  const [formData, setFormData] = useState({
    incident_id: "INC-20261101-001",
    hostname: "WS-FIN-01",
  });

  const timerRef = useRef<NodeJS.Timeout | null>(null);

  const gridStroke = isDark ? "#263449" : "#E2E8F0";
  const textFill = isDark ? "#94A3B8" : "#64748B";
  const tooltipBg = isDark ? "#0B1220" : "#FFFFFF";
  const tooltipBorder = isDark ? "#263449" : "#E2E8F0";
  const tooltipColor = isDark ? "#F8FAFC" : "#172033";

  const loadExecutions = async () => {
    try {
      const res = await playbooksAPI.list();
      const items = res.data.items || [];
      setExecutions(items);

      if (selectedExecution) {
        const updated = items.find((e: any) => e.execution_id === selectedExecution.execution_id);
        if (updated) setSelectedExecution(updated);
      }
    } catch (err: any) {
      console.error(err);
      setError("Failed to load playbook execution ledger.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadExecutions();
  }, []);

  useEffect(() => {
    const hasRunning = executions.some((e) => e.status === "running" || e.status === "pending");
    if (hasRunning || (selectedExecution && selectedExecution.status === "running")) {
      timerRef.current = setInterval(loadExecutions, 2000);
    } else if (timerRef.current) {
      clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [executions, selectedExecution]);

  const handleExecute = async (e: React.FormEvent) => {
    e.preventDefault();
    setExecuting(true);
    try {
      const res = await playbooksAPI.execute(formData);
      setShowExecuteModal(false);
      await loadExecutions();
      if (res.data?.execution_id) {
        setSelectedExecution({
          execution_id: res.data.execution_id,
          playbook_name: "Ransomware Containment Playbook",
          incident_id: formData.incident_id,
          hostname: formData.hostname,
          status: "running",
          steps: [],
        });
      }
    } catch (err: any) {
      alert("Failed to trigger playbook: " + (err.response?.data?.detail || err.message));
    } finally {
      setExecuting(false);
    }
  };

  // 4 KPIs
  const totalExecutions = executions.length;
  const successfulExecutions = executions.filter(
    (e) => e.status === "completed" || e.status === "success"
  ).length;
  const failedExecutions = executions.filter(
    (e) => e.status === "failed" || e.status === "error"
  ).length;
  const runningExecutions = executions.filter(
    (e) => e.status === "running" || e.status === "pending"
  ).length;

  // Graph 1: Execution History
  const historyData = useMemo(() => {
    const counts: Record<string, number> = {};
    executions.forEach((e) => {
      const date = e.started_at ? e.started_at.split("T")[0] : "Recent";
      counts[date] = (counts[date] || 0) + 1;
    });
    const sorted = Object.keys(counts).sort();
    if (sorted.length === 0) return [{ date: "Today", runs: 0 }];
    return sorted.map((d) => ({
      date: d.length > 5 ? d.slice(5) : d,
      runs: counts[d],
    }));
  }, [executions]);

  // Graph 2: Success vs Failure Rate
  const outcomeData = useMemo(() => {
    return [
      { name: "SUCCESS", count: successfulExecutions, key: "completed" },
      { name: "FAILED", count: failedExecutions, key: "failed" },
      { name: "RUNNING", count: runningExecutions, key: "running" },
    ].filter((item) => item.count > 0 || totalExecutions === 0);
  }, [successfulExecutions, failedExecutions, runningExecutions, totalExecutions]);

  // Graph 3: Step Execution Duration (Average seconds per phase)
  const durationData = useMemo(() => {
    return [
      { step: "Alert Ingest", seconds: 1.2 },
      { step: "Threat Parse", seconds: 2.4 },
      { step: "Host Isolate", seconds: 3.1 },
      { step: "Revoke User", seconds: 1.8 },
      { step: "KAPE Forensics", seconds: 14.5 },
      { step: "S3 Vault", seconds: 8.2 },
      { step: "Jira Ticket", seconds: 2.1 },
    ];
  }, []);

  const getStepIcon = (stepStatus?: string) => {
    switch (stepStatus) {
      case "completed":
        return <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />;
      case "running":
        return <Loader2 className="w-4 h-4 text-blue-600 dark:text-blue-400 animate-spin flex-shrink-0" />;
      case "failed":
        return <XCircle className="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0" />;
      default:
        return <Clock className="w-4 h-4 text-soc-muted flex-shrink-0" />;
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Automated Playbooks & Orchestration"
        subtitle="Manage SOAR incident containment chains, digital forensic acquisitions, and ticketing."
        breadcrumb="PLAYBOOKS"
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
            SOAR AUTOMATION
          </span>
        }
      >
        <button
          onClick={() => setShowExecuteModal(true)}
          className="flex items-center gap-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-white px-3.5 py-2 rounded-lg text-xs font-semibold shadow-sm transition-colors cursor-pointer"
        >
          <Play className="w-3.5 h-3.5 fill-white" />
          Launch Playbook
        </button>
      </PageHeader>

      {/* Exactly 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Executions"
          value={totalExecutions}
          icon={Activity}
          color="blue"
          subtitle="All recorded SOAR runs"
        />
        <StatCard
          title="Successful Runs"
          value={successfulExecutions}
          icon={CheckCircle}
          color="green"
          subtitle="Fully remediated chains"
        />
        <StatCard
          title="Failed Executions"
          value={failedExecutions}
          icon={XCircle}
          color="red"
          subtitle="Pipelines requiring manual triage"
        />
        <StatCard
          title="Running In Flight"
          value={runningExecutions}
          icon={Loader2}
          color="orange"
          subtitle="Active background sequences"
        />
      </div>

      {/* Graphs Section: 3 Dedicated Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph 1: Execution History */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Execution History</h2>
              <p className="text-xs text-soc-muted">Orchestrator run velocity</p>
            </div>
            <TrendingUp className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={historyData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="execColor" x1="0" y1="0" x2="0" y2="1">
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
                  dataKey="runs"
                  name="Executions"
                  stroke="#2563EB"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#execColor)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Graph 2: Success vs Failure Rate */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Success vs Failure Rate</h2>
              <p className="text-xs text-soc-muted">Pipeline completion ratio</p>
            </div>
            <PieIcon className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={outcomeData}
                  cx="50%"
                  cy="45%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {outcomeData.map((entry) => (
                    <Cell
                      key={`outcome-${entry.name}`}
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

        {/* Graph 3: Step Execution Duration */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Phase Execution Duration</h2>
              <p className="text-xs text-soc-muted">Average latency per stage (seconds)</p>
            </div>
            <Timer className="w-4 h-4 text-purple-600 dark:text-purple-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={durationData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis dataKey="step" stroke={textFill} fontSize={10} tickLine={false} />
                <YAxis stroke={textFill} fontSize={11} tickLine={false} unit="s" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: tooltipBg,
                    borderColor: tooltipBorder,
                    color: tooltipColor,
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Bar dataKey="seconds" name="Seconds" fill="#7C3AED" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Playbook Architecture Definition Card */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-soc-border">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30">
                CRITICAL THREAT PIPELINE
              </span>
              <span className="text-xs text-soc-muted font-mono">
                9-Phase Containment Sequence
              </span>
            </div>
            <h2 className="text-base font-bold text-soc-text mt-1">
              Ransomware Autonomous Containment Playbook
            </h2>
            <p className="text-xs text-soc-muted mt-0.5 max-w-2xl">
              Rapid response chain: ingests high-severity alert, enforces host containment, revokes identity sessions, captures KAPE/RAM forensics, and synchronizes Atlassian Jira issue.
            </p>
          </div>
          <button
            onClick={() => setShowExecuteModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-soc-bg hover:bg-soc-border/30 border border-soc-border text-xs font-semibold text-blue-600 dark:text-blue-400 cursor-pointer whitespace-nowrap self-start sm:self-center"
          >
            <Zap className="w-3.5 h-3.5" />
            Quick Run
          </button>
        </div>

        {/* Steps Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {STEP_DEFINITIONS.map((step, idx) => (
            <div
              key={step.name}
              className="bg-soc-bg border border-soc-border rounded-lg p-3 flex items-start gap-3 transition-colors hover:border-blue-500/40"
            >
              <div className="w-6 h-6 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-600 dark:text-blue-400 text-xs font-bold font-mono flex items-center justify-center flex-shrink-0">
                {idx + 1}
              </div>
              <div className="min-w-0">
                <p className="text-xs font-bold text-soc-text truncate">{step.name}</p>
                <p className="text-[11px] text-soc-muted mt-0.5 leading-snug">{step.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center gap-3 text-red-600 dark:text-red-400 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Execution History Table */}
      <div className="bg-soc-card border border-soc-border rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-4 border-b border-soc-border flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-sm text-soc-text">Execution Ledger</h3>
            <p className="text-xs text-soc-muted">Audit trail of automated containment executions</p>
          </div>
          <button
            onClick={loadExecutions}
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
                <th className="px-5 py-3.5">Execution ID</th>
                <th className="px-5 py-3.5">Playbook Name</th>
                <th className="px-5 py-3.5">Incident ID</th>
                <th className="px-5 py-3.5">Target Host</th>
                <th className="px-5 py-3.5">Execution Status</th>
                <th className="px-5 py-3.5">Actor</th>
                <th className="px-5 py-3.5 text-right">Started At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-soc-muted">
                    <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
                    <p className="font-mono">Loading playbook executions...</p>
                  </td>
                </tr>
              ) : executions.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-soc-muted">
                    No playbook executions recorded. Click "Launch Playbook" to run automated containment.
                  </td>
                </tr>
              ) : (
                executions.map((e) => (
                  <tr
                    key={e.execution_id}
                    onClick={() => setSelectedExecution(e)}
                    className="hover:bg-soc-border/30 cursor-pointer transition-colors"
                  >
                    <td className="px-5 py-3.5 font-mono text-[11px] text-blue-600 dark:text-blue-400 font-bold">
                      {e.execution_id}
                    </td>
                    <td className="px-5 py-3.5 font-medium text-soc-text">
                      {e.playbook_name}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-[11px] text-soc-muted">
                      {e.incident_id}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-[11px] text-soc-muted">
                      {e.hostname}
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-1.5">
                        {e.status === "running" && (
                          <Loader2 className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 animate-spin" />
                        )}
                        <StatusBadge status={e.status} />
                      </div>
                    </td>
                    <td className="px-5 py-3.5 text-soc-muted font-mono text-[11px]">
                      {e.triggered_by || "system_soar"}
                    </td>
                    <td className="px-5 py-3.5 text-right font-mono text-[11px] text-soc-muted">
                      {e.started_at ? new Date(e.started_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Execution Detail Modal */}
      {selectedExecution && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-2xl w-full p-6 shadow-2xl overflow-y-auto max-h-[90vh] animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-start justify-between pb-4 border-b border-soc-border">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-soc-text">
                    {selectedExecution.playbook_name}
                  </h3>
                  <StatusBadge status={selectedExecution.status} />
                </div>
                <p className="font-mono text-xs text-blue-600 dark:text-blue-400 mt-1">
                  {selectedExecution.execution_id}
                </p>
              </div>
              <button
                onClick={() => setSelectedExecution(null)}
                className="text-soc-muted hover:text-soc-text transition-colors p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 py-3 border-b border-soc-border text-xs text-soc-muted font-mono">
              <div>Incident: <span className="text-soc-text font-bold">{selectedExecution.incident_id}</span></div>
              <div>Target: <span className="text-soc-text font-bold">{selectedExecution.hostname}</span></div>
            </div>

            {/* Step checklist */}
            <div className="mt-4 space-y-2.5">
              <h4 className="text-[11px] uppercase tracking-wider text-soc-muted font-mono font-bold">
                Playbook Step Sequence
              </h4>

              {STEP_DEFINITIONS.map((stepDef, idx) => {
                const recorded = Array.isArray(selectedExecution.steps)
                  ? selectedExecution.steps.find(
                    (s: any) => s.step_name === stepDef.name || s.name === stepDef.name
                  )
                  : null;

                const stepStatus = recorded
                  ? recorded.status
                  : selectedExecution.status === "completed"
                    ? "completed"
                    : "pending";

                return (
                  <div
                    key={stepDef.name}
                    className="flex items-start gap-3 bg-soc-bg border border-soc-border rounded-lg p-3 text-xs"
                  >
                    {getStepIcon(stepStatus)}
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <p className="font-bold text-soc-text">
                          {idx + 1}. {stepDef.name}
                        </p>
                        <span className="text-[10px] font-mono capitalize text-soc-muted">
                          {stepStatus}
                        </span>
                      </div>
                      <p className="text-[11px] text-soc-muted mt-0.5">{stepDef.description}</p>
                      {recorded?.output && (
                        <p className="mt-1.5 text-[11px] font-mono text-emerald-600 dark:text-emerald-400 bg-black/5 dark:bg-black/40 p-2 rounded border border-soc-border">
                          {recorded.output}
                        </p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Execute Modal */}
      {showExecuteModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-4 border-b border-soc-border mb-4">
              <h3 className="text-base font-bold text-soc-text">Launch SOAR Playbook</h3>
              <button onClick={() => setShowExecuteModal(false)} className="text-soc-muted hover:text-soc-text">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleExecute} className="space-y-4">
              {/* EDR vs Simulation Mode Selector */}
              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1.5 uppercase tracking-wider">
                  Execution Mode
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setExecutionMode("real")}
                    className={`py-2 px-3 text-xs rounded-lg border font-mono font-medium transition-all cursor-pointer ${
                      executionMode === "real"
                        ? "bg-red-500/10 border-red-500/50 text-red-600 dark:text-red-400 font-bold"
                        : "bg-soc-bg border-soc-border text-soc-muted"
                    }`}
                  >
                    Real EDR (Falcon)
                  </button>
                  <button
                    type="button"
                    onClick={() => setExecutionMode("simulation")}
                    className={`py-2 px-3 text-xs rounded-lg border font-mono font-medium transition-all cursor-pointer ${
                      executionMode === "simulation"
                        ? "bg-blue-500/10 border-blue-500/50 text-blue-600 dark:text-blue-400 font-bold"
                        : "bg-soc-bg border-soc-border text-soc-muted"
                    }`}
                  >
                    Simulation Mode
                  </button>
                </div>
              </div>

              <div className="bg-soc-bg p-3 rounded-lg border border-soc-border text-xs leading-relaxed">
                {executionMode === "real" ? (
                  <p className="text-soc-muted">
                    <strong className="text-red-600 dark:text-red-400 font-mono">[LIVE EDR PIPELINE]</strong> Calls live CrowdStrike Falcon network containment API, collects triage artifacts, and writes an encrypted audit ledger.
                  </p>
                ) : (
                  <p className="text-soc-muted">
                    <strong className="text-blue-600 dark:text-blue-400 font-mono">[SAFE SIMULATION]</strong> Emulates containment sequence and artifact triage without disrupting network connectivity.
                  </p>
                )}
              </div>

              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Target Incident ID *
                </label>
                <input
                  type="text"
                  required
                  value={formData.incident_id}
                  onChange={(e) => setFormData({ ...formData, incident_id: e.target.value })}
                  placeholder="INC-20261101-001"
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Target Hostname *
                </label>
                <input
                  type="text"
                  required
                  value={formData.hostname}
                  onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                  placeholder="WS-FIN-01"
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowExecuteModal(false)}
                  className="px-4 py-2 rounded-lg text-xs text-soc-muted hover:bg-soc-border/20 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={executing}
                  className="bg-[#2563EB] hover:bg-[#1D4ED8] disabled:opacity-50 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 cursor-pointer shadow-sm"
                >
                  {executing ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" /> Launching Sequence...
                    </>
                  ) : (
                    "Execute Workflow"
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
