"use client";
import React, { useEffect, useState, useMemo } from "react";
import {
  Search,
  Database,
  HardDrive,
  RefreshCw,
  Plus,
  X,
  Shield,
  FileCheck,
  AlertCircle,
  Cloud,
  Cpu,
  FileCode,
  UploadCloud,
  CheckCircle2,
  Terminal,
  Lock,
  Archive,
  Hourglass,
  XCircle,
  CheckCircle,
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
import { forensicsAPI } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

const EVIDENCE_TYPES = [
  { value: "kape_artifacts", label: "KAPE Forensic Triage Package (.zip)" },
  { value: "volatility_report", label: "Volatility Memory Analysis Report (.json)" },
  { value: "memory_dump", label: "Volatile RAM Dump (.raw / .dmp)" },
  { value: "network_capture", label: "PCAP Network Traffic Capture (.pcapng)" },
  { value: "log_files", label: "Windows Event Logs & Sysmon (.evtx)" },
  { value: "disk_image", label: "Full Forensic Disk Image (.E01)" },
];

const TYPE_COLORS = ["#2563EB", "#7C3AED", "#059669", "#D97706", "#DB2777", "#64748B"];

export default function ForensicsPage() {
  const { isDark } = useTheme();
  const [evidenceList, setEvidenceList] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [s3Status, setS3Status] = useState<any>(null);
  const [hostnameFilter, setHostnameFilter] = useState("");
  const [incidentFilter, setIncidentFilter] = useState("");
  const [selectedEvidence, setSelectedEvidence] = useState<any | null>(null);
  const [custodyData, setCustodyData] = useState<any | null>(null);
  const [volatilityResult, setVolatilityResult] = useState<any | null>(null);

  // Modals
  const [showCollectModal, setShowCollectModal] = useState(false);
  const [showKapeModal, setShowKapeModal] = useState(false);
  const [showVolModal, setShowVolModal] = useState(false);

  // Action loaders
  const [actionLoading, setActionLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Forms
  const [kapeForm, setKapeForm] = useState({
    incident_id: "INC-20261101-001",
    hostname: "WS-FIN-01",
    categories: ["RegistryHives", "EventLogs", "Prefetch", "Amcache"],
    notes: "Automated KAPE artifact triage run",
  });

  const [volForm, setVolForm] = useState({
    incident_id: "INC-20261101-001",
    hostname: "WS-FIN-01",
    memory_dump_path: "",
  });

  const [formData, setFormData] = useState({
    incident_id: "INC-20261101-001",
    hostname: "WS-FIN-01",
    evidence_type: "kape_artifacts",
    notes: "Automated live forensics triage before containment",
  });

  const gridStroke = isDark ? "#263449" : "#E2E8F0";
  const textFill = isDark ? "#94A3B8" : "#64748B";
  const tooltipBg = isDark ? "#0B1220" : "#FFFFFF";
  const tooltipBorder = isDark ? "#263449" : "#E2E8F0";
  const tooltipColor = isDark ? "#F8FAFC" : "#172033";

  const loadData = async () => {
    setLoading(true);
    setStatusMessage(null);
    try {
      const [evRes, s3Res] = await Promise.all([
        forensicsAPI.list({
          hostname: hostnameFilter || undefined,
          incident_id: incidentFilter || undefined,
        }),
        forensicsAPI.s3Status().catch(() => ({ data: null })),
      ]);
      setEvidenceList(evRes.data.items || []);
      if (s3Res && s3Res.data) {
        setS3Status(s3Res.data);
      }
    } catch (err: any) {
      console.error(err);
      setStatusMessage({ type: "error", text: "Failed to retrieve forensic evidence catalog." });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleKapeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setActionLoading(true);
    try {
      const res = await forensicsAPI.collectKape(kapeForm);
      setStatusMessage({
        type: "success",
        text: `KAPE Artifact Collection complete. Package SHA-256: ${res.data.sha256.substring(0, 16)}...`,
      });
      setShowKapeModal(false);
      loadData();
    } catch (err: any) {
      alert("KAPE Collection failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setActionLoading(false);
    }
  };

  const handleVolSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setActionLoading(true);
    try {
      const res = await forensicsAPI.analyzeVolatility(volForm);
      setVolatilityResult(res.data.analysis);
      setStatusMessage({
        type: "success",
        text: `Volatility Memory Analysis complete. Verdict: ${res.data.analysis.threat_verdict}`,
      });
      setShowVolModal(false);
      loadData();
    } catch (err: any) {
      alert("Volatility analysis failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setActionLoading(false);
    }
  };

  const handleUploadS3 = async (evidenceId: string) => {
    setActionLoading(true);
    try {
      const res = await forensicsAPI.uploadS3(evidenceId);
      const upload = res.data.s3_upload;
      setStatusMessage({
        type: "success",
        text: `Evidence uploaded to AWS S3: ${upload.s3_uri} (${upload.encryption})`,
      });
      loadData();
      if (selectedEvidence && selectedEvidence.evidence_id === evidenceId) {
        setSelectedEvidence(null);
      }
    } catch (err: any) {
      alert("S3 Upload failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setActionLoading(false);
    }
  };

  const viewCustody = async (ev: any) => {
    setSelectedEvidence(ev);
    try {
      const res = await forensicsAPI.getCustody(ev.evidence_id);
      setCustodyData(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  const formatBytes = (bytes?: number) => {
    if (!bytes) return "—";
    const mb = bytes / (1024 * 1024);
    if (mb >= 1024) return (mb / 1024).toFixed(2) + " GB";
    return mb.toFixed(1) + " MB";
  };

  // 4 KPIs
  const totalEvidence = evidenceList.length;
  const pendingCollections = evidenceList.filter(
    (e) => e.collection_status === "pending" || !e.s3_bucket
  ).length;
  const verifiedEvidence = evidenceList.filter(
    (e) => e.file_hash_sha256 && (e.collection_status === "verified" || e.collection_status === "completed" || e.s3_bucket)
  ).length;
  const failedCollections = evidenceList.filter(
    (e) => e.collection_status === "failed"
  ).length;

  // Graph 1: Timeline
  const timelineData = useMemo(() => {
    const counts: Record<string, number> = {};
    evidenceList.forEach((e) => {
      const date = e.collected_at ? e.collected_at.split("T")[0] : "Recent";
      counts[date] = (counts[date] || 0) + 1;
    });
    const sorted = Object.keys(counts).sort();
    if (sorted.length === 0) return [{ date: "Today", packages: 0 }];
    return sorted.map((d) => ({
      date: d.length > 5 ? d.slice(5) : d,
      packages: counts[d],
    }));
  }, [evidenceList]);

  // Graph 2: Artifact Type Breakdown
  const typeDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    evidenceList.forEach((e) => {
      const t = e.evidence_type || "Artifact";
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.keys(counts).map((type) => ({
      name: type.replace(/_/g, " ").toUpperCase(),
      count: counts[type],
    }));
  }, [evidenceList]);

  // Graph 3: Storage Vault Distribution
  const storageData = useMemo(() => {
    const s3Count = evidenceList.filter((e) => e.s3_bucket).length;
    const localCount = evidenceList.filter((e) => !e.s3_bucket).length;
    return [
      { name: "AWS S3 VAULT", count: s3Count, color: "#059669" },
      { name: "LOCAL STAGED", count: localCount, color: "#2563EB" },
    ];
  }, [evidenceList]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Digital Forensics & Evidence Locker"
        subtitle="Manage forensic artifact packages, Volatility memory analysis, and cryptographic custody."
        breadcrumb="FORENSICS"
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
            CHAIN OF CUSTODY VERIFIED
          </span>
        }
      >
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setShowKapeModal(true)}
            className="flex items-center gap-1.5 bg-[#4F46E5] hover:bg-[#4338CA] text-white px-3 py-1.5 rounded-lg text-xs font-semibold font-mono transition-colors cursor-pointer"
          >
            <Cpu className="w-3.5 h-3.5" />
            Run KAPE Triage
          </button>
          <button
            onClick={() => setShowVolModal(true)}
            className="flex items-center gap-1.5 bg-[#D97706] hover:bg-[#B45309] text-white px-3 py-1.5 rounded-lg text-xs font-semibold font-mono transition-colors cursor-pointer"
          >
            <Terminal className="w-3.5 h-3.5" />
            Volatility Memory
          </button>
          <button
            onClick={() => setShowCollectModal(true)}
            className="flex items-center gap-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-white px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            Collect Custom
          </button>
        </div>
      </PageHeader>

      {/* Exactly 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Evidence Collected"
          value={totalEvidence}
          icon={Archive}
          color="blue"
          subtitle="Total artifact packages"
        />
        <StatCard
          title="Pending S3 Vault"
          value={pendingCollections}
          icon={Hourglass}
          color="orange"
          subtitle="Staged on local sensor"
        />
        <StatCard
          title="Verified Checksums"
          value={verifiedEvidence}
          icon={CheckCircle}
          color="green"
          subtitle="Cryptographically sealed"
        />
        <StatCard
          title="Failed Collections"
          value={failedCollections}
          icon={XCircle}
          color="red"
          subtitle="Extraction anomalies"
        />
      </div>

      {/* Graphs Section: 3 Dedicated Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph 1: Timeline */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Acquisition Timeline</h2>
              <p className="text-xs text-soc-muted">Evidence packages captured over time</p>
            </div>
            <TrendingUp className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="forensicColor" x1="0" y1="0" x2="0" y2="1">
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
                  dataKey="packages"
                  name="Artifact Packages"
                  stroke="#2563EB"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#forensicColor)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Graph 2: Artifact Type Distribution */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Artifact Type Breakdown</h2>
              <p className="text-xs text-soc-muted">KAPE vs Volatility vs Event Logs</p>
            </div>
            <Cpu className="w-4 h-4 text-purple-600 dark:text-purple-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={typeDistribution}
                  cx="50%"
                  cy="45%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {typeDistribution.map((entry, index) => (
                    <Cell
                      key={`type-${index}`}
                      fill={TYPE_COLORS[index % TYPE_COLORS.length]}
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

        {/* Graph 3: Storage Vault Breakdown */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Storage & Encryption</h2>
              <p className="text-xs text-soc-muted">AWS S3 Cloud Vault vs Local Staged</p>
            </div>
            <Cloud className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={storageData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
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
                <Bar dataKey="count" name="Packages" radius={[4, 4, 0, 0]}>
                  {storageData.map((entry, index) => (
                    <Cell key={`storage-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* S3 Storage Status Banner */}
      {s3Status && (
        <div className="bg-soc-card border border-soc-border rounded-xl p-4 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div
              className={`p-2.5 rounded-xl border ${
                s3Status.real_aws
                  ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                  : "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30"
              }`}
            >
              <Cloud className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="text-xs font-bold text-soc-text uppercase tracking-wide">
                  AWS S3 Evidence Locker
                </h4>
                <span
                  className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                    s3Status.status === "CONNECTED"
                      ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                      : "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30"
                  }`}
                >
                  {s3Status.status}
                </span>
                <span className="text-[10px] font-mono text-purple-600 dark:text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/30">
                  {s3Status.encryption}
                </span>
              </div>
              <p className="text-xs text-soc-muted mt-0.5 font-mono">
                Target Bucket: <span className="text-soc-text">{s3Status.bucket}</span> | Region:{" "}
                <span className="text-soc-text">{s3Status.region}</span>
              </p>
            </div>
          </div>
          <p className="text-xs text-soc-muted max-w-md">{s3Status.message}</p>
        </div>
      )}

      {statusMessage && (
        <div
          className={`p-3.5 rounded-xl flex items-center gap-3 text-xs border ${
            statusMessage.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400"
              : "bg-red-500/10 border-red-500/30 text-red-600 dark:text-red-400"
          }`}
        >
          {statusMessage.type === "success" ? (
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
          )}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Volatility Memory Triage Findings */}
      {volatilityResult && (
        <div className="bg-soc-card border border-red-500/30 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-soc-border">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-red-500" />
              <h3 className="text-xs font-bold text-soc-text uppercase tracking-wide">
                Volatility 3 Memory Triage Findings
              </h3>
              <span className="bg-red-500/10 text-red-600 dark:text-red-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-red-500/30">
                {volatilityResult.threat_verdict}
              </span>
            </div>
            <button
              onClick={() => setVolatilityResult(null)}
              className="text-soc-muted hover:text-soc-text text-xs font-mono cursor-pointer"
            >
              Dismiss
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
            {volatilityResult.findings?.map((f: any, idx: number) => (
              <div key={idx} className="bg-soc-bg p-3 rounded-lg border border-soc-border text-xs">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-blue-600 dark:text-blue-400 font-bold">{f.finding_type}</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30">
                    {f.severity}
                  </span>
                </div>
                <p className="text-soc-text mt-0.5">{f.description}</p>
                {f.command_line && (
                  <p className="font-mono text-amber-600 dark:text-amber-400 bg-black/5 dark:bg-black/40 p-2 rounded mt-2 break-all border border-soc-border">
                    $ {f.command_line}
                  </p>
                )}
                {f.foreign_address && (
                  <p className="font-mono text-purple-600 dark:text-purple-400 bg-black/5 dark:bg-black/40 p-1.5 rounded mt-1.5 border border-soc-border">
                    Foreign IP: {f.foreign_address} (PID: {f.pid})
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filter and Search */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-soc-muted absolute left-3.5 top-3" />
            <input
              type="text"
              value={hostnameFilter}
              onChange={(e) => setHostnameFilter(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && loadData()}
              placeholder="Filter by hostname..."
              className="w-full bg-soc-bg border border-soc-border rounded-lg pl-10 pr-4 py-2 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={incidentFilter}
              onChange={(e) => setIncidentFilter(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && loadData()}
              placeholder="Incident ID..."
              className="bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-blue-500 font-mono w-44"
            />

            <button
              onClick={loadData}
              className="bg-[#2563EB] hover:bg-[#1D4ED8] text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
            >
              Filter
            </button>
          </div>
        </div>
      </div>

      {/* Evidence Table */}
      <div className="bg-soc-card border border-soc-border rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-3.5 border-b border-soc-border flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-soc-text">Forensic Package Catalog</h2>
            <p className="text-xs text-soc-muted">Acquired memory dumps, KAPE triage archives, and chain of custody audit records</p>
          </div>
          <span className="text-xs font-mono text-soc-muted">Showing {evidenceList.length} items</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-soc-bg text-soc-muted text-[10px] uppercase font-mono border-b border-soc-border">
              <tr>
                <th className="px-5 py-3.5">Evidence ID & Filename</th>
                <th className="px-5 py-3.5">Host / Incident</th>
                <th className="px-5 py-3.5">Acquisition Type</th>
                <th className="px-5 py-3.5">SHA-256 Checksum</th>
                <th className="px-5 py-3.5">Simulation Status</th>
                <th className="px-5 py-3.5">Storage Vault</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-soc-muted">
                    <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
                    <p className="font-mono">Loading forensic evidence packages...</p>
                  </td>
                </tr>
              ) : evidenceList.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-soc-muted">
                    No evidence packages captured yet. Trigger KAPE triage or Volatility analysis above.
                  </td>
                </tr>
              ) : (
                evidenceList.map((ev) => (
                  <tr key={ev.evidence_id} className="hover:bg-soc-border/30 transition-colors">
                    <td className="px-5 py-3.5">
                      <span className="font-mono text-[11px] text-blue-600 dark:text-blue-400 font-bold block">
                        {ev.evidence_id}
                      </span>
                      <span className="font-mono text-[10px] text-soc-muted block truncate max-w-[160px]" title={ev.file_name}>
                        {ev.file_name || `${ev.evidence_id}.zip`}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 font-mono text-soc-text font-semibold">
                      <div>{ev.hostname}</div>
                      <div className="text-[10px] text-soc-muted font-normal">{ev.incident_id || "Unlinked"}</div>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/30">
                        {ev.evidence_type}
                      </span>
                    </td>
                    <td
                      className="px-5 py-3.5 font-mono text-[11px] text-emerald-600 dark:text-emerald-400 max-w-[140px] truncate"
                      title={ev.file_hash_sha256}
                    >
                      {ev.file_hash_sha256 ? `${ev.file_hash_sha256.substring(0, 12)}...` : "—"}
                    </td>
                    <td className="px-5 py-3.5">
                      {ev.is_simulated || !ev.s3_bucket ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30">
                          <AlertCircle className="w-3 h-3" />
                          SIMULATED_TRIAGE
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                          <CheckCircle className="w-3 h-3" />
                          REAL_HOST_COLLECTION
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3.5">
                      {ev.s3_bucket ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                          <Cloud className="w-3 h-3" />
                          AWS S3 WORM
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/30">
                          <HardDrive className="w-3 h-3" />
                          Local Vault Staging
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => viewCustody(ev)}
                          className="px-2.5 py-1 text-xs rounded-lg bg-soc-bg hover:bg-soc-border/30 border border-soc-border text-soc-text font-mono transition-colors cursor-pointer"
                        >
                          Chain of Custody
                        </button>
                        {!ev.s3_bucket && (
                          <button
                            onClick={() => handleUploadS3(ev.evidence_id)}
                            disabled={actionLoading}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white font-mono font-semibold transition-colors cursor-pointer disabled:opacity-50"
                          >
                            <UploadCloud className="w-3 h-3" />
                            Upload S3
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Evidence Chain of Custody Detail Modal */}
      {selectedEvidence && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-xl w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-start justify-between pb-4 border-b border-soc-border">
              <div>
                <div className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  <h3 className="text-base font-bold text-soc-text">Forensic Evidence Package</h3>
                </div>
                <p className="font-mono text-xs text-blue-600 dark:text-blue-400 mt-1">{selectedEvidence.evidence_id}</p>
              </div>
              <button onClick={() => setSelectedEvidence(null)} className="text-soc-muted hover:text-soc-text">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="py-4 space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3 bg-soc-bg p-3 rounded-lg border border-soc-border">
                <div>
                  <span className="text-soc-muted">Target Host:</span>
                  <p className="text-soc-text font-bold text-sm mt-0.5 font-mono">{selectedEvidence.hostname}</p>
                </div>
                <div>
                  <span className="text-soc-muted">Incident ID:</span>
                  <p className="font-mono text-blue-600 dark:text-blue-400 mt-0.5 font-bold">{selectedEvidence.incident_id || "Unlinked"}</p>
                </div>
                <div>
                  <span className="text-soc-muted">Acquisition Type:</span>
                  <p className="text-soc-text font-mono mt-0.5 font-semibold">{selectedEvidence.evidence_type}</p>
                </div>
                <div>
                  <span className="text-soc-muted">Package Size:</span>
                  <p className="text-soc-text font-mono mt-0.5">{formatBytes(selectedEvidence.file_size_bytes)}</p>
                </div>
                <div className="col-span-2">
                  <span className="text-soc-muted">Forensic Integrity & Simulation Status:</span>
                  <div className="mt-1">
                    {selectedEvidence.is_simulated || !selectedEvidence.s3_bucket ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30">
                        <AlertCircle className="w-3.5 h-3.5" />
                        SIMULATED_TRIAGE_PACKAGE (Mock RAM/Triage Fallback, Zero Host Disruption)
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                        <CheckCircle className="w-3.5 h-3.5" />
                        REAL_HOST_COLLECTION (Physical Memory / Full Disk / KAPE)
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div>
                <span className="text-soc-muted">Evidence File Name:</span>
                <p className="font-mono text-soc-text bg-soc-bg p-2 rounded border border-soc-border mt-0.5 break-all">
                  {selectedEvidence.file_name}
                </p>
              </div>

              {selectedEvidence.file_hash_sha256 && (
                <div>
                  <span className="text-soc-muted">Streaming Checksum (SHA-256):</span>
                  <p className="font-mono text-emerald-600 dark:text-emerald-400 bg-soc-bg p-2 rounded border border-soc-border mt-0.5 break-all font-bold">
                    {selectedEvidence.file_hash_sha256}
                  </p>
                </div>
              )}

              <div className="bg-soc-bg p-3 rounded-lg border border-soc-border">
                <span className="text-soc-muted font-mono text-[11px] block mb-1">
                  Storage Vault Location & Object Lock:
                </span>
                {selectedEvidence.s3_bucket ? (
                  <div>
                    <span className="text-emerald-600 dark:text-emerald-400 font-bold flex items-center gap-1.5 font-mono">
                      <Cloud className="w-4 h-4" />
                      AWS S3 Cloud Vault (Enforced SSE-S3 AES-256)
                    </span>
                    <p className="font-mono text-soc-text mt-1 text-[11px]">
                      s3://{selectedEvidence.s3_bucket}/{selectedEvidence.s3_key}
                    </p>
                  </div>
                ) : (
                  <div>
                    <span className="text-blue-600 dark:text-blue-400 font-bold flex items-center gap-1.5 font-mono">
                      <HardDrive className="w-4 h-4" />
                      Local Evidence Vault (Simulated WORM Object Lock Staging)
                    </span>
                    <p className="font-mono text-soc-text mt-1 text-[11px]">
                      d:/ransomware response/zaalima/backend/storage/evidence_vault/{selectedEvidence.file_name || `${selectedEvidence.evidence_id}.zip`}
                    </p>
                  </div>
                )}
              </div>

              {/* Chain of Custody */}
              <div className="border-t border-soc-border pt-3">
                <h4 className="font-bold text-soc-text uppercase tracking-wider text-[11px] font-mono mb-2 flex items-center gap-1.5">
                  <FileCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                  Chain of Custody Ledger
                </h4>
                <div className="bg-soc-bg p-3 rounded-lg border border-soc-border space-y-2 text-soc-muted max-h-48 overflow-y-auto">
                  {custodyData?.chain_of_custody?.length > 0 ? (
                    custodyData.chain_of_custody.map((c: any, i: number) => (
                      <div key={i} className="border-b border-soc-border/60 pb-1.5 last:border-0 last:pb-0">
                        <div className="flex items-center justify-between text-soc-text font-semibold">
                          <span>{i + 1}. {c.action}</span>
                          <span className="text-[10px] font-mono text-soc-muted">
                            {c.timestamp ? new Date(c.timestamp).toLocaleString() : ""}
                          </span>
                        </div>
                        <p className="text-[11px] text-soc-muted">
                          Actor: {c.actor} {c.location ? `| Loc: ${c.location}` : ""}
                        </p>
                        {c.verification_hash_sha256 && (
                          <p className="font-mono text-[10px] text-emerald-600 dark:text-emerald-400 truncate">
                            Hash: {c.verification_hash_sha256}
                          </p>
                        )}
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-soc-muted">No ledger records available.</p>
                  )}
                </div>
              </div>
            </div>

            <div className="flex justify-between items-center pt-2">
              {!selectedEvidence.s3_bucket ? (
                <button
                  onClick={() => handleUploadS3(selectedEvidence.evidence_id)}
                  disabled={actionLoading}
                  className="flex items-center gap-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-white px-3.5 py-2 rounded-lg text-xs font-semibold cursor-pointer shadow-sm"
                >
                  <UploadCloud className="w-3.5 h-3.5" />
                  Upload to AWS S3 Vault
                </button>
              ) : <div />}
              <button
                onClick={() => setSelectedEvidence(null)}
                className="bg-soc-bg hover:bg-soc-border/30 border border-soc-border text-soc-text px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* KAPE Modal */}
      {showKapeModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-4 border-b border-soc-border mb-4">
              <div className="flex items-center gap-2">
                <Cpu className="w-5 h-5 text-indigo-500" />
                <h3 className="text-base font-bold text-soc-text">Execute KAPE Triage Acquisition</h3>
              </div>
              <button onClick={() => setShowKapeModal(false)} className="text-soc-muted hover:text-soc-text">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleKapeSubmit} className="space-y-4">
              <div className="bg-soc-bg p-3 rounded-lg border border-soc-border text-xs leading-relaxed">
                <span className="font-bold text-indigo-600 dark:text-indigo-400 font-mono">Kroll Artifact Parser and Extractor: </span>
                <span className="text-soc-muted">
                  Acquires Registry hives, Event Logs (.evtx), Prefetch, and Amcache into an integrity-sealed package with SHA-256 hash.
                </span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Target Incident ID *
                </label>
                <input
                  type="text"
                  required
                  value={kapeForm.incident_id}
                  onChange={(e) => setKapeForm({ ...kapeForm, incident_id: e.target.value })}
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
                  value={kapeForm.hostname}
                  onChange={(e) => setKapeForm({ ...kapeForm, hostname: e.target.value })}
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowKapeModal(false)}
                  className="px-4 py-2 rounded-lg text-xs font-medium text-soc-muted hover:bg-soc-border/20 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="bg-[#4F46E5] hover:bg-[#4338CA] disabled:opacity-50 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
                >
                  {actionLoading ? "Acquiring..." : "Execute KAPE Sequence"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Volatility Modal */}
      {showVolModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-4 border-b border-soc-border mb-4">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-amber-500" />
                <h3 className="text-base font-bold text-soc-text">Volatility 3 Memory Triage</h3>
              </div>
              <button onClick={() => setShowVolModal(false)} className="text-soc-muted hover:text-soc-text">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleVolSubmit} className="space-y-4">
              <div className="bg-soc-bg p-3 rounded-lg border border-soc-border text-xs leading-relaxed">
                <span className="font-bold text-amber-600 dark:text-amber-400 font-mono">Volatility 3 Engine: </span>
                <span className="text-soc-muted">
                  Scans unmapped executable memory spaces (malfind), checks cmdline for vssadmin shadows deletion, and flags suspicious C2 network egress sockets.
                </span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Target Incident ID *
                </label>
                <input
                  type="text"
                  required
                  value={volForm.incident_id}
                  onChange={(e) => setVolForm({ ...volForm, incident_id: e.target.value })}
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
                  value={volForm.hostname}
                  onChange={(e) => setVolForm({ ...volForm, hostname: e.target.value })}
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowVolModal(false)}
                  className="px-4 py-2 rounded-lg text-xs font-medium text-soc-muted hover:bg-soc-border/20 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="bg-[#D97706] hover:bg-[#B45309] disabled:opacity-50 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
                >
                  {actionLoading ? "Analyzing Memory..." : "Launch Memory Triage"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Custom Collect Modal */}
      {showCollectModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-4 border-b border-soc-border mb-4">
              <h3 className="text-base font-bold text-soc-text">Custom Evidence Capture</h3>
              <button onClick={() => setShowCollectModal(false)} className="text-soc-muted hover:text-soc-text">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setActionLoading(true);
                try {
                  await forensicsAPI.collect(formData);
                  setShowCollectModal(false);
                  loadData();
                } catch (err: any) {
                  alert("Collection failed: " + (err.response?.data?.detail || err.message));
                } finally {
                  setActionLoading(false);
                }
              }}
              className="space-y-4"
            >
              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Incident ID *
                </label>
                <input
                  type="text"
                  required
                  value={formData.incident_id}
                  onChange={(e) => setFormData({ ...formData, incident_id: e.target.value })}
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
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Evidence Artifact Type *
                </label>
                <select
                  value={formData.evidence_type}
                  onChange={(e) => setFormData({ ...formData, evidence_type: e.target.value })}
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500"
                >
                  {EVIDENCE_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                  Analyst Notes
                </label>
                <textarea
                  rows={2}
                  value={formData.notes}
                  onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                  className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowCollectModal(false)}
                  className="px-4 py-2 rounded-lg text-xs font-medium text-soc-muted hover:bg-soc-border/20 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="bg-[#2563EB] hover:bg-[#1D4ED8] disabled:opacity-50 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer shadow-sm"
                >
                  {actionLoading ? "Queueing Package..." : "Collect Artifact"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
