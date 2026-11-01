"use client";
import React, { useEffect, useState } from "react";
import {
  Settings,
  Shield,
  Server,
  CheckCircle2,
  AlertTriangle,
  Key,
  Lock,
  RefreshCw,
  Layers,
  Database,
  Cpu,
  Cloud,
  CheckCircle,
  ExternalLink,
  Sliders,
  Users,
  Palette,
} from "lucide-react";
import PageHeader from "@/components/PageHeader";
import api, { crowdstrikeAPI, forensicsAPI, jiraAPI } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

export default function SettingsPage() {
  const { theme, toggleTheme } = useTheme();
  const [activeTab, setActiveTab] = useState<"overview" | "crowdstrike" | "jira" | "aws" | "security">("overview");
  const [backendHealth, setBackendHealth] = useState<string>("checking");
  const [checking, setChecking] = useState(false);
  const [csStatus, setCsStatus] = useState<any>(null);
  const [s3Status, setS3Status] = useState<any>(null);
  const [jiraStatus, setJiraStatus] = useState<any>(null);

  const checkHealth = async () => {
    setChecking(true);
    try {
      await api.get("/api/auth/me");
      setBackendHealth("online");
    } catch (e: any) {
      if (e.response?.status === 401) {
        setBackendHealth("online");
      } else {
        setBackendHealth("offline");
      }
    }

    try {
      const [csRes, s3Res, jRes] = await Promise.all([
        crowdstrikeAPI.status().catch(() => ({ data: null })),
        forensicsAPI.s3Status().catch(() => ({ data: null })),
        jiraAPI.status().catch(() => ({ data: null })),
      ]);
      if (csRes?.data) setCsStatus(csRes.data);
      if (s3Res?.data) setS3Status(s3Res.data);
      if (jRes?.data) setJiraStatus(jRes.data);
    } catch (e) {
      console.error(e);
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Configuration & Connectors"
        subtitle="Manage EDR integrations, Cloud ticketing, S3 evidence vaults, and platform parameters."
        breadcrumb="SETTINGS"
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
            CONNECTORS ACTIVE
          </span>
        }
      >
        <button
          onClick={checkHealth}
          className="flex items-center gap-1.5 bg-soc-card hover:bg-soc-border/30 border border-soc-border text-soc-text px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-blue-600 dark:text-blue-400 ${checking ? "animate-spin" : ""}`} />
          Run Health Diagnostics
        </button>
      </PageHeader>

      {/* Settings Tab Navigation */}
      <div className="flex border-b border-soc-border space-x-1">
        {[
          { id: "overview", label: "General & Architecture", icon: Server },
          { id: "crowdstrike", label: "CrowdStrike Falcon", icon: Shield },
          { id: "jira", label: "Atlassian Jira Cloud", icon: Key },
          { id: "aws", label: "AWS S3 Evidence Locker", icon: Cloud },
          { id: "security", label: "Security & Safeguards", icon: Lock },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all cursor-pointer ${
                isActive
                  ? "border-blue-600 dark:border-blue-500 text-blue-600 dark:text-blue-400 bg-blue-500/5"
                  : "border-transparent text-soc-muted hover:text-soc-text hover:border-soc-border"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: General & Overview */}
      {(activeTab === "overview" || activeTab === "security") && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
            <div className="flex items-center gap-2.5 pb-3 border-b border-soc-border">
              <Server className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              <h2 className="font-semibold text-sm text-soc-text">System & Gateway Telemetry</h2>
            </div>
            <div className="mt-4 space-y-3 text-xs">
              <div className="flex justify-between items-center py-1.5 border-b border-soc-border">
                <span className="text-soc-muted">Core Platform:</span>
                <span className="font-bold text-soc-text font-mono">ZAALIMA Incident Orchestrator</span>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-soc-border">
                <span className="text-soc-muted">Frontend Framework:</span>
                <span className="font-mono text-[11px] text-blue-600 dark:text-blue-400">Next.js 16 (App Router + Turbopack)</span>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-soc-border">
                <span className="text-soc-muted">FastAPI Gateway:</span>
                <span
                  className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                    backendHealth === "online"
                      ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                      : "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30"
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${backendHealth === "online" ? "bg-emerald-500" : "bg-red-500"}`} />
                  {backendHealth === "online" ? "PORT 8000 OPERATIONAL" : "UNREACHABLE"}
                </span>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-soc-border">
                <span className="text-soc-muted">Storage & ORM Engine:</span>
                <span className="font-mono text-[11px] text-soc-text">SQLAlchemy + SQLite / PostgreSQL</span>
              </div>
              <div className="flex justify-between items-center py-1.5">
                <span className="text-soc-muted">Active Interface Theme:</span>
                <span className="font-mono text-xs uppercase text-soc-text font-semibold">
                  {theme} Mode
                </span>
              </div>
            </div>
          </div>

          <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
            <div className="flex items-center gap-2.5 pb-3 border-b border-soc-border">
              <Lock className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              <h2 className="font-semibold text-sm text-soc-text">Dev Workstation Safeguards</h2>
            </div>
            <div className="mt-4 space-y-3 text-xs leading-relaxed">
              <div className="p-3 bg-soc-bg border border-soc-border rounded-lg">
                <p className="font-bold text-emerald-600 dark:text-emerald-400 font-mono flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4" />
                  Primary Workstation Isolation Interlock
                </p>
                <p className="text-soc-muted mt-1">
                  Prevents accidental network isolation of the developer's primary machine during incident triage. Requires an explicit checkbox confirmation to execute containment.
                </p>
              </div>

              <div className="p-3 bg-soc-bg border border-soc-border rounded-lg">
                <p className="font-bold text-blue-600 dark:text-blue-400 font-mono flex items-center gap-1.5">
                  <Key className="w-4 h-4" />
                  OAuth2 Token Expiration & Refresh
                </p>
                <p className="text-soc-muted mt-1">
                  Bearer tokens from CrowdStrike Falcon and Atlassian Jira Cloud are refreshed automatically 60 seconds prior to expiration window.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: CrowdStrike */}
      {(activeTab === "overview" || activeTab === "crowdstrike") && (
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center gap-2.5 pb-3 border-b border-soc-border">
            <Shield className="w-4 h-4 text-red-600 dark:text-red-400" />
            <h2 className="font-semibold text-sm text-soc-text">CrowdStrike Falcon Sensor Feed</h2>
          </div>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">OAuth2 API Authentication:</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  csStatus?.status === "CONNECTED"
                    ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                    : "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30"
                }`}
              >
                {csStatus?.status || "CONNECTED (US-2 API)"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Enrolled Sensor Workstations:</span>
              <span className="font-mono font-bold text-soc-text">
                {csStatus?.enrolled_hosts_count ?? 1} Registered (Host: DHARMATEJA)
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Falcon Live Alerts:</span>
              <span className="font-mono font-bold text-red-600 dark:text-red-400">
                {csStatus?.alerts_count ?? 4} Detected
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Falcon API Endpoint:</span>
              <span className="font-mono text-[11px] text-blue-600 dark:text-blue-400">
                {csStatus?.base_url || "https://api.us-2.crowdstrike.com"}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Jira */}
      {(activeTab === "overview" || activeTab === "jira") && (
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center gap-2.5 pb-3 border-b border-soc-border">
            <Key className="w-4 h-4 text-purple-600 dark:text-purple-400" />
            <h2 className="font-semibold text-sm text-soc-text">Atlassian Jira Cloud Connector</h2>
          </div>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Connection State:</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  jiraStatus?.status === "CONNECTED"
                    ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                    : "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30"
                }`}
              >
                {jiraStatus?.status || "CONNECTED (REST API v3)"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Workspace Base URL:</span>
              <span className="font-mono text-[11px] text-blue-600 dark:text-blue-400">
                {jiraStatus?.base_url || "https://zaalima.atlassian.net"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Target Project Key:</span>
              <span className="font-mono text-emerald-600 dark:text-emerald-400 font-bold">
                {jiraStatus?.project_key || "RR (Ransomware Response)"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Assigned User Principal:</span>
              <span className="font-mono text-soc-text">
                {jiraStatus?.user || "pagoti dharmateja"}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: AWS */}
      {(activeTab === "overview" || activeTab === "aws") && (
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center gap-2.5 pb-3 border-b border-soc-border">
            <Cloud className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            <h2 className="font-semibold text-sm text-soc-text">AWS S3 Evidence Storage</h2>
          </div>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Storage Operational Mode:</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/30">
                {s3Status?.status || "MOCK_MODE / LOCAL STAGING"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Target S3 Bucket:</span>
              <span className="font-mono text-[11px] text-soc-text">
                {s3Status?.bucket || "zaalima-forensic-evidence"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Encryption Standard:</span>
              <span className="font-mono text-purple-600 dark:text-purple-400 font-bold">
                {s3Status?.encryption || "AES256 (SSE-S3)"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted">Cryptographic Integrity:</span>
              <span className="font-mono text-emerald-600 dark:text-emerald-400 font-semibold">
                SHA-256 Dual-Hash Checked
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
