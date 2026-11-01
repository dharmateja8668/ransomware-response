"use client";
import React, { useEffect, useState, useMemo } from "react";
import {
  Users,
  UserX,
  UserCheck,
  KeyRound,
  Shield,
  AlertTriangle,
  RefreshCw,
  X,
  Lock,
  CheckCircle2,
  AlertCircle,
  ShieldAlert,
  UserCheck2,
  Activity,
  Key,
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
import { getUser } from "@/lib/auth";
import { usersAPI } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

const ROLE_COLORS: Record<string, string> = {
  admin: "#7C3AED",
  soc_analyst: "#2563EB",
  auditor: "#D97706",
  user: "#64748B",
};

export default function IdentityPage() {
  const { isDark } = useTheme();
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [currentUser, setCurrentUser] = useState<any | null>(null);
  const [selectedUser, setSelectedUser] = useState<any | null>(null);
  const [actionType, setActionType] = useState<"suspend" | "activate" | "revoke" | null>(null);
  const [reason, setReason] = useState("Suspected compromised credentials from ransomware IOC");
  const [processing, setProcessing] = useState(false);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  const gridStroke = isDark ? "#263449" : "#E2E8F0";
  const textFill = isDark ? "#94A3B8" : "#64748B";
  const tooltipBg = isDark ? "#0B1220" : "#FFFFFF";
  const tooltipBorder = isDark ? "#263449" : "#E2E8F0";
  const tooltipColor = isDark ? "#F8FAFC" : "#172033";

  const loadUsers = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await usersAPI.list();
      setUsers(Array.isArray(res.data) ? res.data : res.data.items || []);
    } catch (err: any) {
      console.error(err);
      setError("Failed to load user directory.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setCurrentUser(getUser());
    loadUsers();
  }, []);

  const handleAction = async () => {
    if (!selectedUser || !actionType) return;
    setProcessing(true);
    setSuccessMsg("");
    try {
      if (actionType === "suspend") {
        await usersAPI.suspend(selectedUser.id, reason);
        setSuccessMsg(`Suspended user account '${selectedUser.username}'`);
      } else if (actionType === "activate") {
        await usersAPI.activate(selectedUser.id);
        setSuccessMsg(`Re-activated user account '${selectedUser.username}'`);
      } else if (actionType === "revoke") {
        await usersAPI.revokeSessions(selectedUser.id);
        setSuccessMsg(`Revoked all active tokens and sessions for '${selectedUser.username}'`);
      }
      setSelectedUser(null);
      setActionType(null);
      loadUsers();
    } catch (err: any) {
      alert("Action failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setProcessing(false);
    }
  };

  const isAdmin = currentUser?.role === "admin";

  // 4 KPIs
  const totalUsers = users.length;
  const activeUsers = users.filter((u) => u.is_active).length;
  const suspendedUsers = users.filter((u) => !u.is_active).length;
  const privilegedAccounts = users.filter((u) => u.role === "admin" || u.role === "soc_analyst").length;

  // Graph 1: Role Distribution
  const roleData = useMemo(() => {
    const counts: Record<string, number> = {};
    users.forEach((u) => {
      const r = u.role || "user";
      counts[r] = (counts[r] || 0) + 1;
    });
    return Object.keys(counts).map((r) => ({
      name: r.replace(/_/g, " ").toUpperCase(),
      role: r,
      count: counts[r],
    }));
  }, [users]);

  // Graph 2: Account Status
  const statusData = useMemo(() => {
    return [
      { name: "ACTIVE", count: activeUsers, color: "#059669" },
      { name: "SUSPENDED", count: suspendedUsers, color: "#DC2626" },
    ];
  }, [activeUsers, suspendedUsers]);

  // Graph 3: Privilege Level Breakdown
  const privilegeData = useMemo(() => {
    const adminCount = users.filter((u) => u.role === "admin").length;
    const analystCount = users.filter((u) => u.role === "soc_analyst").length;
    const standardCount = users.filter((u) => u.role !== "admin" && u.role !== "soc_analyst").length;
    return [
      { level: "Admin", count: adminCount },
      { level: "SOC Analyst", count: analystCount },
      { level: "Standard", count: standardCount },
    ];
  }, [users]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Identity & Credential Control"
        subtitle="Manage Active Directory accounts, role assignments, and emergency session invalidation."
        breadcrumb="IDENTITY"
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
            {users.length} Managed Accounts
          </span>
        }
      >
        <button
          onClick={loadUsers}
          className="flex items-center gap-1.5 bg-soc-card hover:bg-soc-border/30 border border-soc-border text-soc-text px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
          Refresh
        </button>
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
          title="Total Accounts"
          value={totalUsers}
          icon={Users}
          color="blue"
          subtitle="Directory principals"
        />
        <StatCard
          title="Active Accounts"
          value={activeUsers}
          icon={UserCheck}
          color="green"
          subtitle="Nominal access status"
        />
        <StatCard
          title="Suspended Accounts"
          value={suspendedUsers}
          icon={UserX}
          color="red"
          subtitle="Credential revocation active"
        />
        <StatCard
          title="Privileged Accounts"
          value={privilegedAccounts}
          icon={Shield}
          color="purple"
          subtitle="Admin & SOC Analyst tier"
        />
      </div>

      {/* Graphs Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph 1: Role Breakdown */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Role Distribution</h2>
              <p className="text-xs text-soc-muted">RBAC authorization tiers</p>
            </div>
            <Shield className="w-4 h-4 text-purple-600 dark:text-purple-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={roleData}
                  cx="50%"
                  cy="45%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {roleData.map((entry) => (
                    <Cell
                      key={`role-${entry.role}`}
                      fill={ROLE_COLORS[entry.role] || "#64748B"}
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

        {/* Graph 2: Account Status */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Account State</h2>
              <p className="text-xs text-soc-muted">Active vs Suspended principals</p>
            </div>
            <Activity className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={statusData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
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
                <Bar dataKey="count" name="Accounts" radius={[4, 4, 0, 0]}>
                  {statusData.map((entry, index) => (
                    <Cell key={`status-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Graph 3: Privilege Level Breakdown */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-soc-border">
            <div>
              <h2 className="text-sm font-semibold text-soc-text">Privileged Access</h2>
              <p className="text-xs text-soc-muted">Administrative attack surface</p>
            </div>
            <Key className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={privilegeData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis dataKey="level" stroke={textFill} fontSize={10} tickLine={false} />
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
                <Bar dataKey="count" name="Accounts" fill="#2563EB" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-soc-card border border-soc-border rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-3.5 border-b border-soc-border flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-soc-text">Identity Directory</h2>
            <p className="text-xs text-soc-muted">Role permissions, credential status, and emergency isolation controls</p>
          </div>
          <span className="text-xs font-mono text-soc-muted">Showing {users.length} accounts</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-soc-bg text-soc-muted text-[10px] uppercase font-mono border-b border-soc-border">
              <tr>
                <th className="px-5 py-3.5">Account Principal</th>
                <th className="px-5 py-3.5">Email Address</th>
                <th className="px-5 py-3.5">Role Authorization</th>
                <th className="px-5 py-3.5">Account Status</th>
                <th className="px-5 py-3.5">Last Authenticated</th>
                <th className="px-5 py-3.5 text-right">Emergency Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-soc-muted">
                    <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
                    <p className="font-mono">Loading user directory...</p>
                  </td>
                </tr>
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-soc-muted">
                    No user accounts found.
                  </td>
                </tr>
              ) : (
                users.map((u) => (
                  <tr key={u.id} className="hover:bg-soc-border/30 transition-colors">
                    <td className="px-5 py-3.5 font-medium text-soc-text flex items-center gap-3">
                      <div className="w-7 h-7 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold text-xs uppercase font-mono">
                        {u.username ? u.username[0] : "U"}
                      </div>
                      <div>
                        <span className="font-bold">{u.username}</span>
                        {u.id === currentUser?.id && (
                          <span className="ml-2 text-[10px] text-blue-600 dark:text-blue-400 font-mono font-normal">
                            (Active Session)
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-3.5 text-soc-muted font-mono text-[11px]">
                      {u.email}
                    </td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold capitalize border ${
                          u.role === "admin"
                            ? "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30"
                            : u.role === "soc_analyst"
                            ? "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30"
                            : "bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/30"
                        }`}
                      >
                        {u.role.replace("_", " ")}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${
                          u.is_active
                            ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                            : "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30"
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            u.is_active ? "bg-emerald-500" : "bg-red-500"
                          }`}
                        />
                        {u.is_active ? "Active" : "Suspended"}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-soc-muted font-mono text-[11px]">
                      {u.last_login ? new Date(u.last_login).toLocaleString() : "Never"}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {u.is_active ? (
                          <button
                            onClick={() => {
                              setSelectedUser(u);
                              setActionType("suspend");
                            }}
                            disabled={!isAdmin || u.id === currentUser?.id}
                            title={!isAdmin ? "Admin permissions required" : ""}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-lg bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30 hover:bg-red-500/20 transition-colors disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed font-mono"
                          >
                            <UserX className="w-3.5 h-3.5" />
                            Suspend
                          </button>
                        ) : (
                          <button
                            onClick={() => {
                              setSelectedUser(u);
                              setActionType("activate");
                            }}
                            disabled={!isAdmin}
                            title={!isAdmin ? "Admin permissions required" : ""}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-colors disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed font-mono"
                          >
                            <UserCheck className="w-3.5 h-3.5" />
                            Activate
                          </button>
                        )}

                        <button
                          onClick={() => {
                            setSelectedUser(u);
                            setActionType("revoke");
                          }}
                          disabled={!isAdmin}
                          title="Revoke active sessions and reset refresh tokens"
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-lg bg-soc-bg text-soc-muted border border-soc-border hover:text-soc-text hover:bg-soc-border/30 transition-colors disabled:opacity-30 cursor-pointer font-mono"
                        >
                          <KeyRound className="w-3.5 h-3.5" />
                          Revoke JWT
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Action Modal */}
      {selectedUser && actionType && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-4 border-b border-soc-border mb-4">
              <h3 className="text-base font-bold text-soc-text capitalize">
                {actionType === "suspend"
                  ? "Suspend User Account"
                  : actionType === "activate"
                  ? "Restore User Account"
                  : "Revoke Active Sessions"}
              </h3>
              <button
                onClick={() => {
                  setSelectedUser(null);
                  setActionType(null);
                }}
                className="text-soc-muted hover:text-soc-text"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="mb-4">
              <div className="bg-soc-bg p-3 rounded-lg border border-soc-border mb-3 text-xs leading-relaxed">
                <span className="font-bold text-amber-600 dark:text-amber-400 font-mono">[IAM INCIDENT CONTROL] </span>
                <span className="text-soc-muted">
                  {actionType === "suspend"
                    ? "Immediately disables user in Active Directory / Azure AD to halt ransomware lateral movement."
                    : actionType === "activate"
                    ? "Re-activates user principal and re-enables login access."
                    : "Invalidates all active JWT tokens, refresh tokens, and active browser sessions."}
                </span>
              </div>

              <div className="space-y-1 text-xs text-soc-muted font-mono">
                <p>Target: <span className="text-soc-text font-bold">{selectedUser.username}</span></p>
                <p>Email: <span>{selectedUser.email}</span></p>
              </div>

              {actionType === "suspend" && (
                <div className="mt-3">
                  <label className="block text-xs font-semibold text-soc-muted mb-1 uppercase tracking-wider">
                    Suspension Reason
                  </label>
                  <input
                    type="text"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    className="w-full bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-soc-text focus:outline-none focus:border-red-500 font-mono"
                  />
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => {
                  setSelectedUser(null);
                  setActionType(null);
                }}
                className="px-4 py-2 rounded-lg text-xs font-medium text-soc-muted hover:bg-soc-border/20 cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleAction}
                disabled={processing}
                className={`px-4 py-2 rounded-lg text-xs font-semibold text-white transition-colors cursor-pointer ${
                  actionType === "suspend"
                    ? "bg-red-600 hover:bg-red-700"
                    : actionType === "activate"
                    ? "bg-emerald-600 hover:bg-emerald-700"
                    : "bg-[#2563EB] hover:bg-[#1D4ED8]"
                } disabled:opacity-50`}
              >
                {processing ? "Executing..." : "Confirm Action"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
