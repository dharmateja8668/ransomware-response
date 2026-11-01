"use client";
import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Shield,
  Eye,
  EyeOff,
  AlertCircle,
  Loader2,
  Lock,
  User,
  Zap,
  Activity,
  CheckCircle2,
  Cpu,
  KeyRound,
  HelpCircle,
  X,
  ShieldCheck,
  Server,
  FileCheck2,
  Terminal,
} from "lucide-react";
import { authAPI } from "@/lib/api";
import { setAuth } from "@/lib/auth";
import ThemeToggle from "@/components/ThemeToggle";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin");
  const [password, setPassword] = useState("Admin@123!");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showForgotModal, setShowForgotModal] = useState(false);

  // Load remembered user if saved previously
  useEffect(() => {
    try {
      const savedUser = localStorage.getItem("zaalima_remember_user");
      if (savedUser) {
        setEmail(savedUser);
        setRememberMe(true);
      }
    } catch {
      // Ignore localStorage read errors in non-standard environments
    }
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await authAPI.login(email, password);
      
      // Handle Remember Me preference
      if (rememberMe) {
        localStorage.setItem("zaalima_remember_user", email);
      } else {
        localStorage.removeItem("zaalima_remember_user");
      }

      setAuth(res.data.access_token, res.data.user);
      router.push("/dashboard");
    } catch (err: any) {
      setError(
        err.response?.data?.detail || "Authentication failed. Check your security credentials."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleDemoFill = (u: string, p: string) => {
    setEmail(u);
    setPassword(p);
    setError("");
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#080D19] flex text-slate-900 dark:text-[#F8FAFC] selection:bg-blue-600 selection:text-white relative overflow-hidden transition-colors duration-200">
      {/* Floating Theme Switcher at Top-Right Corner */}
      <div className="absolute top-5 right-5 z-40">
        <ThemeToggle showLabel />
      </div>

      {/* Background cyber radial glow */}
      <div className="absolute top-[-20%] left-[-10%] w-[600px] h-[600px] rounded-full bg-blue-600/5 dark:bg-blue-600/10 blur-[140px] pointer-events-none" />
      <div className="absolute bottom-[-20%] right-[-10%] w-[600px] h-[600px] rounded-full bg-indigo-600/5 dark:bg-indigo-600/10 blur-[140px] pointer-events-none" />

      {/* LEFT COLUMN: Enterprise Presentation & Feature Showcase (Desktop Only) */}
      <div className="hidden lg:flex w-7/12 bg-white dark:bg-gradient-to-br dark:from-[#0B1220]/95 dark:via-[#080D19]/90 dark:to-[#0A1024]/95 text-slate-900 dark:text-white border-r border-slate-200 dark:border-[#263449] flex-col justify-between p-12 relative z-10 transition-colors">
        {/* Subtle grid pattern background */}
        <div className="absolute inset-0 bg-[radial-gradient(#CBD5E1_1px,transparent_1px)] dark:bg-[radial-gradient(#263449_1px,transparent_1px)] [background-size:24px_24px] opacity-60 dark:opacity-20 pointer-events-none" />
        
        {/* Primary Enterprise Brand Header */}
        <div className="relative z-10 flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-tr from-blue-700 via-blue-600 to-indigo-500 flex items-center justify-center shadow-lg shadow-blue-500/25 border border-blue-400/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-2xl font-black tracking-wider text-slate-900 dark:text-white font-mono">
                ZAALIMA
              </span>
              <span className="px-2 py-0.5 text-[10px] font-semibold font-mono uppercase bg-blue-500/10 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 border border-blue-500/20 dark:border-blue-500/30 rounded">
                v2.4 Enterprise
              </span>
            </div>
            <p className="text-xs font-mono tracking-widest text-slate-500 dark:text-[#94A3B8] uppercase">
              Automated Ransomware Containment & Incident Response
            </p>
          </div>
        </div>

        {/* Hero Section & Core Value Proposition */}
        <div className="relative z-10 max-w-xl my-auto py-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/25 text-blue-600 dark:text-blue-400 text-xs font-mono mb-6">
            <span className="w-2 h-2 rounded-full bg-emerald-500 dark:bg-emerald-400 animate-pulse" />
            Autonomous SOC Defensive Fabric
          </div>

          <h2 className="text-3xl xl:text-4xl font-extrabold text-slate-900 dark:text-white tracking-tight leading-tight mb-4">
            Isolate infected hosts in seconds. Eliminate enterprise extortion.
          </h2>

          <p className="text-slate-600 dark:text-slate-300 text-sm leading-relaxed mb-8">
            A defense-grade orchestration platform uniting real-time CrowdStrike Falcon EDR telemetry, automated host network isolation, volatile memory forensics, and Jira ITIL incident pipelines.
          </p>

          {/* Feature Highlights Grid */}
          <div className="grid grid-cols-2 gap-3.5">
            {[
              {
                title: "CrowdStrike Falcon EDR",
                desc: "Live OAuth2 telemetry ingestion and one-click host isolation",
                icon: Activity,
                color: "text-blue-600 dark:text-blue-400",
                bg: "bg-blue-500/10",
              },
              {
                title: "Digital Forensics Engine",
                desc: "Targeted KAPE artifact extraction & Volatility3 memory triage",
                icon: Cpu,
                color: "text-purple-600 dark:text-purple-400",
                bg: "bg-purple-500/10",
              },
              {
                title: "Encrypted Evidence Vault",
                desc: "Immutable AWS S3 storage with SHA-256 integrity sealing",
                icon: Lock,
                color: "text-emerald-600 dark:text-emerald-400",
                bg: "bg-emerald-500/10",
              },
              {
                title: "Bi-Directional Jira Sync",
                desc: "Automated ITIL incident dispatch with real-time status sync",
                icon: Zap,
                color: "text-amber-600 dark:text-amber-400",
                bg: "bg-amber-500/10",
              },
            ].map(({ title, desc, icon: Icon, color, bg }) => (
              <div
                key={title}
                className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-700/60 hover:border-blue-500/50 transition-colors backdrop-blur-sm group"
              >
                <div className="flex items-center gap-2.5 mb-1.5">
                  <div className={`p-1.5 rounded-lg ${bg} ${color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="text-xs font-bold text-slate-900 dark:text-white tracking-wide">
                    {title}
                  </span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">
                  {desc}
                </p>
              </div>
            ))}
          </div>

          {/* Quick Terminal Telemetry Ribbon */}
          <div className="mt-6 p-3 rounded-xl bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs font-mono text-slate-600 dark:text-slate-400">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              <span className="text-slate-700 dark:text-slate-300">EDR Agent Pipeline:</span>
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">ONLINE</span>
            </div>
            <div className="flex items-center gap-3 text-[11px]">
              <span>Latency: 18ms</span>
              <span className="text-slate-300 dark:text-slate-700">|</span>
              <span>TLS 1.3 Strict</span>
            </div>
          </div>
        </div>

        {/* Security & Compliance Badges */}
        <div className="relative z-10 flex items-center justify-between pt-4 border-t border-slate-200 dark:border-slate-800 text-[11px] text-slate-600 dark:text-slate-300 font-mono">
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
            AES-256 VAULT
          </span>
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
            FALCON OAUTH2 ACTIVE
          </span>
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
            ZERO-TRUST RBAC
          </span>
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
            SOC-2 TYPE II
          </span>
        </div>
      </div>

      {/* RIGHT COLUMN: Modern Glass-Effect Login Card */}
      <div className="flex-1 flex flex-col justify-center items-center p-6 sm:p-10 lg:p-12 relative z-10">
        <div className="w-full max-w-md">
          {/* Mobile-Only Brand Header (Hidden on Desktop to prevent duplicate branding) */}
          <div className="lg:hidden flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-700 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/25 border border-blue-400/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-black text-slate-900 dark:text-white font-mono">ZAALIMA</span>
                <span className="px-1.5 py-0.5 text-[9px] font-mono bg-blue-500/10 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 rounded">v2.4</span>
              </div>
              <p className="text-slate-500 dark:text-[#94A3B8] text-xs font-mono">Ransomware Containment Orchestrator</p>
            </div>
          </div>

          {/* Modern Glassmorphic Login Card */}
          <div className="bg-white dark:bg-[#111B2E]/90 backdrop-blur-xl border border-slate-200 dark:border-[#263449] rounded-2xl p-6 sm:p-8 shadow-xl dark:shadow-2xl relative overflow-hidden transition-colors">
            {/* Top glowing cyber accent line */}
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-blue-500 to-transparent opacity-90" />

            {/* Header Content */}
            <div className="mb-6">
              <div className="flex items-center justify-between mb-1.5">
                <h2 className="text-xl font-bold text-slate-900 dark:text-[#F8FAFC] tracking-tight">
                  SOC Analyst Portal
                </h2>
                <span className="flex items-center gap-1.5 text-[11px] font-mono font-medium text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 dark:bg-emerald-400 animate-pulse" />
                  TLS 1.3
                </span>
              </div>
              <p className="text-xs text-slate-600 dark:text-[#94A3B8] leading-relaxed">
                Provide your authorized SOC operator credentials to access the containment console.
              </p>
            </div>

            {/* Error Notification Alert */}
            {error && (
              <div className="mb-5 p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start gap-2.5 text-xs text-red-600 dark:text-red-300 animate-in fade-in">
                <AlertCircle className="w-4 h-4 text-red-500 dark:text-red-400 flex-shrink-0 mt-0.5" />
                <span className="leading-snug">{error}</span>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleLogin} className="space-y-4">
              {/* Username or Email Input */}
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-[#94A3B8] mb-1.5 uppercase tracking-wider font-mono">
                  Username or Security ID
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-400 dark:text-[#64748B] absolute left-3.5 top-3.5" />
                  <input
                    type="text"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    placeholder="e.g. admin or analyst"
                    className="w-full bg-slate-50 dark:bg-[#080D19]/90 border border-slate-200 dark:border-[#263449] rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-900 dark:text-[#F8FAFC] placeholder-slate-400 dark:placeholder-[#64748B] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all font-mono"
                  />
                </div>
              </div>

              {/* Password Input with Show/Hide Toggle */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-semibold text-slate-700 dark:text-[#94A3B8] uppercase tracking-wider font-mono">
                    Security Password
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowForgotModal(true)}
                    className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-500 dark:hover:text-blue-300 transition-colors font-medium cursor-pointer"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 dark:text-[#64748B] absolute left-3.5 top-3.5" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="••••••••••••"
                    className="w-full bg-slate-50 dark:bg-[#080D19]/90 border border-slate-200 dark:border-[#263449] rounded-xl pl-10 pr-11 py-2.5 text-sm text-slate-900 dark:text-[#F8FAFC] placeholder-slate-400 dark:placeholder-[#64748B] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    className="absolute right-3.5 top-3 text-slate-400 dark:text-[#64748B] hover:text-slate-600 dark:hover:text-[#94A3B8] transition-colors cursor-pointer"
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>

              {/* Remember Me & Session Security Indicator */}
              <div className="flex items-center justify-between text-xs pt-1">
                <label className="flex items-center gap-2 cursor-pointer select-none text-slate-600 dark:text-[#94A3B8] hover:text-slate-900 dark:hover:text-[#F8FAFC] transition-colors">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-300 dark:border-[#263449] bg-white dark:bg-[#080D19] text-blue-600 focus:ring-blue-500 focus:ring-offset-0 cursor-pointer accent-blue-600"
                  />
                  <span>Remember my Security ID</span>
                </label>
                <span className="text-slate-500 dark:text-[#64748B] text-[11px] font-mono">
                  JWT Session: 24h
                </span>
              </div>

              {/* Animated Sign In Button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full relative group overflow-hidden bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-500 hover:from-blue-500 hover:via-indigo-500 hover:to-blue-400 text-white font-semibold py-3 px-4 rounded-xl text-sm transition-all duration-300 shadow-md shadow-blue-600/25 hover:shadow-lg hover:shadow-blue-500/40 disabled:opacity-50 cursor-pointer active:scale-[0.99] mt-3"
              >
                <div className="absolute inset-0 w-1/2 h-full bg-white/10 skew-x-12 -translate-x-full group-hover:translate-x-[300%] transition-transform duration-1000 ease-out pointer-events-none" />
                <div className="flex items-center justify-center gap-2 relative z-10">
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Authenticating Operator...</span>
                    </>
                  ) : (
                    <>
                      <KeyRound className="w-4 h-4" />
                      <span>Authenticate & Enter Console</span>
                    </>
                  )}
                </div>
              </button>
            </form>

            {/* Quick Demo Credentials Autofill */}
            <div className="mt-6 pt-5 border-t border-slate-200 dark:border-[#263449]">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono text-slate-500 dark:text-[#64748B] uppercase tracking-wider">
                  Test & Evaluation Access:
                </span>
                <span className="text-[10px] font-mono text-blue-600 dark:text-blue-400 font-semibold">Click to autofill</span>
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                <button
                  type="button"
                  onClick={() => handleDemoFill("admin", "Admin@123!")}
                  className="p-2.5 rounded-xl bg-slate-50 hover:bg-slate-100 dark:bg-[#080D19]/80 dark:hover:bg-[#15223A] border border-slate-200 dark:border-[#263449] hover:border-blue-400 dark:hover:border-blue-500/40 text-left transition-all cursor-pointer group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs text-slate-900 dark:text-[#F8FAFC] group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                      SOC Lead (Admin)
                    </span>
                    <ShieldCheck className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 dark:text-[#64748B] block mt-0.5">
                    admin / Admin@123!
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => handleDemoFill("analyst", "Analyst@123!")}
                  className="p-2.5 rounded-xl bg-slate-50 hover:bg-slate-100 dark:bg-[#080D19]/80 dark:hover:bg-[#15223A] border border-slate-200 dark:border-[#263449] hover:border-blue-400 dark:hover:border-blue-500/40 text-left transition-all cursor-pointer group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs text-slate-900 dark:text-[#F8FAFC] group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                      Tier 2 Analyst
                    </span>
                    <Server className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 dark:text-[#64748B] block mt-0.5">
                    analyst / Analyst@123!
                  </span>
                </button>
              </div>
            </div>
          </div>

          {/* Bottom Security Assurance Footnote */}
          <div className="mt-6 flex items-center justify-center gap-2 text-[11px] text-slate-500 dark:text-[#64748B] font-mono">
            <Lock className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
            <span>Encrypted SOC Session • Strict Zero-Trust RBAC Enforced</span>
          </div>
        </div>
      </div>

      {/* Forgot Password Modal (SOC Enterprise Reset Flow) */}
      {showForgotModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-2xl p-6 max-w-md w-full shadow-2xl relative text-slate-900 dark:text-[#F8FAFC]">
            <button
              onClick={() => setShowForgotModal(false)}
              className="absolute top-4 right-4 text-slate-400 dark:text-[#64748B] hover:text-slate-700 dark:hover:text-[#F8FAFC] p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-[#15223A] transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
                <HelpCircle className="w-5 h-5 text-amber-500 dark:text-amber-400" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-[#F8FAFC]">
                  Credential Recovery Policy
                </h3>
                <p className="text-xs text-slate-500 dark:text-[#94A3B8] font-mono">
                  Enterprise Security Operations Rule
                </p>
              </div>
            </div>

            <div className="space-y-3 text-xs text-slate-600 dark:text-[#94A3B8] leading-relaxed mb-6">
              <p>
                In compliance with strict SOC-2 Type II and Zero-Trust standards, automated self-service password resets are disabled for security operations consoles.
              </p>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#080D19] border border-slate-200 dark:border-[#263449] space-y-1.5 font-mono text-[11px]">
                <div className="text-slate-900 dark:text-[#F8FAFC] font-semibold">Recovery Escalation Steps:</div>
                <div className="text-slate-600 dark:text-[#64748B]">1. Open internal Jira ticket under project <span className="text-blue-600 dark:text-blue-400 font-bold">SEC-OPS</span>.</div>
                <div className="text-slate-600 dark:text-[#64748B]">2. Contact SOC Lead Administrator at <span className="text-emerald-600 dark:text-emerald-400">admin@zaalima.corp</span>.</div>
                <div className="text-slate-600 dark:text-[#64748B]">3. Provide MFA hardware token serial verification.</div>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-[#64748B]">
                For demo testing, click either of the Quick Fill buttons on the login card to instantly load default test credentials.
              </p>
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setShowForgotModal(false);
                  handleDemoFill("admin", "Admin@123!");
                }}
                className="px-3 py-2 rounded-xl bg-blue-50 dark:bg-blue-600/20 hover:bg-blue-100 dark:hover:bg-blue-600/30 text-blue-600 dark:text-blue-400 text-xs font-semibold border border-blue-200 dark:border-blue-500/30 transition-colors cursor-pointer"
              >
                Use Admin Demo
              </button>
              <button
                type="button"
                onClick={() => setShowForgotModal(false)}
                className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold transition-colors cursor-pointer"
              >
                Understood
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
