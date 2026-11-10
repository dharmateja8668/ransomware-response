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
  HelpCircle,
  X,
} from "lucide-react";
import { authAPI } from "@/lib/api";
import { setAuth } from "@/lib/auth";
import ThemeToggle from "@/components/ThemeToggle";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showForgotModal, setShowForgotModal] = useState(false);

  // Load remembered username if explicitly saved previously
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

    if (!email.trim() || !password) {
      setError("Please enter both username and password.");
      return;
    }

    setLoading(true);

    try {
      const res = await authAPI.login(email.trim(), password);

      // Handle Remember Me preference (only saves username, never password)
      if (rememberMe) {
        localStorage.setItem("zaalima_remember_user", email.trim());
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

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 sm:p-6 md:p-8 relative selection:bg-blue-600 selection:text-white transition-colors duration-300 bg-gradient-to-br from-[#F5F3FF] via-[#FDF2F8] to-[#EFF6FF] dark:from-[#0B101D] dark:via-[#0F172A] dark:to-[#080D1A] text-slate-900 dark:text-[#F8FAFC]">
      {/* Soft ambient background radial washes */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[650px] h-[650px] rounded-full bg-gradient-to-tr from-violet-200/40 via-pink-200/35 to-blue-200/40 dark:from-indigo-950/20 dark:via-purple-950/20 dark:to-blue-950/20 blur-[130px] pointer-events-none" />

      {/* Floating Theme Switcher at Top-Right Corner */}
      <div className="absolute top-5 right-5 sm:top-6 sm:right-6 z-40">
        <ThemeToggle showLabel />
      </div>

      {/* CENTERED LOGIN CARD */}
      <div className="w-full max-w-[400px] bg-white dark:bg-[#111A2E] rounded-[18px] border border-slate-200/70 dark:border-[#1E293B] shadow-[0_12px_40px_-10px_rgba(0,0,0,0.08)] dark:shadow-[0_20px_50px_-15px_rgba(0,0,0,0.5)] p-7 sm:p-8 relative z-10 transition-all">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center">
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-600 flex items-center justify-center shadow-md shadow-blue-500/20 mb-3">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white font-mono">
            ZAALIMA
          </h1>
          <p className="text-[12px] font-medium text-slate-500 dark:text-slate-400 mt-0.5">
            Cybersecurity Operations Platform
          </p>
        </div>

        {/* Section Heading */}
        <div className="text-center mt-6 mb-6">
          <h2 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight">
            Welcome back
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Sign in to access your SOC dashboard.
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-5 p-3 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/50 flex items-start gap-2.5 text-xs text-red-600 dark:text-red-400">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span className="leading-snug">{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleLogin} className="space-y-4">
          {/* Username */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Username
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400 dark:text-slate-500">
                <User className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your username"
                required
                autoComplete="username"
                className="w-full pl-10 pr-3.5 py-2.5 rounded-xl text-xs bg-slate-50/70 hover:bg-slate-50 dark:bg-[#0A101D] dark:hover:bg-[#0C1424] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 transition-all"
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400 dark:text-slate-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
                autoComplete="current-password"
                className="w-full pl-10 pr-10 py-2.5 rounded-xl text-xs bg-slate-50/70 hover:bg-slate-50 dark:bg-[#0A101D] dark:hover:bg-[#0C1424] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 transition-all"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? "Hide password" : "Show password"}
                className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 transition-colors cursor-pointer"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Remember me & Forgot password */}
          <div className="flex items-center justify-between pt-1">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="w-3.5 h-3.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500/30 cursor-pointer accent-blue-600"
              />
              <span className="text-xs text-slate-600 dark:text-slate-400 font-medium">
                Remember me
              </span>
            </label>
            <button
              type="button"
              onClick={() => setShowForgotModal(true)}
              className="text-xs font-semibold text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors cursor-pointer"
            >
              Forgot password?
            </button>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 mt-2 rounded-xl bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-semibold text-xs tracking-wide shadow-md shadow-blue-500/20 hover:shadow-lg hover:shadow-blue-500/25 transition-all duration-150 flex items-center justify-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed cursor-pointer"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Authenticating...</span>
              </>
            ) : (
              <span>Sign in</span>
            )}
          </button>
        </form>
      </div>

      {/* Forgot Password Modal */}
      {showForgotModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 dark:bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-white dark:bg-[#111A2E] border border-slate-200 dark:border-slate-800 rounded-2xl p-6 max-w-sm w-full shadow-2xl relative text-slate-900 dark:text-[#F8FAFC]">
            <button
              onClick={() => setShowForgotModal(false)}
              aria-label="Close modal"
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-700 dark:text-slate-500 dark:hover:text-slate-300 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-3 mb-3">
              <div className="w-9 h-9 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
                <HelpCircle className="w-4 h-4 text-amber-500 dark:text-amber-400" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Credential Recovery
                </h3>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Zero-Trust Security Policy
                </p>
              </div>
            </div>

            <div className="space-y-2.5 text-xs text-slate-600 dark:text-slate-400 leading-relaxed mb-5">
              <p>
                In compliance with SOC-2 Type II standards, automated self-service password resets are disabled.
              </p>
              <p>
                Please contact your SOC Lead Administrator at <span className="font-semibold text-slate-900 dark:text-white">admin@zaalima.io</span> to request a secure password reset.
              </p>
            </div>

            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => setShowForgotModal(false)}
                className="px-4 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold transition-colors cursor-pointer"
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
