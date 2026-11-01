"use client";
import React from "react";
import { Sun, Moon } from "lucide-react";
import { useTheme } from "./ThemeProvider";

interface ThemeToggleProps {
  className?: string;
  showLabel?: boolean;
}

export default function ThemeToggle({
  className = "",
  showLabel = false,
}: ThemeToggleProps) {
  const { theme, toggleTheme, isDark } = useTheme();

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={`Switch to ${isDark ? "Light" : "Dark"} Mode (Current: ${theme})`}
      title={`Current: ${isDark ? "Dark Mode" : "Light Mode"} • Click to switch`}
      className={`relative inline-flex items-center justify-center gap-2 p-2 rounded-xl border transition-all duration-200 cursor-pointer select-none focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${
        isDark
          ? "bg-[#111B2E] hover:bg-[#15223A] border-[#263449] text-amber-400 hover:text-amber-300 shadow-sm"
          : "bg-white hover:bg-slate-50 border-slate-200 text-slate-700 hover:text-slate-900 shadow-sm"
      } ${className}`}
    >
      <div className="relative w-4 h-4 flex items-center justify-center">
        {isDark ? (
          <Sun className="w-4 h-4 transition-transform duration-300 rotate-0 scale-100 text-amber-400" />
        ) : (
          <Moon className="w-4 h-4 transition-transform duration-300 rotate-0 scale-100 text-slate-700" />
        )}
      </div>

      {showLabel && (
        <span className="text-xs font-semibold font-mono tracking-tight">
          {isDark ? "Dark" : "Light"}
        </span>
      )}
    </button>
  );
}

