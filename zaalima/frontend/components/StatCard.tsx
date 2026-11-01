"use client";
import { LucideIcon, TrendingUp, TrendingDown, Minus } from "lucide-react";

interface StatCardProps {
  title: string;
  value: number | string;
  icon: LucideIcon;
  color: "red" | "orange" | "green" | "blue" | "purple";
  subtitle?: string;
  trend?: {
    value: string;
    isPositive?: boolean;
    isNeutral?: boolean;
  };
}

const COLOR_MAP = {
  red: {
    bg: "bg-red-500/10",
    border: "border-red-500/20",
    icon: "text-red-600 dark:text-red-400",
    value: "text-red-600 dark:text-red-400",
    glow: "group-hover:border-red-500/40",
    accent: "bg-red-500",
  },
  orange: {
    bg: "bg-orange-500/10",
    border: "border-orange-500/20",
    icon: "text-orange-600 dark:text-orange-400",
    value: "text-orange-600 dark:text-orange-400",
    glow: "group-hover:border-orange-500/40",
    accent: "bg-orange-500",
  },
  green: {
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/20",
    icon: "text-emerald-600 dark:text-emerald-400",
    value: "text-emerald-600 dark:text-emerald-400",
    glow: "group-hover:border-emerald-500/40",
    accent: "bg-emerald-500",
  },
  blue: {
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
    icon: "text-blue-600 dark:text-blue-400",
    value: "text-blue-600 dark:text-blue-400",
    glow: "group-hover:border-blue-500/40",
    accent: "bg-blue-500",
  },
  purple: {
    bg: "bg-purple-500/10",
    border: "border-purple-500/20",
    icon: "text-purple-600 dark:text-purple-400",
    value: "text-purple-600 dark:text-purple-400",
    glow: "group-hover:border-purple-500/40",
    accent: "bg-purple-500",
  },
};

export default function StatCard({
  title,
  value,
  icon: Icon,
  color,
  subtitle,
  trend,
}: StatCardProps) {
  const c = COLOR_MAP[color] || COLOR_MAP.blue;

  return (
    <div
      className={`relative group bg-white dark:bg-[#111B2E] border border-slate-200 dark:border-[#263449] rounded-xl p-4 transition-all duration-200 hover:bg-slate-50 dark:hover:bg-[#15223A] ${c.glow} shadow-sm dark:shadow-card`}
    >
      {/* Top micro accent line */}
      <div className={`absolute top-0 left-4 right-4 h-[2px] ${c.accent} opacity-40 group-hover:opacity-90 transition-opacity rounded-t`} />

      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-slate-500 dark:text-[#94A3B8] text-xs font-semibold uppercase tracking-wider truncate font-mono">
            {title}
          </p>
          <div className="flex items-baseline gap-2 mt-1">
            <span className={`text-2xl font-bold tracking-tight ${c.value} font-mono`}>
              {value}
            </span>
            {trend && (
              <span
                className={`inline-flex items-center gap-0.5 text-[11px] font-semibold px-1.5 py-0.5 rounded ${
                  trend.isNeutral
                    ? "bg-slate-500/10 text-slate-600 dark:text-slate-400"
                    : trend.isPositive
                    ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : "bg-red-500/10 text-red-600 dark:text-red-400"
                }`}
              >
                {trend.isNeutral ? (
                  <Minus className="w-2.5 h-2.5" />
                ) : trend.isPositive ? (
                  <TrendingUp className="w-2.5 h-2.5" />
                ) : (
                  <TrendingDown className="w-2.5 h-2.5" />
                )}
                {trend.value}
              </span>
            )}
          </div>
        </div>

        <div
          className={`${c.bg} ${c.border} border rounded-xl p-2.5 flex-shrink-0 group-hover:scale-105 transition-transform`}
        >
          <Icon className={`w-4 h-4 ${c.icon}`} />
        </div>
      </div>

      {subtitle && (
        <p className="text-slate-400 dark:text-[#64748B] text-[11px] mt-2.5 pt-2 border-t border-slate-100 dark:border-[#263449]/50 truncate">
          {subtitle}
        </p>
      )}
    </div>
  );
}
