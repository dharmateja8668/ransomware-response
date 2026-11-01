"use client";

interface BadgeProps {
  severity?: string;
  status?: string;
  className?: string;
}

const SEVERITY_CONFIG: Record<
  string,
  { bg: string; text: string; border: string; dot: string }
> = {
  critical: {
    bg: "bg-red-500/10",
    text: "text-red-600 dark:text-red-400",
    border: "border-red-500/30",
    dot: "bg-red-500",
  },
  high: {
    bg: "bg-orange-500/10",
    text: "text-orange-600 dark:text-orange-400",
    border: "border-orange-500/30",
    dot: "bg-orange-500",
  },
  medium: {
    bg: "bg-amber-500/10",
    text: "text-amber-600 dark:text-amber-400",
    border: "border-amber-500/30",
    dot: "bg-amber-500",
  },
  low: {
    bg: "bg-blue-500/10",
    text: "text-blue-600 dark:text-blue-400",
    border: "border-blue-500/30",
    dot: "bg-blue-500",
  },
};

const STATUS_CONFIG: Record<
  string,
  { bg: string; text: string; border: string; dot: string }
> = {
  // Threat & Incident States
  new: { bg: "bg-red-500/10", text: "text-red-600 dark:text-red-400", border: "border-red-500/30", dot: "bg-red-500" },
  detected: { bg: "bg-red-500/10", text: "text-red-600 dark:text-red-400", border: "border-red-500/30", dot: "bg-red-500" },
  investigating: { bg: "bg-amber-500/10", text: "text-amber-600 dark:text-amber-400", border: "border-amber-500/30", dot: "bg-amber-500" },
  containing: { bg: "bg-orange-500/10", text: "text-orange-600 dark:text-orange-400", border: "border-orange-500/30", dot: "bg-orange-500" },
  evidence_collection: { bg: "bg-purple-500/10", text: "text-purple-600 dark:text-purple-400", border: "border-purple-500/30", dot: "bg-purple-500" },
  contained: { bg: "bg-blue-500/10", text: "text-blue-600 dark:text-blue-400", border: "border-blue-500/30", dot: "bg-blue-500" },
  resolved: { bg: "bg-emerald-500/10", text: "text-emerald-600 dark:text-emerald-400", border: "border-emerald-500/30", dot: "bg-emerald-500" },
  false_positive: { bg: "bg-slate-500/10", text: "text-slate-600 dark:text-slate-400", border: "border-slate-500/30", dot: "bg-slate-500" },

  // Endpoint States
  healthy: { bg: "bg-emerald-500/10", text: "text-emerald-600 dark:text-emerald-400", border: "border-emerald-500/30", dot: "bg-emerald-500" },
  normal: { bg: "bg-emerald-500/10", text: "text-emerald-600 dark:text-emerald-400", border: "border-emerald-500/30", dot: "bg-emerald-500" },
  suspicious: { bg: "bg-amber-500/10", text: "text-amber-600 dark:text-amber-400", border: "border-amber-500/30", dot: "bg-amber-500" },
  infected: { bg: "bg-red-500/10", text: "text-red-600 dark:text-red-400", border: "border-red-500/30", dot: "bg-red-500" },
  isolated: { bg: "bg-blue-500/10", text: "text-blue-600 dark:text-blue-400", border: "border-blue-500/30", dot: "bg-blue-500" },
  offline: { bg: "bg-slate-500/10", text: "text-slate-600 dark:text-slate-400", border: "border-slate-500/30", dot: "bg-slate-500" },

  // Execution & Pipeline States
  pending: { bg: "bg-slate-500/10", text: "text-slate-600 dark:text-slate-400", border: "border-slate-500/30", dot: "bg-slate-500" },
  running: { bg: "bg-blue-500/10", text: "text-blue-600 dark:text-blue-400", border: "border-blue-500/30", dot: "bg-blue-500 animate-pulse" },
  completed: { bg: "bg-emerald-500/10", text: "text-emerald-600 dark:text-emerald-400", border: "border-emerald-500/30", dot: "bg-emerald-500" },
  failed: { bg: "bg-red-500/10", text: "text-red-600 dark:text-red-400", border: "border-red-500/30", dot: "bg-red-500" },
  success: { bg: "bg-emerald-500/10", text: "text-emerald-600 dark:text-emerald-400", border: "border-emerald-500/30", dot: "bg-emerald-500" },
};

export function SeverityBadge({ severity, className = "" }: { severity: string; className?: string }) {
  const key = severity?.toLowerCase() || "low";
  const cfg = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.low;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wider border ${cfg.bg} ${cfg.text} ${cfg.border} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {severity}
    </span>
  );
}

export function StatusBadge({ status, className = "" }: { status: string; className?: string }) {
  const key = status?.toLowerCase() || "pending";
  const cfg = STATUS_CONFIG[key] || {
    bg: "bg-slate-500/10",
    text: "text-slate-600 dark:text-slate-400",
    border: "border-slate-500/30",
    dot: "bg-slate-500",
  };
  const label = status?.replace(/_/g, " ");

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium capitalize border ${cfg.bg} ${cfg.text} ${cfg.border} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {label}
    </span>
  );
}
