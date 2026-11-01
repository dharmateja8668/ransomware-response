"use client";
import React from "react";
import { ChevronRight } from "lucide-react";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  breadcrumb?: string;
  badge?: React.ReactNode;
  children?: React.ReactNode;
}

export default function PageHeader({
  title,
  subtitle,
  breadcrumb,
  badge,
  children,
}: PageHeaderProps) {
  return (
    <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6 pb-4 border-b border-slate-200 dark:border-[#263449]/70 transition-colors">
      <div>
        {breadcrumb && (
          <div className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-[#94A3B8] uppercase tracking-wider mb-1 font-mono">
            <span>SOC Console</span>
            <ChevronRight className="w-3 h-3 text-slate-400 dark:text-[#64748B]" />
            <span className="text-blue-600 dark:text-[#3B82F6] font-semibold">{breadcrumb}</span>
          </div>
        )}
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-[#F8FAFC]">
            {title}
          </h1>
          {badge}
        </div>
        {subtitle && (
          <p className="text-slate-600 dark:text-[#94A3B8] text-xs md:text-sm mt-1 max-w-3xl leading-relaxed">
            {subtitle}
          </p>
        )}
      </div>
      {children && (
        <div className="flex items-center gap-2.5 flex-wrap flex-shrink-0">
          {children}
        </div>
      )}
    </div>
  );
}
