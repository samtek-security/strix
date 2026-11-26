"use client";

import type { ToolRendererProps } from "@/types/events";
import { TruncatedText } from "./ToolCard";
import Markdown from "./Markdown";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400",
  low: "text-blue-400", info: "text-cyan-400", none: "text-[#888]",
};

interface ReportEntry {
  id?: string;
  title?: string;
  severity?: string;
  cvss?: number;
  cve?: string;
  cwe?: string;
  target?: string;
  endpoint?: string;
  method?: string;
  description_preview?: string;
  description?: string;
  agent_name?: string;
  by_you?: boolean;
  proof_status?: string;
}

function authorTag(r: ReportEntry) {
  if (!r.agent_name && !r.by_you) return null;
  const label = r.by_you ? "you" : r.agent_name;
  return <span className="text-[#666] text-xs ml-1.5">({label})</span>;
}

const isLead = (r: { proof_status?: string }) => {
  const status = String(r.proof_status ?? "").trim().toLowerCase();
  return status !== "" && status !== "exploited";
};

function leadBadge(r: { proof_status?: string }) {
  if (!isLead(r)) return null;
  return (
    <span className="ml-1.5 text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border border-dashed border-[#777] text-[#bbb]">
      lead, not validated
    </span>
  );
}

function sevBadge(severity: string | undefined) {
  const sev = String(severity ?? "").toLowerCase();
  const color = SEVERITY_COLORS[sev] ?? "text-yellow-400";
  return <span className={`font-semibold text-[13px] ${color}`}>{sev.toUpperCase() || "—"}</span>;
}

export default function ReportListRenderer({ toolName, result }: ToolRendererProps) {
  const res = result as Record<string, unknown> | null;
  const ok = res != null && typeof res === "object" && res.success === true;

  if (toolName === "get_report") {
    const report = ok ? (res.report as ReportEntry | undefined) : undefined;
    return (
      <div>
        <span className="text-red-400/80 font-semibold text-sm">report</span>
        {report ? (
          <div className="mt-1.5 space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              {isLead(report) ? (
                <span className="font-semibold text-[13px] text-[#bbb]">CLAIMED {String(report.severity ?? "").toUpperCase() || "—"}</span>
              ) : (
                sevBadge(report.severity)
              )}
              {leadBadge(report)}
              {report.cvss != null && <span className="text-[#888] text-[13px]">CVSS {report.cvss}</span>}
              {report.id && <span className="text-[#555] font-mono text-[13px]">{report.id}</span>}
              {report.cve && <span className="text-[#888] font-mono text-[13px]">{report.cve}</span>}
              {report.cwe && <span className="text-[#888] font-mono text-[13px]">{report.cwe}</span>}
              {(report.agent_name || report.by_you) && (
                <span className="text-[#666] text-[13px]">{report.by_you ? "you" : report.agent_name}</span>
              )}
            </div>
            {report.title && <div className="text-[15px] text-white/80 font-semibold">{report.title}</div>}
            {(report.target || report.endpoint) && (
              <div className="text-[13px] text-[#888] font-mono">
                {report.target}{report.endpoint ? ` ${report.method ?? ""} ${report.endpoint}` : ""}
              </div>
            )}
            {report.description && <TruncatedText text={report.description} maxLines={20} />}
          </div>
        ) : (
          <div className="mt-1 text-[#555] text-xs">
            {(res && typeof res === "object" && (res.error as string)) || "Report not found"}
          </div>
        )}
      </div>
    );
  }

  // list_reports
  const rawReports = ok ? res.reports : null;
  const reports: ReportEntry[] = Array.isArray(rawReports) ? (rawReports as ReportEntry[]) : [];
  const total = ok && typeof res.total_count === "number" ? (res.total_count as number) : reports.length;
  const counts = ok && res.severity_counts && typeof res.severity_counts === "object"
    ? (res.severity_counts as Record<string, number>)
    : {};
  const countEntries = Object.entries(counts);
  const leadCount = ok && typeof res.lead_count === "number" ? (res.lead_count as number) : 0;

  return (
    <div>
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-red-400/80 font-semibold text-sm">reports</span>
        <span className="text-[#555] text-[13px]">({total})</span>
        {countEntries.map(([sev, n]) => (
          <span key={sev} className="text-[13px]">
            {sevBadge(sev)}<span className="text-[#888] ml-0.5">{n}</span>
          </span>
        ))}
        {leadCount > 0 && (
          <span className="text-[13px] text-[#bbb] border border-dashed border-[#777] rounded px-1.5">
            {leadCount} {leadCount === 1 ? "lead" : "leads"}, not validated
          </span>
        )}
      </div>
      {reports.length > 0 ? (
        <div className="mt-1.5 space-y-1">
          {reports.map((r, i) => (
            <div key={r.id ?? i} className="text-[13px]">
              <span className="text-[#555] mr-1">-</span>
              {isLead(r) ? (
                <span className="font-semibold text-[13px] text-[#bbb]">CLAIMED {String(r.severity ?? "").toUpperCase() || "—"}</span>
              ) : (
                sevBadge(r.severity)
              )}
              {leadBadge(r)}
              {r.id && <span className="text-[#555] font-mono ml-1.5">{r.id}</span>}
              <span className="text-[#999] ml-1.5">{r.title ?? "(untitled)"}</span>
              {authorTag(r)}
              {(r.target || r.endpoint) && (
                <div className="ml-3 text-[#666] font-mono text-xs">
                  {r.target}{r.endpoint ? ` ${r.method ?? ""} ${r.endpoint}` : ""}
                </div>
              )}
              {r.description_preview && (
                <div className="ml-3"><Markdown text={r.description_preview} /></div>
              )}
            </div>
          ))}
        </div>
      ) : <div className="mt-1 text-[#555] text-xs">No reports filed yet</div>}
    </div>
  );
}
