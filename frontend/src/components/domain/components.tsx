"use client";

import React, { useState } from "react";
import { Badge } from "@/components/ui/primitives";
import { Copy, Check, Cpu, AlertTriangle, Layers, Server, ArrowRight, ShieldCheck, ShieldAlert } from "lucide-react";

// 1. DECISION PILL
export function DecisionPill({ decision, reason }: { decision?: string; reason?: string }) {
  const d = (decision || "").toUpperCase();

  let variant: "allowed" | "held" | "blocked" | "info" | "tamper" | "subtle" = "subtle";
  const label = d || "UNKNOWN";

  if (d.includes("ALLOW") || d.includes("COMMIT") || d.includes("VERIFIED") || d.includes("SUCCESS") || d === "ACTIVE") {
    variant = "allowed";
  } else if (d.includes("PENDING") || d.includes("HELD") || d.includes("APPROVAL")) {
    variant = "held";
  } else if (d.includes("BLOCK") || d.includes("REJECT") || d.includes("FAIL") || d.includes("SUSPEND") || d === "REVOKED") {
    variant = "blocked";
  } else if (d.includes("TAMPER")) {
    variant = "tamper";
  }

  return (
    <div className="inline-flex items-center gap-2">
      <Badge variant={variant}>{label}</Badge>
      {reason && <span className="text-xs text-[var(--muted)] truncate max-w-[200px]" title={reason}>({reason})</span>}
    </div>
  );
}

// 2. HASH TEXT (Truncated cryptographic digest with copy button & tooltip)
export function HashText({
  hash,
  value,
  length = 10,
  truncateLen,
}: {
  hash?: string;
  value?: string;
  length?: number;
  truncateLen?: number;
}) {
  const [copied, setCopied] = useState(false);
  const targetHash = hash || value;
  const targetLen = truncateLen || length;

  if (!targetHash) return <span className="text-xs text-[var(--subtle)] font-mono">N/A</span>;

  const truncated =
    targetHash.length > targetLen * 2
      ? `${targetHash.slice(0, targetLen)}...${targetHash.slice(-targetLen)}`
      : targetHash;

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(targetHash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <span
      onClick={handleCopy}
      title={`Click to copy: ${targetHash}`}
      className="inline-flex items-center gap-1.5 font-mono text-xs px-2.5 py-1 rounded-md bg-[var(--surface-2)] text-[var(--emerald)] border border-[var(--border)] cursor-pointer hover:border-[var(--emerald)]/50 transition-all hover:scale-[1.02] shadow-sm group"
    >
      <span>{truncated}</span>
      {copied ? (
        <Check className="w-3 h-3 text-[var(--emerald)] shrink-0" />
      ) : (
        <Copy className="w-3 h-3 text-[var(--subtle)] group-hover:text-[var(--muted)] shrink-0" />
      )}
    </span>
  );
}

// 3. STAT CARD
export function StatCard({
  title,
  value,
  subtext,
  icon: Icon,
  variant = "default",
}: {
  title: string;
  value: string | number;
  subtext?: string;
  icon?: React.ElementType;
  variant?: "emerald" | "held" | "blocked" | "info" | "default";
}) {
  const borderColors = {
    emerald: "border-l-4 border-l-[var(--emerald)] glow-emerald",
    held: "border-l-4 border-l-[var(--held)] glow-amber",
    blocked: "border-l-4 border-l-[var(--blocked)] glow-rose",
    info: "border-l-4 border-l-[var(--info)] glow-blue",
    default: "border border-[var(--border)]",
  };

  return (
    <div className={`rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5 ${borderColors[variant]} transition-all hover:border-[var(--border-strong)] shadow-sm`}>
      <div className="flex items-center justify-between text-[var(--muted)] text-xs font-medium mb-2 tracking-wide uppercase font-mono">
        <span>{title}</span>
        {Icon && <Icon className="w-4 h-4 text-[var(--subtle)]" />}
      </div>
      <div className="text-3xl font-extrabold font-mono text-[var(--fg)] tracking-tight mb-1">
        {value}
      </div>
      {subtext && <div className="text-xs text-[var(--muted)] font-mono">{subtext}</div>}
    </div>
  );
}

// 4. MODE BADGE (Honest Ledger Status)
export function ModeBadge({ mode }: { mode?: string }) {
  return (
    <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] font-mono text-xs text-[var(--fg)] shadow-sm">
      <span className="w-2 h-2 rounded-full bg-[var(--emerald)] animate-pulse"></span>
      <Server className="w-3.5 h-3.5 text-[var(--emerald)]" />
      <span className="font-medium">Ledger: local simulator</span>
      <span className="text-[10px] text-[var(--muted)] font-normal">({mode || "MODE_D"})</span>
    </div>
  );
}

// 5. EMPTY STATE
export function EmptyState({
  title = "No Data Available",
  description = "No records were returned from the backend service.",
  icon: Icon = Layers,
  actionLabel,
  onAction,
}: {
  title?: string;
  description?: string;
  icon?: React.ElementType;
  actionLabel?: string;
  onAction?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-[var(--border)] rounded-xl bg-[var(--surface)]/50">
      <div className="w-12 h-12 rounded-full bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center text-[var(--emerald)] mb-3 shadow-inner">
        <Icon className="w-6 h-6" />
      </div>
      <h4 className="text-base font-semibold text-[var(--fg)] mb-1">{title}</h4>
      <p className="text-xs text-[var(--muted)] max-w-sm mb-4 leading-relaxed">{description}</p>
      {actionLabel && onAction && (
        <button
          onClick={onAction}
          className="px-4 py-2 rounded-lg bg-[var(--emerald)] text-[var(--accent-fg)] font-semibold text-xs hover:opacity-90 transition-opacity shadow-sm"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}

// 6. SANDBOX WARNING BANNER
export function SandboxBanner() {
  return (
    <div className="mb-6 p-4 rounded-xl border border-[var(--held)]/40 bg-[var(--held)]/10 text-[var(--held)] flex items-start gap-3 shadow-sm">
      <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
      <div>
        <h4 className="text-sm font-bold">Sandbox Testing Environment</h4>
        <p className="text-xs text-[var(--held)]/90 mt-0.5 leading-relaxed">
          This section contains sandbox controls (such as off-chain evidence tamper simulation and operational mode switching).
          Actions taken here simulate attack scenarios for security verification and will trigger chain validation warnings.
        </p>
      </div>
    </div>
  );
}

// 7. PIPELINE STRIP (13-Stage Execution Component)
export const STAGES_LIST = [
  { id: 1, label: "Canonical JSON", desc: "Ingestion Schema Check" },
  { id: 2, label: "X.509 Certificate", desc: "Certificate & CRL Verification" },
  { id: 3, label: "RSA Signature", desc: "Digital Signature Verification" },
  { id: 4, label: "Agent Status", desc: "Active & Key-Version Check" },
  { id: 5, label: "Replay Protection", desc: "Nonce & Window Freshness" },
  { id: 6, label: "Server Risk", desc: "Dynamic Risk Score Evaluation" },
  { id: 7, label: "Policy Engine", desc: "Deny-by-Default Boundary Check" },
  { id: 8, label: "Decision Ticket", desc: "Branch or Human Approval Gate" },
  { id: 9, label: "Protected Execution", desc: "Signed Gateway API Execution" },
  { id: 10, label: "Evidence Builder", desc: "Off-Chain SHA-256 Digest" },
  { id: 11, label: "Hash Chain Log", desc: "Atomic Local Ledger Write" },
  { id: 12, label: "Fabric Commit", desc: "Simulator State Commit" },
  { id: 13, label: "Response Telemetry", desc: "Gateway Response Output" },
];

export function PipelineStrip({
  stoppedStage,
  reasonCode,
}: {
  stoppedStage?: number;
  reasonCode?: string;
}) {
  const lastActive = stoppedStage !== undefined ? stoppedStage : 13;

  return (
    <div className="w-full bg-[var(--surface)] border border-[var(--border)] rounded-xl p-5 mb-6 shadow-sm relative overflow-hidden">
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center text-[var(--emerald)]">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-sm text-[var(--fg)]">13-Stage Action Gateway Pipeline</h3>
            <p className="text-[11px] text-[var(--muted)]">Sequential Zero-Trust Security Verification Gateways</p>
          </div>
        </div>
        {stoppedStage !== undefined && stoppedStage < 13 ? (
          <span className="text-xs font-mono px-3 py-1 rounded-full bg-[var(--blocked)]/15 text-[var(--blocked)] border border-[var(--blocked)]/30 font-semibold flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5" />
            Stopped at Stage {stoppedStage}: {reasonCode || "REJECTED"}
          </span>
        ) : (
          <span className="text-xs font-mono px-3 py-1 rounded-full bg-[var(--allowed)]/15 text-[var(--allowed)] border border-[var(--allowed)]/30 font-semibold flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5" />
            Pipeline Passed (13/13)
          </span>
        )}
      </div>

      {/* Grid Stages with Glowing Nodes */}
      <div className="grid grid-cols-2 md:grid-cols-7 lg:grid-cols-13 gap-2">
        {STAGES_LIST.map((stg) => {
          const isPassed = stg.id <= lastActive;
          const isFailedStage = stg.id === stoppedStage && stoppedStage < 13;

          let statusBg = "bg-[var(--surface-2)] text-[var(--muted)] border-[var(--border)]";
          if (isFailedStage) {
            statusBg = "bg-red-950/40 text-red-400 border-red-500 font-bold animate-pulse shadow-[0_0_15px_rgba(248,113,113,0.3)]";
          } else if (isPassed) {
            statusBg = "bg-emerald-950/30 text-emerald-400 border-emerald-500/40 font-medium shadow-[0_0_10px_rgba(52,211,153,0.1)]";
          }

          return (
            <div
              key={stg.id}
              className={`flex flex-col items-center p-2 rounded-lg border text-center transition-all ${statusBg}`}
              title={`Stage ${stg.id}: ${stg.label} — ${stg.desc}`}
            >
              <div className="text-[10px] font-mono font-bold mb-1 opacity-80">
                0{stg.id}
              </div>
              <div className="text-[11px] font-semibold truncate w-full leading-tight">
                {stg.label}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
