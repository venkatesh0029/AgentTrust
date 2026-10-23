"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { api, AuditRecord } from "@/lib/api";
import { StatCard, DecisionPill, HashText, EmptyState } from "@/components/domain/components";
import { Card, Button } from "@/components/ui/primitives";
import { 
  Activity, 
  ShieldCheck, 
  ShieldAlert, 
  Clock, 
  Database, 
  RefreshCw, 
  TrendingUp,
  Layers,
  Sparkles
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip as RechartsTooltip,
  PieChart, 
  Pie, 
  Cell 
} from "recharts";

export default function OverviewPage() {
  const router = useRouter();
  const { data: auditEvents = [], refetch: refetchEvents, isLoading: auditLoading, isError: auditError } = useQuery({
    queryKey: ["auditEvents"],
    queryFn: () => api.fetchAuditChain(),
    refetchInterval: 3000,
  });
  const { data: chainVerify, isLoading: chainVerifyLoading, isError: chainVerifyError } = useQuery({
    queryKey: ["chainVerify"],
    queryFn: () => api.verifyChain(),
    refetchInterval: 5000,
  });
  const { data: pendingApprovals = [], isLoading: approvalsLoading, isError: approvalsError } = useQuery({
    queryKey: ["pendingApprovals"],
    queryFn: () => api.fetchPendingApprovals(),
    refetchInterval: 5000,
  });

  const { data: health, isLoading: healthLoading, isError: healthError } = useQuery({
    queryKey: ["backendHealth"],
    queryFn: () => api.fetchHealth(),
    refetchInterval: 5000,
  });
  // Calculate real metrics from audit data
  const allowedCount = auditEvents.filter((e: AuditRecord) => { const decision = (e.decision || "").toUpperCase(); return decision.includes("ALLOW") || decision.includes("COMMIT"); }).length;

  const blockedCount = auditEvents.filter((e: AuditRecord) =>
    (e.decision || "").toUpperCase().includes("BLOCK")
  ).length;

  const heldCount = pendingApprovals.length;
  const heldDecisionCount = auditEvents.filter((e: AuditRecord) => { const decision = (e.decision || "").toUpperCase(); return decision.includes("HELD") || decision.includes("PENDING") || decision.includes("APPROVAL"); }).length;

  // Both visualizations below are derived exclusively from backend records.
  const chartTimelineData = auditEvents.slice(-10).map((event, index) => ({
    name: event.request_id ? event.request_id.slice(-6) : `#${event.sequence_number || index + 1}`,
    riskScore: event.risk_score,
  }));

  const pieData = [
    { name: "Allowed", value: allowedCount, color: "#34d399" },
    { name: "Held", value: heldDecisionCount, color: "#fbbf24" },
    { name: "Blocked", value: blockedCount, color: "#f87171" },
  ].filter((item) => item.value > 0);
  return (
    <div className="space-y-6">
      
      {/* Top Banner Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-3 py-1">
            <h1 className="text-2xl font-extrabold text-[var(--fg)] tracking-tight leading-snug">
              Security Operations Overview
            </h1>
            <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wide border font-mono ${
              healthError
                ? "bg-rose-950/50 text-rose-400 border-rose-500/30"
                : healthLoading
                ? "bg-[var(--surface-2)] text-[var(--muted)] border-[var(--border)]"
                : (health?.status || "UNKNOWN").toUpperCase() === "ONLINE"
                ? "bg-emerald-950/60 text-emerald-400 border-emerald-500/30"
                : "bg-amber-950/50 text-amber-400 border-amber-500/30"
            }`}>
              {healthError ? "BACKEND UNAVAILABLE" : healthLoading ? "CHECKING BACKEND" : `BACKEND ${(health?.status || "UNKNOWN").toUpperCase()}`}
            </span>
          </div>
          <p className="text-xs text-[var(--muted)] mt-1">
            Backend health, cryptographic decisions, recent risk scores, and audit-chain verification from returned records.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={() => refetchEvents()}>
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
            <span>Refresh Telemetry</span>
          </Button>
          <Link href="/gateway">
            <Button variant="emerald" size="sm">
              <Sparkles className="w-3.5 h-3.5 mr-1.5" />
              Submit Action Request
            </Button>
          </Link>
        </div>
      </div>

      {/* Hero KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="AUTHORIZED ACTIONS"
          value={auditLoading ? "…" : auditError ? "—" : allowedCount}
          subtext={auditError ? "Audit API unavailable" : auditLoading ? "Loading audit records" : "Recorded allowed or committed decisions"}
          icon={ShieldCheck}
          variant="emerald"
        />
        <StatCard
          title="HELD FOR APPROVAL"
          value={approvalsLoading ? "…" : approvalsError ? "—" : heldCount}
          subtext={approvalsError ? "Approvals API unavailable" : approvalsLoading ? "Loading approval queue" : "Currently pending approval tickets"}
          icon={Clock}
          variant="held"
        />
        <StatCard
          title="BLOCKED VIOLATIONS"
          value={auditLoading ? "…" : auditError ? "—" : blockedCount}
          subtext={auditError ? "Audit API unavailable" : auditLoading ? "Loading audit records" : "Recorded blocked decisions"}
          icon={ShieldAlert}
          variant="blocked"
        />
        <StatCard
          title="CHAIN INTEGRITY"
          value={chainVerifyLoading ? "CHECKING" : chainVerifyError ? "UNAVAILABLE" : chainVerify?.valid ? "VERIFIED" : "TAMPERED"}
          subtext={chainVerify?.status || (chainVerifyError ? "Verification API unavailable" : chainVerifyLoading ? "Checking chain integrity" : chainVerify?.message || "No verification details returned")}
          icon={Database}
          variant={chainVerifyLoading || chainVerifyError ? "info" : chainVerify?.valid ? "emerald" : "blocked"}
        />
      </div>

      {/* Audit-derived visualizations; no latency is inferred from risk scores. */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-[var(--emerald)]" />
              <h3 className="font-bold text-sm text-[var(--fg)]">Risk Scores in Recent Audit Records</h3>
            </div>
            <span className="text-xs font-mono text-[var(--muted)]">Source: audit chain</span>
          </div>
          {auditLoading ? (
            <div className="h-56 flex items-center justify-center text-xs text-[var(--muted)]">Loading audit records…</div>
          ) : auditError ? (
            <div className="h-56 flex items-center justify-center text-xs text-[var(--blocked)]">Risk chart unavailable: audit API request failed.</div>
          ) : chartTimelineData.length === 0 ? (
            <div className="h-56 flex items-center justify-center text-xs text-[var(--muted)]">No audit records are available to chart.</div>
          ) : (
            <div className="h-56 w-full pt-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartTimelineData}>
                  <defs>
                    <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#34d399" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#34d399" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="name" stroke="#5b6878" fontSize={10} tickLine={false} />
                  <YAxis stroke="#5b6878" fontSize={10} tickLine={false} />
                  <RechartsTooltip
                    contentStyle={{
                      backgroundColor: "#0f141b",
                      borderColor: "#1f2a37",
                      borderRadius: "8px",
                      fontSize: "12px",
                      color: "#e6edf3",
                    }}
                  />
                  <Area type="monotone" dataKey="riskScore" name="Risk score" stroke="#34d399" strokeWidth={2} fillOpacity={1} fill="url(#riskGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
            <h3 className="font-bold text-sm text-[var(--fg)] flex items-center gap-2">
              <Layers className="w-4 h-4 text-amber-400" />
              Audit Decision Breakdown
            </h3>
            <span className="text-xs font-mono text-[var(--muted)]">Recorded events</span>
          </div>
          {auditLoading ? (
            <div className="h-44 flex items-center justify-center text-xs text-[var(--muted)]">Loading decisions…</div>
          ) : auditError ? (
            <div className="h-44 flex items-center justify-center text-xs text-[var(--blocked)]">Decision breakdown unavailable.</div>
          ) : pieData.length === 0 ? (
            <div className="h-44 flex items-center justify-center text-xs text-[var(--muted)]">No categorized decisions in the audit records.</div>
          ) : (
            <div className="h-44 w-full flex items-center justify-center relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={5} dataKey="value">
                    {pieData.map((entry, index) => <Cell key={`decision-${entry.name}-${index}`} fill={entry.color} />)}
                  </Pie>
                  <RechartsTooltip contentStyle={{ backgroundColor: "#0f141b", borderColor: "#1f2a37", borderRadius: "8px", fontSize: "12px", color: "#e6edf3" }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-xl font-bold font-mono text-[var(--fg)]">{auditEvents.length}</span>
                <span className="text-[10px] text-[var(--muted)] uppercase font-mono">Audit events</span>
              </div>
            </div>
          )}
          <div className="space-y-1.5 pt-1 text-xs">
            <div className="flex items-center justify-between"><span className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />Allowed / committed</span><span className="font-mono font-bold">{allowedCount}</span></div>
            <div className="flex items-center justify-between"><span className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-amber-400" />Held / pending</span><span className="font-mono font-bold">{heldDecisionCount}</span></div>
            <div className="flex items-center justify-between"><span className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-rose-400" />Blocked</span><span className="font-mono font-bold">{blockedCount}</span></div>
          </div>
        </Card>
      </div>
      {/* Recent Decisions Log Table */}
      <Card className="p-0 overflow-hidden">
        <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[var(--emerald)]" />
            <h3 className="font-bold text-sm text-[var(--fg)]">Recent Gateway Execution Log</h3>
          </div>
          <span className="text-xs font-mono text-[var(--muted)]">
            {auditEvents.length} Total Audit Records
          </span>
        </div>

        {auditLoading ? (
          <div className="p-8 text-center text-xs text-[var(--muted)]">Loading audit records…</div>
        ) : auditError ? (
          <EmptyState
            title="Audit Records Unavailable"
            description="The backend audit API request failed. Check backend health and retry."
            actionLabel="Retry Audit Fetch"
            onAction={() => refetchEvents()}
          />
        ) : auditEvents.length === 0 ? (
          <EmptyState
            title="No Gateway Decisions Logged"
            description="Submit a signed action request via the Gateway Pipeline page to see decisions recorded in real time."
            actionLabel="Go to Gateway"
            onAction={() => router.push("/gateway")}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[var(--surface-2)] border-b border-[var(--border)] text-[var(--muted)] font-mono uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="py-3 px-4">Request ID</th>
                  <th className="py-3 px-4">Agent ID</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Decision</th>
                  <th className="py-3 px-4">Record Hash</th>
                  <th className="py-3 px-4 text-right pr-4">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)] font-sans">
                {auditEvents.slice().reverse().slice(0, 10).map((ev: AuditRecord, i: number) => (
                  <tr key={`${ev.request_id || 'REQ'}-${i}`} className="hover:bg-[var(--surface-2)]/40 transition-colors">
                    <td className="py-3 px-4 font-mono font-bold text-[var(--fg)]">
                      {ev.request_id}
                    </td>
                    <td className="py-3 px-4 font-mono text-[var(--muted)]">
                      {ev.agent_id}
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-[var(--emerald)]">
                      {ev.event_type}
                    </td>
                    <td className="py-3 px-4">
                      <DecisionPill decision={ev.decision} reason={ev.execution_result} />
                    </td>
                    <td className="py-3 px-4">
                      <HashText value={ev.record_hash} truncateLen={8} />
                    </td>
                    <td className="py-3 px-4 text-right pr-4 font-mono text-[var(--muted)] text-[11px]">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

    </div>
  );
}
