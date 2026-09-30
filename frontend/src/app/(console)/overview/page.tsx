"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { api, AuditRecord } from "@/lib/api";
import { StatCard, DecisionPill, EmptyState } from "@/components/domain/components";
import { Card, Button, Skeleton } from "@/components/ui/primitives";
import { Activity, ShieldCheck, ShieldAlert, Clock, Database, RefreshCw } from "lucide-react";
import Link from "next/link";

export default function OverviewPage() {
  const { data: auditEvents = [], isLoading: eventsLoading, refetch: refetchEvents } = useQuery({
    queryKey: ["auditEvents"],
    queryFn: () => api.fetchAuditChain(),
  });

  const { data: chainVerify } = useQuery({
    queryKey: ["chainVerify"],
    queryFn: () => api.verifyChain(),
  });

  const { data: pendingApprovals = [] } = useQuery({
    queryKey: ["pendingApprovals"],
    queryFn: () => api.fetchPendingApprovals(),
  });

  // Calculate real metrics from audit data
  const allowedCount = auditEvents.filter((e: AuditRecord) =>
    (e.decision || "").toUpperCase().includes("ALLOW")
  ).length;

  const blockedCount = auditEvents.filter((e: AuditRecord) =>
    (e.decision || "").toUpperCase().includes("BLOCK")
  ).length;

  const heldCount = pendingApprovals.length;

  return (
    <div className="space-y-6">
      
      {/* Top Banner Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <h1 className="text-xl font-bold text-[var(--fg)] tracking-tight">Security Operations Overview</h1>
          <p className="text-xs text-[var(--muted)] mt-1">
            Real-time status, cryptographic decision distribution, and local ledger verification.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetchEvents()}>
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </Button>
          <Link href="/gateway">
            <Button variant="emerald" size="sm">
              Submit Action Request
            </Button>
          </Link>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {eventsLoading ? (
          Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28 w-full" />)
        ) : (
          <>
            <StatCard
              title="AUTHORIZED ACTIONS"
              value={allowedCount}
              subtext="Within policy limits"
              icon={ShieldCheck}
              variant="emerald"
            />
            <StatCard
              title="HELD FOR APPROVAL"
              value={heldCount}
              subtext="Exceeds threshold limits"
              icon={Clock}
              variant="held"
            />
            <StatCard
              title="BLOCKED VIOLATIONS"
              value={blockedCount}
              subtext="Security boundary enforced"
              icon={ShieldAlert}
              variant="blocked"
            />
            <StatCard
              title="CHAIN INTEGRITY"
              value={chainVerify?.valid ? "VERIFIED" : "TAMPERED"}
              subtext={chainVerify?.status || "Audit log integrity check"}
              icon={Database}
              variant={chainVerify?.valid ? "emerald" : "blocked"}
            />
          </>
        )}
      </div>

      {/* Recent Decisions Table */}
      <Card>
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[var(--emerald)]" />
            <h3 className="font-semibold text-sm">Recent Gateway Decisions</h3>
          </div>
          <span className="text-xs font-mono text-[var(--muted)]">
            Total Logged: {auditEvents.length} events
          </span>
        </div>

        {eventsLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : auditEvents.length === 0 ? (
          <EmptyState
            title="No Gateway Decisions Logged"
            description="Submit a signed action request via the Gateway Pipeline page to see decisions recorded in real-time."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--border)] text-[var(--muted)] font-mono uppercase text-[10px]">
                  <th className="py-2.5 px-3">Request ID</th>
                  <th className="py-2.5 px-3">Agent ID</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Decision</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)] font-mono">
                {auditEvents.slice(0, 10).map((ev: AuditRecord, i: number) => (
                  <tr key={ev.request_id || i} className="hover:bg-white/5 transition-colors">
                    <td className="py-2.5 px-3 text-[var(--fg)] font-medium">
                      {ev.request_id || `REQ-${i}`}
                    </td>
                    <td className="py-2.5 px-3 text-[var(--muted)]">
                      {ev.agent_id || "FINANCE-AGENT-001"}
                    </td>
                    <td className="py-2.5 px-3 text-[var(--muted)]">
                      {ev.event_type || "CREATE_PURCHASE_ORDER"}
                    </td>
                    <td className="py-2.5 px-3">
                      <DecisionPill decision={ev.decision} reason={ev.execution_result} />
                    </td>
                    <td className="py-2.5 px-3 text-[var(--subtle)]">
                      {ev.timestamp || new Date().toISOString()}
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
