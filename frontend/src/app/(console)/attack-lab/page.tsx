"use client";

import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, Button, Badge, Skeleton } from "@/components/ui/primitives";
import { EmptyState } from "@/components/domain/components";
import { Play, CheckCircle2, XCircle, Flame } from "lucide-react";
import { AttackScenario } from "@/lib/api";

interface MatrixResultData {
  summary: {
    total: number;
    passed: number;
    failed: number;
    pass_rate: string;
  };
  details: AttackScenario[];
}

export default function AttackLabPage() {
  const [matrixData, setMatrixData] = useState<MatrixResultData | null>(null);

  const { isFetching } = useQuery({
    queryKey: ["attackMatrix"],
    queryFn: async () => {
      const data = await api.runAttackMatrix();
      setMatrixData(data);
      return data;
    },
    enabled: false,
    refetchOnWindowFocus: false,
  });

  const runMutation = useMutation({
    mutationFn: () => api.runAttackMatrix(),
    onSuccess: (data) => {
      setMatrixData(data);
    },
  });

  const isExecuting = runMutation.isPending || isFetching;
  const hasRun = matrixData !== null;
  const scenariosList = matrixData?.details || [];
  const summary = matrixData?.summary;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[var(--fg)]">
              Adversarial Attack Laboratory
            </h1>
            <Badge variant="outline" className="text-xs font-mono text-[var(--muted)]">
              20 Threat Scenarios
            </Badge>
          </div>
          <p className="text-sm text-[var(--muted)] mt-1">
            Automated security test suite validating AgentTrust zero-trust defenses against forged signatures, replays, and ledger tampering.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="primary"
            size="sm"
            onClick={() => runMutation.mutate()}
            disabled={isExecuting}
          >
            <Play className="w-4 h-4 mr-2" />
            {isExecuting ? "Running 20 Attack Vectors..." : "Run Full 20-Scenario Matrix"}
          </Button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <Card className="p-4 space-y-1">
          <span className="text-xs text-[var(--muted)]">Total Threat Scenarios</span>
          <div className="text-2xl font-bold font-mono text-[var(--fg)]">
            {hasRun ? summary?.total : 20}
          </div>
          <span className="text-[11px] text-[var(--muted)]">Automated Security Suite</span>
        </Card>

        <Card className={`p-4 space-y-1 ${hasRun && (summary?.passed ?? 0) > 0 ? "bg-emerald-950/20 border-emerald-500/30" : ""}`}>
          <span className={`text-xs font-medium ${hasRun ? "text-emerald-400" : "text-[var(--muted)]"}`}>
            Successfully Mitigated
          </span>
          <div className={`text-2xl font-bold font-mono ${hasRun ? "text-emerald-400" : "text-[var(--fg)]"}`}>
            {hasRun ? `${summary?.passed} / ${summary?.total}` : "— / 20"}
          </div>
          <span className="text-[11px] text-[var(--muted)]">
            {hasRun
              ? summary?.failed === 0
                ? "100% Defense Neutralization"
                : `${summary?.passed} Scenarios Neutralized`
              : "Awaiting Execution"}
          </span>
        </Card>

        <Card className={`p-4 space-y-1 ${hasRun && (summary?.failed ?? 0) > 0 ? "bg-red-950/20 border-red-500/30" : ""}`}>
          <span className={`text-xs font-medium ${hasRun && (summary?.failed ?? 0) > 0 ? "text-red-400" : "text-[var(--muted)]"}`}>
            Bypassed / Failed
          </span>
          <div className={`text-2xl font-bold font-mono ${hasRun && (summary?.failed ?? 0) > 0 ? "text-red-400" : "text-[var(--fg)]"}`}>
            {hasRun ? summary?.failed : "—"}
          </div>
          <span className="text-[11px] text-[var(--muted)]">
            {hasRun
              ? summary?.failed === 0
                ? "Zero Bypass Tolerated"
                : `${summary?.failed} Vulnerabilities Detected`
              : "Pending Test Run"}
          </span>
        </Card>

        <Card className="p-4 space-y-1">
          <span className="text-xs text-[var(--muted)]">Security Score Rate</span>
          <div className={`text-2xl font-bold font-mono ${hasRun ? "text-[var(--accent)]" : "text-[var(--muted)]"}`}>
            {hasRun ? summary?.pass_rate : "Awaiting Run"}
          </div>
          <span className="text-[11px] text-[var(--muted)]">
            {hasRun ? "Zero-Trust Pipeline Rating" : "Run Matrix to Profile"}
          </span>
        </Card>
      </div>

      {/* Scenarios Table */}
      <Card className="p-0 overflow-hidden">
        <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-[var(--accent)]" />
            <h3 className="font-bold text-sm text-[var(--fg)]">
              20-Stage Attack Vector Execution Matrix
            </h3>
          </div>
          <span className="text-xs text-[var(--muted)] font-mono">
            {hasRun ? `${scenariosList.length} Executed` : "0 Executed"}
          </span>
        </div>

        {isExecuting ? (
          <div className="p-4 space-y-2">
            {[1, 2, 3, 4, 5, 6].map((n) => (
              <Skeleton key={n} className="h-12 w-full rounded-lg" />
            ))}
          </div>
        ) : scenariosList.length === 0 ? (
          <EmptyState
            title="Click Run to Execute Attack Lab"
            description="Run the 20 attack vectors to evaluate forged signature rejection, replay protection, and evidence verification against genuine backend endpoints."
            actionLabel="Run Attack Matrix"
            onAction={() => runMutation.mutate()}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[var(--surface-2)] border-b border-[var(--border)] text-[var(--muted)] font-mono uppercase tracking-wider">
                <tr>
                  <th className="p-3.5 pl-4">Scenario #</th>
                  <th className="p-3.5">Threat Vector & Description</th>
                  <th className="p-3.5">Expected Defense</th>
                  <th className="p-3.5 text-right pr-4">Result Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)] font-sans">
                {scenariosList.map((item: AttackScenario) => (
                  <tr
                    key={item.scenario_id}
                    className="hover:bg-[var(--surface-2)]/40 transition-colors"
                  >
                    <td className="p-3.5 pl-4 font-mono font-bold text-[var(--accent)]">
                      #{String(item.scenario_id).padStart(2, "0")}
                    </td>

                    <td className="p-3.5">
                      <div className="font-medium text-[var(--fg)]">
                        {item.title}
                      </div>
                    </td>

                    <td className="p-3.5">
                      <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-[var(--surface-2)] text-[var(--muted)] border border-[var(--border)]">
                        {item.expected || "BLOCKED"}
                      </span>
                    </td>

                    <td className="p-3.5 text-right pr-4">
                      {item.status.includes("PASSED") ? (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/40 text-emerald-400 border border-emerald-500/30">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          PASSED (Mitigated)
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950/40 text-red-400 border border-red-500/30">
                          <XCircle className="w-3.5 h-3.5 text-red-400" />
                          FAILED ({item.error || item.actual || "Bypassed"})
                        </span>
                      )}
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
