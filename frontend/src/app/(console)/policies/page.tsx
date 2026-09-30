"use me";
"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, PolicyRecord } from "@/lib/api";
import { Card, Button, Badge, Skeleton } from "@/components/ui/primitives";
import { EmptyState } from "@/components/domain/components";
import { 
  FileText, 
  RefreshCw, 
  RotateCcw, 
  CheckCircle2, 
  ShieldCheck, 
  Clock, 
  DollarSign, 
  ShieldAlert,
  Sliders,
  Plus
} from "lucide-react";

export default function PoliciesPage() {
  const queryClient = useQueryClient();
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyRecord | null>(null);
  const [rollbackVersion, setRollbackVersion] = useState("1.0");
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const { data: policies = [], isLoading, refetch } = useQuery({
    queryKey: ["policies"],
    queryFn: () => api.fetchPolicies(),
    refetchInterval: 3000,
  });

  const rollbackMutation = useMutation({
    mutationFn: ({ policyId, version }: { policyId: string; version: string }) =>
      api.rollbackPolicy(policyId, version),
    onSuccess: (data) => {
      setFeedback({
        type: "success",
        text: `Policy '${data.policy?.policy_id}' rolled back to version ${data.policy?.version}.`,
      });
      queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
    onError: (err: any) => {
      setFeedback({ type: "error", text: err.message || "Rollback failed." });
    }
  });

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[var(--fg)]">
              Declarative Policy Engine
            </h1>
            <Badge variant="outline" className="text-xs font-mono text-[var(--muted)]">
              {policies.length} Active Policy
            </Badge>
          </div>
          <p className="text-sm text-[var(--muted)] mt-1">
            Fine-grained access control, financial bounds, and versioned compliance rules (Stage 4 & 5).
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Action Feedback Banner */}
      {feedback && (
        <div
          className={`p-3.5 rounded-xl border flex items-center justify-between text-xs font-medium transition-all ${
            feedback.type === "success"
              ? "bg-emerald-950/30 border-emerald-500/30 text-emerald-400"
              : "bg-red-950/30 border-red-500/30 text-red-400"
          }`}
        >
          <span>{feedback.text}</span>
          <button
            onClick={() => setFeedback(null)}
            className="opacity-70 hover:opacity-100 font-bold ml-4"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Grid: Policy Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Side: Policies List */}
        <div className="lg:col-span-2 space-y-4">
          {isLoading ? (
            <div className="space-y-3">
              {[1, 2].map((n) => (
                <Skeleton key={n} className="h-56 w-full rounded-xl" />
              ))}
            </div>
          ) : policies.length === 0 ? (
            <EmptyState
              title="No Policies Configured"
              description="No policy rules registered in policy loader."
            />
          ) : (
            policies.map((policy) => (
              <Card
                key={policy.policy_id}
                className={`p-5 transition-all space-y-4 ${
                  selectedPolicy?.policy_id === policy.policy_id
                    ? "border-[var(--accent)]"
                    : ""
                }`}
                onClick={() => setSelectedPolicy(policy)}
              >
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[var(--border)]">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center text-[var(--accent)] shrink-0">
                      <FileText className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="font-bold font-mono text-[var(--fg)] text-base">
                        {policy.policy_id}
                      </h3>
                      <span className="text-xs text-[var(--muted)]">
                        Target Agent: <strong className="text-[var(--fg)] font-mono">{policy.agent_id}</strong>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)] text-[var(--accent)]">
                      v{policy.version}
                    </span>
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/40 text-emerald-400 border border-emerald-500/30">
                      ACTIVE
                    </span>
                  </div>
                </div>

                {/* Bounds Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-[var(--bg)] border border-[var(--border)] space-y-1">
                    <span className="text-[var(--muted)] text-[11px] block">Max Transaction Cap</span>
                    <div className="font-bold font-mono text-[var(--fg)] text-sm">
                      ${Number(policy.maximum_amount).toLocaleString()}
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-[var(--bg)] border border-[var(--border)] space-y-1">
                    <span className="text-[var(--muted)] text-[11px] block">Human Approval Threshold</span>
                    <div className="font-bold font-mono text-amber-400 text-sm">
                      ${Number(policy.human_approval_above).toLocaleString()}
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-[var(--bg)] border border-[var(--border)] space-y-1">
                    <span className="text-[var(--muted)] text-[11px] block">Allowed Working Hours</span>
                    <div className="font-semibold font-mono text-[var(--fg)] text-xs flex items-center gap-1 mt-0.5">
                      <Clock className="w-3.5 h-3.5 text-[var(--muted)]" />
                      {policy.working_hours?.start || "00:00"} - {policy.working_hours?.end || "23:59"}
                    </div>
                  </div>
                </div>

                {/* Allowed Actions Chips */}
                <div className="space-y-1.5">
                  <span className="text-xs text-[var(--muted)] block">Allowed Actions List:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {policy.allowed_actions.map((act) => (
                      <span
                        key={act}
                        className="font-mono text-xs px-2.5 py-1 rounded-md bg-[var(--surface-2)] border border-[var(--border)] text-[var(--fg)] font-medium"
                      >
                        {act}
                      </span>
                    ))}
                  </div>
                </div>
              </Card>
            ))
          )}
        </div>

        {/* Right Side: Version Rollback Drawer */}
        <div className="space-y-4">
          <Card className="p-5 space-y-4">
            <h3 className="text-base font-bold text-[var(--fg)] flex items-center gap-2">
              <RotateCcw className="w-4 h-4 text-[var(--accent)]" />
              Policy Rollback Control
            </h3>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              Instantly revert policy definitions to a previous version in policy loader & update Fabric chaincode status.
            </p>

            <div className="space-y-3 pt-2">
              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">
                  Target Policy ID
                </label>
                <input
                  type="text"
                  readOnly
                  value={selectedPolicy?.policy_id || policies[0]?.policy_id || "FIN-POLICY-001"}
                  className="w-full bg-[var(--bg)] border border-[var(--border)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--fg)] focus:outline-none"
                />
              </div>

              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">
                  Rollback Target Version
                </label>
                <select
                  value={rollbackVersion}
                  onChange={(e) => setRollbackVersion(e.target.value)}
                  className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--fg)] focus:outline-none focus:border-[var(--accent)]"
                >
                  <option value="1.0">v1.0 (Initial Setup)</option>
                  <option value="1.1">v1.1 (Previous Revision)</option>
                  <option value="2.0">v2.0 (Strict Financial Controls)</option>
                </select>
              </div>

              <Button
                variant="primary"
                className="w-full mt-2"
                onClick={() =>
                  rollbackMutation.mutate({
                    policyId: selectedPolicy?.policy_id || policies[0]?.policy_id || "FIN-POLICY-001",
                    version: rollbackVersion,
                  })
                }
                disabled={rollbackMutation.isPending}
              >
                <RotateCcw className="w-4 h-4 mr-2" />
                {rollbackMutation.isPending ? "Rolling Back..." : "Execute Policy Rollback"}
              </Button>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
