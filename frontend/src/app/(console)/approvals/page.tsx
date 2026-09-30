"use me";
"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, Button, Badge, Skeleton } from "@/components/ui/primitives";
import { EmptyState } from "@/components/domain/components";
import { 
  UserCheck, 
  UserX, 
  RefreshCw, 
  Clock, 
  AlertTriangle, 
  DollarSign,
  FileCode
} from "lucide-react";

export default function ApprovalsPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [rejectingTicket, setRejectingTicket] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const { data: pendingTickets = [], isLoading, refetch } = useQuery({
    queryKey: ["pendingApprovals"],
    queryFn: () => api.fetchPendingApprovals(),
    refetchInterval: 3000,
  });

  const approveMutation = useMutation({
    mutationFn: (approvalId: string) => api.approveTicket(approvalId),
    onSuccess: (data) => {
      setFeedback({ type: "success", text: `Ticket ${(data.approval_id as string) || "approved"} resumed and executed on chain.` });
      queryClient.invalidateQueries({ queryKey: ["pendingApprovals"] });
      queryClient.invalidateQueries({ queryKey: ["auditChain"] });
    },
    onError: (err: Error) => {
      setFeedback({ type: "error", text: err.message || "Failed to approve ticket." });
    }
  });

  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.rejectTicket(id, reason),
    onSuccess: () => {
      setFeedback({ type: "success", text: "Ticket rejected and recorded in audit log." });
      setRejectingTicket(null);
      setRejectReason("");
      queryClient.invalidateQueries({ queryKey: ["pendingApprovals"] });
      queryClient.invalidateQueries({ queryKey: ["auditChain"] });
    },
    onError: (err: Error) => {
      setFeedback({ type: "error", text: err.message || "Failed to reject ticket." });
    }
  });

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[var(--fg)]">
              Human-in-the-Loop Approvals Queue
            </h1>
            <Badge
              variant="outline"
              className={`text-xs font-mono ${
                pendingTickets.length > 0
                  ? "bg-amber-950/40 border-amber-500/40 text-amber-400"
                  : "text-[var(--muted)]"
              }`}
            >
              {pendingTickets.length} Pending Ticket{pendingTickets.length !== 1 ? "s" : ""}
            </Badge>
          </div>
          <p className="text-sm text-[var(--muted)] mt-1">
            Gated high-risk agent transactions awaiting human supervisor evaluation (Stage 6).
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh Queue
          </Button>
        </div>
      </div>

      {/* Action Notification Banner */}
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

      {/* Main Approvals List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="space-y-3">
            {[1, 2].map((n) => (
              <Skeleton key={n} className="h-40 w-full rounded-xl" />
            ))}
          </div>
        ) : pendingTickets.length === 0 ? (
          <EmptyState
            title="No Pending Approvals"
            description="All agent requests are within policy thresholds. High-value transactions requiring human approval will appear here."
            actionLabel="Submit High-Value Request"
            onAction={() => router.push("/gateway")}
          />
        ) : (
          pendingTickets.map((ticket) => {
            const amount = ticket.parameters?.total_amount || ticket.parameters?.amount;
            return (
              <Card
                key={ticket.approval_id}
                className="p-5 border border-amber-500/30 bg-amber-950/10 transition-all hover:border-amber-500/50 space-y-4"
              >
                {/* Header Strip */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[var(--border)]">
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                      TICKET #{ticket.approval_id}
                    </span>
                    <span className="text-xs font-semibold text-[var(--fg)] font-mono">
                      {ticket.action}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-[var(--muted)] font-mono">
                    <Clock className="w-3.5 h-3.5 text-amber-400" />
                    <span>{ticket.created_at || "Just now"}</span>
                  </div>
                </div>

                {/* Ticket Details Body */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                  <div>
                    <span className="text-[var(--muted)] block mb-1">Request ID & Agent</span>
                    <div className="font-mono text-[var(--fg)] font-medium">
                      {ticket.request_id}
                    </div>
                    <div className="text-[11px] text-[var(--muted)] font-mono mt-0.5">
                      Agent: {ticket.agent_id}
                    </div>
                  </div>

                  <div>
                    <span className="text-[var(--muted)] block mb-1">Transaction Value</span>
                    <div className="text-base font-bold font-mono text-[var(--fg)] flex items-center gap-1">
                      {amount !== undefined ? (
                        <>
                          <DollarSign className="w-4 h-4 text-emerald-400 -mr-1" />
                          {Number(amount).toLocaleString("en-US", { minimumFractionDigits: 2 })}
                        </>
                      ) : (
                        <span className="text-xs font-normal text-[var(--muted)]">N/A</span>
                      )}
                    </div>
                    <div className="text-[11px] text-[var(--muted)] mt-0.5">
                      Target: {ticket.resource || "*"}
                    </div>
                  </div>

                  <div>
                    <span className="text-[var(--muted)] block mb-1">Hold Reason</span>
                    <div className="p-2 rounded bg-[var(--surface-2)] border border-[var(--border)] text-amber-300 text-[11px] font-mono leading-relaxed">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 inline mr-1 -mt-0.5" />
                      {ticket.reason || "Exceeds automated policy threshold ($10,000)"}
                    </div>
                  </div>
                </div>

                {/* Parameters JSON Drawer */}
                {ticket.parameters && Object.keys(ticket.parameters).length > 0 && (
                  <div className="pt-2 border-t border-[var(--border)]/50">
                    <span className="text-[11px] text-[var(--muted)] flex items-center gap-1 mb-1 font-mono">
                      <FileCode className="w-3 h-3 text-[var(--muted)]" />
                      Payload Parameters
                    </span>
                    <pre className="p-2.5 rounded bg-[var(--bg)] border border-[var(--border)] font-mono text-[11px] text-[var(--fg)] overflow-x-auto">
                      {JSON.stringify(ticket.parameters, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Reject Input Box (if active) */}
                {rejectingTicket === ticket.approval_id && (
                  <div className="p-3 rounded-lg bg-red-950/20 border border-red-500/30 space-y-2">
                    <span className="text-xs text-red-300 font-medium block">
                      Rejection Reason (Recorded in Immutable Audit Log)
                    </span>
                    <input
                      type="text"
                      placeholder="e.g. Budget allocation exceeded for supplier..."
                      value={rejectReason}
                      onChange={(e) => setRejectReason(e.target.value)}
                      className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded px-3 py-1.5 text-xs text-[var(--fg)] focus:outline-none focus:border-red-400"
                    />
                    <div className="flex justify-end gap-2 pt-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setRejectingTicket(null);
                          setRejectReason("");
                        }}
                      >
                        Cancel
                      </Button>
                      <Button
                        variant="secondary"
                        size="sm"
                        className="bg-red-600 hover:bg-red-700 text-white"
                        onClick={() =>
                          rejectMutation.mutate({
                            id: ticket.approval_id,
                            reason: rejectReason || "REJECTED_BY_HUMAN_APPROVER",
                          })
                        }
                        disabled={rejectMutation.isPending}
                      >
                        Confirm Rejection
                      </Button>
                    </div>
                  </div>
                )}

                {/* Card Actions Footer */}
                {rejectingTicket !== ticket.approval_id && (
                  <div className="flex items-center justify-end gap-3 pt-3 border-t border-[var(--border)]">
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-red-400 hover:bg-red-950/30 hover:border-red-500/40"
                      onClick={() => setRejectingTicket(ticket.approval_id)}
                      disabled={approveMutation.isPending || rejectMutation.isPending}
                    >
                      <UserX className="w-4 h-4 mr-1.5" />
                      Reject Transaction
                    </Button>

                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => approveMutation.mutate(ticket.approval_id)}
                      disabled={approveMutation.isPending || rejectMutation.isPending}
                    >
                      <UserCheck className="w-4 h-4 mr-1.5" />
                      {approveMutation.isPending ? "Approving..." : "Approve & Execute"}
                    </Button>
                  </div>
                )}
              </Card>
            );
          })
        )}
      </div>
    </div>
  );
}
