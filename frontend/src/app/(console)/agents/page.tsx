"use me";
"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, AgentRecord } from "@/lib/api";
import { Card, Button, Badge, Skeleton, Dialog } from "@/components/ui/primitives";
import { HashText, EmptyState } from "@/components/domain/components";
import { 
  Bot, 
  RefreshCw, 
  ShieldAlert, 
  ShieldCheck, 
  Key, 
  UserCheck, 
  UserX, 
  RotateCw,
  Fingerprint,
  Plus
} from "lucide-react";

export default function AgentsPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<AgentRecord | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const { data: agents = [], isLoading, refetch } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.fetchAgents(),
    refetchInterval: 3000,
  });

  const suspendMutation = useMutation({
    mutationFn: (agentId: string) => api.suspendAgent(agentId, "ADMIN_SUSPENSION"),
    onSuccess: (data) => {
      setActionMessage({ type: "success", text: data.message || "Agent suspended successfully." });
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (err: any) => {
      setActionMessage({ type: "error", text: err.message || "Failed to suspend agent." });
    }
  });

  const reactivateMutation = useMutation({
    mutationFn: (agentId: string) => api.reactivateAgent(agentId),
    onSuccess: (data) => {
      setActionMessage({ type: "success", text: data.message || "Agent reactivated successfully." });
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (err: any) => {
      setActionMessage({ type: "error", text: err.message || "Failed to reactivate agent." });
    }
  });

  const revokeMutation = useMutation({
    mutationFn: (agentId: string) => api.revokeAgent(agentId),
    onSuccess: (data) => {
      setActionMessage({ type: "success", text: data.message || "Agent certificate revoked." });
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (err: any) => {
      setActionMessage({ type: "error", text: err.message || "Failed to revoke agent." });
    }
  });

  const rotateKeyMutation = useMutation({
    mutationFn: (agentId: string) => api.rotateAgentKey(agentId),
    onSuccess: (data) => {
      setActionMessage({ type: "success", text: `RSA key rotated! New key version: ${data.new_key_version}` });
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (err: any) => {
      setActionMessage({ type: "error", text: err.message || "Failed to rotate key." });
    }
  });

  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case "ACTIVE":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/40 text-emerald-400 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            ACTIVE
          </span>
        );
      case "SUSPENDED":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/40 text-amber-400 border border-amber-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            SUSPENDED
          </span>
        );
      case "REVOKED":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950/40 text-red-400 border border-red-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span>
            REVOKED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-zinc-800 text-zinc-300 border border-zinc-700">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[var(--fg)]">
              Agent Registry & X.509 Identities
            </h1>
            <Badge variant="outline" className="text-xs font-mono text-[var(--muted)]">
              {agents.length} Registered
            </Badge>
          </div>
          <p className="text-sm text-[var(--muted)] mt-1">
            Manage autonomous AI agents, RSA key versions, X.509 certificates, and RBAC lifecycle.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Action Notification Banner */}
      {actionMessage && (
        <div
          className={`p-3.5 rounded-xl border flex items-center justify-between text-xs font-medium transition-all ${
            actionMessage.type === "success"
              ? "bg-emerald-950/30 border-emerald-500/30 text-emerald-400"
              : "bg-red-950/30 border-red-500/30 text-red-400"
          }`}
        >
          <span>{actionMessage.text}</span>
          <button
            onClick={() => setActionMessage(null)}
            className="opacity-70 hover:opacity-100 font-bold ml-4"
          >
            ✕
          </button>
        </div>
      )}

      {/* Agents Table */}
      <Card className="p-0 overflow-hidden">
        {isLoading ? (
          <div className="p-4 space-y-3">
            {[1, 2, 3].map((n) => (
              <Skeleton key={n} className="h-16 w-full rounded-lg" />
            ))}
          </div>
        ) : agents.length === 0 ? (
          <EmptyState
            title="No Registered Agents"
            description="The agent registry is currently empty."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[var(--surface-2)] border-b border-[var(--border)] text-[var(--muted)] font-mono uppercase tracking-wider">
                <tr>
                  <th className="p-3.5 pl-4">Agent ID / Name</th>
                  <th className="p-3.5">Owner / Org</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5 font-center">Key Ver</th>
                  <th className="p-3.5">X.509 Fingerprint</th>
                  <th className="p-3.5 text-right pr-4">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)] font-sans">
                {agents.map((agent) => (
                  <tr
                    key={agent.agent_id}
                    className="hover:bg-[var(--surface-2)]/40 transition-colors"
                  >
                    {/* ID & Name */}
                    <td className="p-3.5 pl-4">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center shrink-0 text-[var(--accent)]">
                          <Bot className="w-4 h-4" />
                        </div>
                        <div>
                          <span className="font-bold font-mono text-[var(--fg)] block">
                            {agent.agent_id}
                          </span>
                          <span className="text-[11px] text-[var(--muted)]">
                            {agent.agent_name || "Procurement Bot"}
                          </span>
                        </div>
                      </div>
                    </td>

                    {/* Owner & Org */}
                    <td className="p-3.5">
                      <div className="text-[var(--fg)] font-medium">
                        {agent.owner || "Finance Dept"}
                      </div>
                      <div className="text-[11px] text-[var(--muted)]">
                        {agent.organization || "FinanceOrg"} ({agent.role || "agent"})
                      </div>
                    </td>

                    {/* Status */}
                    <td className="p-3.5">{getStatusBadge(agent.status)}</td>

                    {/* Key Version */}
                    <td className="p-3.5">
                      <span className="font-mono px-2 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)] text-[var(--fg)] font-semibold">
                        v{agent.key_version ?? 1}
                      </span>
                    </td>

                    {/* Fingerprint */}
                    <td className="p-3.5">
                      {agent.certificate_fingerprint ? (
                        <div className="flex items-center gap-1.5">
                          <Fingerprint className="w-3.5 h-3.5 text-[var(--muted)] shrink-0" />
                          <HashText
                            value={agent.certificate_fingerprint}
                            truncateLen={14}
                          />
                        </div>
                      ) : (
                        <span className="text-[var(--subtle)]">RSA-PSS Self-Signed</span>
                      )}
                    </td>

                    {/* Action Controls */}
                    <td className="p-3.5 text-right pr-4">
                      <div className="flex items-center justify-end gap-1.5">
                        {/* Key Rotation */}
                        <Button
                          variant="ghost"
                          size="sm"
                          title="Rotate RSA-PSS Key Pair"
                          onClick={() => rotateKeyMutation.mutate(agent.agent_id)}
                          disabled={rotateKeyMutation.isPending || agent.status === "REVOKED"}
                        >
                          <RotateCw className="w-3.5 h-3.5 text-[var(--info)]" />
                        </Button>

                        {/* Suspend / Reactivate Toggle */}
                        {agent.status === "ACTIVE" ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            title="Suspend Agent"
                            onClick={() => suspendMutation.mutate(agent.agent_id)}
                            disabled={suspendMutation.isPending}
                          >
                            <UserX className="w-3.5 h-3.5 text-amber-400" />
                          </Button>
                        ) : agent.status === "SUSPENDED" ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            title="Reactivate Agent"
                            onClick={() => reactivateMutation.mutate(agent.agent_id)}
                            disabled={reactivateMutation.isPending}
                          >
                            <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
                          </Button>
                        ) : null}

                        {/* Revoke */}
                        {agent.status !== "REVOKED" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            title="Revoke Certificate Permanently"
                            onClick={() => {
                              if (confirm(`Are you sure you want to permanently revoke certificate for ${agent.agent_id}?`)) {
                                revokeMutation.mutate(agent.agent_id);
                              }
                            }}
                            disabled={revokeMutation.isPending}
                          >
                            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                          </Button>
                        )}
                      </div>
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
