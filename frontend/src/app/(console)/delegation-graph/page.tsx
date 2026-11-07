"use client";

import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Network,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Lock,
  ArrowRight,
  RefreshCw,
  Plus,
  Trash2,
  Flame,
  Zap,
  Play,
  RotateCcw,
  Clock,
  Layers,
  Coins,
  FileText,
  Activity,
  User,
} from "lucide-react";
import { Card, Button } from "@/components/ui/primitives";
import {
  api,
  DelegationNode,
  DelegationEdge,
  DelegationGraphResponse,
} from "@/lib/api";

type TabMode = "TREE" | "TOKENS" | "ATTACK_LAB" | "AUDIT";

export default function DelegationGraphPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabMode>("TREE");
  const [selectedAgentId, setSelectedAgentId] = useState<string>("FIN-SUPERVISOR-001");
  const [issueModalOpen, setIssueModalOpen] = useState(false);
  const [simulationResult, setSimulationResult] = useState<any | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Form State for Issue Delegation
  const [formIssuer, setFormIssuer] = useState("FIN-SUPERVISOR-001");
  const [formDelegate, setFormDelegate] = useState("VENDOR-VERIF-003");
  const [formActions, setFormActions] = useState<string[]>(["CREATE_PURCHASE_ORDER"]);
  const [formBudget, setFormBudget] = useState(50000);
  const [formReason, setFormReason] = useState("VENDOR_ONBOARDING_ALLOCATION");

  // Fetch complete graph
  const { data: graphData, isLoading, isError, refetch } = useQuery<DelegationGraphResponse>({
    queryKey: ["delegationGraph"],
    queryFn: () => api.fetchDelegationGraph(),
    refetchInterval: 3000,
  });

  // Execute Delegated Action on Spot Mutation
  const executeOnSpotMutation = useMutation({
    mutationFn: (data: {
      agent_id: string;
      action: string;
      amount: number;
      resource?: string;
      token_id?: string;
    }) => api.executeDelegatedActionOnSpot(data),
    onSuccess: (data: any) => {
      const oc = data.outcome || {};
      const del = oc.delegation_context || {};
      const ueba = oc.behavioral_intelligence || {};
      setActionMessage({
        type: "success",
        text: `⚡ Action Executed On Spot! Decision: ${oc.decision} (${oc.reason || "PASSED"}). Budget consumed: ₹${(oc.parameters?.amount || 0).toLocaleString()} • Remaining: ₹${(del.remaining_budget ?? 0).toLocaleString()} • UEBA Anomaly Score: ${ueba.anomaly_score ?? "Normal"}/100`,
      });
      queryClient.invalidateQueries({ queryKey: ["delegationGraph"] });
    },
    onError: (err: Error) => {
      setActionMessage({ type: "error", text: err.message || "Failed to execute delegated action on spot." });
    },
  });

  // Issue Delegation Mutation
  const issueMutation = useMutation({
    mutationFn: (data: {
      issuer_agent_id: string;
      delegate_agent_id: string;
      allowed_actions: string[];
      delegated_budget: number;
      reason: string;
    }) => api.issueGraphDelegation(data),
    onSuccess: () => {
      setActionMessage({ type: "success", text: "Capability delegation token successfully issued and signed!" });
      setIssueModalOpen(false);
      queryClient.invalidateQueries({ queryKey: ["delegationGraph"] });
    },
    onError: (err: Error) => {
      setActionMessage({ type: "error", text: err.message || "Failed to issue delegation." });
    },
  });

  // Revoke Delegation Mutation
  const revokeMutation = useMutation({
    mutationFn: (tokenId: string) => api.revokeGraphDelegation(tokenId, "MANUAL_CONSOLE_REVOCATION"),
    onSuccess: (data: any) => {
      setActionMessage({
        type: "success",
        text: `Cascading revocation executed! Total tokens invalidated in subtree: ${data.total_revoked || 1}`,
      });
      queryClient.invalidateQueries({ queryKey: ["delegationGraph"] });
    },
    onError: (err: Error) => {
      setActionMessage({ type: "error", text: err.message || "Failed to revoke delegation." });
    },
  });

  // Reset Graph Mutation
  const resetMutation = useMutation({
    mutationFn: () => api.resetGraphDelegation(),
    onSuccess: () => {
      setActionMessage({ type: "success", text: "Delegation graph reset to canonical 4-tier enterprise baseline." });
      setSelectedAgentId("FIN-SUPERVISOR-001");
      setSimulationResult(null);
      queryClient.invalidateQueries({ queryKey: ["delegationGraph"] });
    },
    onError: (err: Error) => {
      setActionMessage({ type: "error", text: err.message || "Failed to reset graph." });
    },
  });

  // Attack Simulation Mutation
  const attackMutation = useMutation({
    mutationFn: (scenario: string) => api.simulateGraphAttack(scenario),
    onSuccess: (data: any) => {
      setSimulationResult(data.simulation || data);
      queryClient.invalidateQueries({ queryKey: ["delegationGraph"] });
    },
    onError: (err: Error) => {
      setActionMessage({ type: "error", text: err.message || "Simulation failed." });
    },
  });

  const nodes = useMemo(() => graphData?.nodes || [], [graphData]);
  const edges = useMemo(() => graphData?.edges || [], [graphData]);
  const summary = graphData?.summary;
  const auditTrail = graphData?.audit_trail || [];

  const selectedNode = useMemo(
    () => nodes.find((n) => n.agent_id === selectedAgentId) || nodes[0] || null,
    [nodes, selectedAgentId]
  );

  const selectedIssuerNode = useMemo(
    () => nodes.find((n) => n.agent_id === formIssuer) || null,
    [nodes, formIssuer]
  );

  // Group nodes by depth for the Visual Tree Columns
  const rootNodes = useMemo(() => nodes.filter((n) => n.depth === 0), [nodes]);
  const depth1Nodes = useMemo(() => nodes.filter((n) => n.depth === 1), [nodes]);
  const depth2PlusNodes = useMemo(() => nodes.filter((n) => n.depth >= 2), [nodes]);

  const handleActionToggle = (act: string) => {
    setFormActions((prev) =>
      prev.includes(act) ? prev.filter((a) => a !== act) : [...prev, act]
    );
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Toast Banner */}
      {actionMessage && (
        <div
          className={`p-3 rounded-lg border flex items-center justify-between text-xs font-mono transition-all animate-in fade-in slide-in-from-top-2 ${
            actionMessage.type === "success"
              ? "bg-emerald-950/40 text-emerald-300 border-emerald-500/30"
              : "bg-rose-950/40 text-rose-300 border-rose-500/30"
          }`}
        >
          <div className="flex items-center gap-2">
            {actionMessage.type === "success" ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            )}
            <span>{actionMessage.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setActionMessage(null)}
            className="hover:opacity-75 text-sm font-bold ml-4"
          >
            &times;
          </button>
        </div>
      )}

      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-[var(--emerald)]">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-[var(--fg)]">
                  Intelligent Multi-Agent Authority Graph
                </h1>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Transitive Attenuation
                </span>
              </div>
              <p className="text-xs text-[var(--muted)] mt-0.5">
                Hierarchical capability attenuation, non-expanding privilege lineage, cross-agent budget tracking, and blast radius governance.
              </p>
            </div>
          </div>
        </div>

        {/* Global Action Triggers */}
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            type="button"
            variant="secondary"
            onClick={() => resetMutation.mutate()}
            disabled={resetMutation.isPending}
            className="h-8 text-xs font-mono gap-1.5"
            title="Reset to canonical 4-tier enterprise scenario"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${resetMutation.isPending ? "animate-spin" : ""}`} />
            <span>Reset Canonical Baseline</span>
          </Button>

          <Button
            type="button"
            variant="emerald"
            onClick={() => setIssueModalOpen(true)}
            className="h-8 text-xs font-mono font-bold gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Issue Delegation</span>
          </Button>

          <Button
            type="button"
            variant="secondary"
            onClick={() => refetch()}
            className="h-8 text-xs font-mono gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </Button>
        </div>
      </div>

      {/* Top Telemetry KPI Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="p-3">
          <div className="text-[10px] font-mono uppercase text-[var(--muted)] flex items-center justify-between">
            <span>Graph Nodes</span>
            <User className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-xl font-bold font-mono text-[var(--fg)] mt-1">
            {summary?.total_agents || nodes.length}
          </div>
          <div className="text-[10px] text-[var(--muted)] mt-0.5">Participating AI Agents</div>
        </Card>

        <Card className="p-3">
          <div className="text-[10px] font-mono uppercase text-[var(--muted)] flex items-center justify-between">
            <span>Active Delegations</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
            {summary?.active_delegations ?? edges.filter((e) => e.status === "ACTIVE").length}
          </div>
          <div className="text-[10px] text-[var(--muted)] mt-0.5">
            {summary?.revoked_delegations || 0} Cascaded Revocations
          </div>
        </Card>

        <Card className="p-3">
          <div className="text-[10px] font-mono uppercase text-[var(--muted)] flex items-center justify-between">
            <span>Max Hierarchy Depth</span>
            <Layers className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-xl font-bold font-mono text-[var(--fg)] mt-1">
            L{summary?.max_depth_observed ?? 2} <span className="text-xs text-[var(--muted)]">/ L{summary?.max_depth_limit ?? 4}</span>
          </div>
          <div className="text-[10px] text-[var(--muted)] mt-0.5">Strict Depth Cap Enforced</div>
        </Card>

        <Card className="p-3">
          <div className="text-[10px] font-mono uppercase text-[var(--muted)] flex items-center justify-between">
            <span>Delegated Budget</span>
            <Coins className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400 mt-1">
            ₹{((summary?.aggregate_delegated_budget || 250000) / 1000).toFixed(0)}k
          </div>
          <div className="text-[10px] text-[var(--muted)] mt-0.5">
            ₹{((summary?.aggregate_spent_budget || 45000) / 1000).toFixed(0)}k Consumed
          </div>
        </Card>

        <Card className="p-3 col-span-2 md:col-span-1 border-emerald-500/30 bg-emerald-950/10">
          <div className="text-[10px] font-mono uppercase text-emerald-400 flex items-center justify-between">
            <span>Risk Reduction</span>
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
            {summary?.risk_reduction_percentage || 44}%
          </div>
          <div className="text-[10px] text-emerald-500/80 mt-0.5">By Attenuation Invariant</div>
        </Card>
      </div>

      {/* Navigation View Tabs */}
      <div className="flex items-center gap-2 border-b border-[var(--border)] pb-2">
        <button
          type="button"
          onClick={() => setActiveTab("TREE")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
            activeTab === "TREE"
              ? "bg-[var(--surface-2)] text-[var(--emerald)] border border-[var(--border)]"
              : "text-[var(--muted)] hover:text-[var(--fg)]"
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Authority Tree & Blast Radius</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("TOKENS")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
            activeTab === "TOKENS"
              ? "bg-[var(--surface-2)] text-[var(--emerald)] border border-[var(--border)]"
              : "text-[var(--muted)] hover:text-[var(--fg)]"
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Delegation Tokens ({edges.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("ATTACK_LAB")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
            activeTab === "ATTACK_LAB"
              ? "bg-[var(--surface-2)] text-[var(--emerald)] border border-[var(--border)]"
              : "text-[var(--muted)] hover:text-[var(--fg)]"
          }`}
        >
          <Flame className="w-3.5 h-3.5 text-rose-400" />
          <span>Security Invariant Lab (5 Attacks)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("AUDIT")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
            activeTab === "AUDIT"
              ? "bg-[var(--surface-2)] text-[var(--emerald)] border border-[var(--border)]"
              : "text-[var(--muted)] hover:text-[var(--fg)]"
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-blue-400" />
          <span>Cryptographic Audit Trail</span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: VISUAL AUTHORITY TREE & BLAST RADIUS (KeyRunner Design Reference) */}
      {/* ========================================================================= */}
      {activeTab === "TREE" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left / Center: Visual Multi-Tier Graph (8 Cols) */}
          <div className="lg:col-span-8 space-y-4">
            <Card className="p-4">
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
                <div>
                  <h3 className="font-semibold text-sm text-[var(--fg)] flex items-center gap-2">
                    <span>Multi-Agent Capability Lineage</span>
                    <span className="text-[10px] font-mono text-[var(--muted)] px-2 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)]">
                      Non-Expansion Verified
                    </span>
                  </h3>
                  <p className="text-[11px] text-[var(--muted)] mt-0.5">
                    Click any node to inspect real-time blast radius, depth attenuation, and cross-agent budget.
                  </p>
                </div>
                <div className="flex items-center gap-3 text-[10px] font-mono text-[var(--muted)]">
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" /> ACTIVE
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-purple-400" /> ATTENUATED
                  </span>
                </div>
              </div>

              {/* 3-Column Visual Flow: Level 0 -> Level 1 -> Level 2 */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                {/* Column 1: Root Authority (Level 0) */}
                <div className="space-y-3">
                  <div className="text-[10px] uppercase font-bold tracking-wider text-[var(--muted)] border-b border-[var(--border)] pb-1 flex items-center justify-between">
                    <span>L0: Supervisor</span>
                    <span className="text-emerald-400">Root</span>
                  </div>

                  {rootNodes.map((node) => {
                    const isSelected = selectedNode?.agent_id === node.agent_id;
                    return (
                      <div
                        key={node.agent_id}
                        onClick={() => setSelectedAgentId(node.agent_id)}
                        className={`p-3 rounded-lg border cursor-pointer transition-all ${
                          isSelected
                            ? "bg-[var(--surface-2)] border-emerald-500/60 shadow-lg shadow-emerald-950/20 ring-1 ring-emerald-500/30"
                            : "bg-[var(--surface)] border-[var(--border)] hover:border-[var(--border-strong)]"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[var(--fg)] truncate">{node.agent_id}</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            PROD
                          </span>
                        </div>
                        <div className="text-[10px] text-[var(--muted)] mt-0.5 truncate">{node.agent_name}</div>
                        <div className="mt-2 text-[10px] text-emerald-400 font-bold">
                          Budget: ₹{node.base_budget.toLocaleString()}
                        </div>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {node.effective_actions.map((act) => (
                            <span key={act} className="text-[8px] px-1 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)] text-[var(--muted)]">
                              {act.replace("CREATE_", "").replace("TRANSFER_", "TRX_")}
                            </span>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Column 2: Direct Delegates (Level 1) */}
                <div className="space-y-3">
                  <div className="text-[10px] uppercase font-bold tracking-wider text-[var(--muted)] border-b border-[var(--border)] pb-1 flex items-center justify-between">
                    <span>L1: Execution & Verif</span>
                    <span className="text-purple-400">Attenuated</span>
                  </div>

                  {depth1Nodes.map((node) => {
                    const isSelected = selectedNode?.agent_id === node.agent_id;
                    return (
                      <div
                        key={node.agent_id}
                        onClick={() => setSelectedAgentId(node.agent_id)}
                        className={`p-3 rounded-lg border cursor-pointer transition-all ${
                          isSelected
                            ? "bg-[var(--surface-2)] border-purple-500/60 shadow-lg shadow-purple-950/20 ring-1 ring-purple-500/30"
                            : "bg-[var(--surface)] border-[var(--border)] hover:border-[var(--border-strong)]"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[var(--fg)] truncate">{node.agent_id}</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                            Depth 1
                          </span>
                        </div>
                        <div className="text-[10px] text-[var(--muted)] mt-0.5 truncate">{node.agent_name}</div>
                        <div className="mt-2 text-[10px] text-purple-300 font-bold">
                          Budget: ₹{node.base_budget.toLocaleString()}
                        </div>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {node.effective_actions.map((act) => (
                            <span key={act} className="text-[8px] px-1 py-0.5 rounded bg-purple-950/20 border border-purple-500/30 text-purple-300">
                              {act.replace("CREATE_", "").replace("TRANSFER_", "TRX_")}
                            </span>
                          ))}
                        </div>
                        <div className="mt-2 text-[9px] text-[var(--subtle)] flex items-center gap-1">
                          <ArrowRight className="w-2.5 h-2.5 text-purple-400" />
                          <span>From {node.parent_agent_id}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Column 3: Sub-Delegates (Level 2+) */}
                <div className="space-y-3">
                  <div className="text-[10px] uppercase font-bold tracking-wider text-[var(--muted)] border-b border-[var(--border)] pb-1 flex items-center justify-between">
                    <span>L2+: Specialized Tasks</span>
                    <span className="text-blue-400">Sub-Scoped</span>
                  </div>

                  {depth2PlusNodes.map((node) => {
                    const isSelected = selectedNode?.agent_id === node.agent_id;
                    return (
                      <div
                        key={node.agent_id}
                        onClick={() => setSelectedAgentId(node.agent_id)}
                        className={`p-3 rounded-lg border cursor-pointer transition-all ${
                          isSelected
                            ? "bg-[var(--surface-2)] border-blue-500/60 shadow-lg shadow-blue-950/20 ring-1 ring-blue-500/30"
                            : "bg-[var(--surface)] border-[var(--border)] hover:border-[var(--border-strong)]"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[var(--fg)] truncate">{node.agent_id}</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                            Depth {node.depth}
                          </span>
                        </div>
                        <div className="text-[10px] text-[var(--muted)] mt-0.5 truncate">{node.agent_name}</div>
                        <div className="mt-2 text-[10px] text-blue-300 font-bold">
                          Budget: ₹{node.base_budget.toLocaleString()}
                        </div>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {node.effective_actions.map((act) => (
                            <span key={act} className="text-[8px] px-1 py-0.5 rounded bg-blue-950/20 border border-blue-500/30 text-blue-300">
                              {act.replace("CREATE_", "")}
                            </span>
                          ))}
                        </div>
                        <div className="mt-2 text-[9px] text-[var(--subtle)] flex items-center gap-1">
                          <ArrowRight className="w-2.5 h-2.5 text-blue-400" />
                          <span>From {node.parent_agent_id}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Security Invariant Callout */}
              <div className="mt-6 p-3 rounded-lg bg-[var(--surface-2)]/50 border border-[var(--border)] text-xs font-mono flex items-start gap-3">
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold text-[var(--fg)]">Transitive Non-Expansion Invariant: </span>
                  <span className="text-[var(--muted)]">
                    An AI agent can never delegate greater privileges or budget than it received from its parent.
                    Every delegation link is cryptographically signed with RSA-PSS and checked against depth limits and cycle graphs.
                  </span>
                </div>
              </div>
            </Card>
          </div>

          {/* Right Panel: Blast Radius & Impact Breakdown (4 Cols - Inspired by KeyRunner) */}
          <div className="lg:col-span-4 space-y-4">
            <Card className="p-4 border-[var(--border)]">
              {/* Header */}
              <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
                <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--muted)] font-bold">
                  BLAST RADIUS INSPECTOR
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--surface-2)] text-[var(--muted)]">
                  Live Gov Engine
                </span>
              </div>

              {selectedNode ? (
                <div className="mt-4 space-y-4">
                  {/* Selected Agent Header */}
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center text-[var(--emerald)]">
                      <User className="w-4 h-4" />
                    </div>
                    <div className="truncate">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-sm text-[var(--fg)] truncate">
                          {selectedNode.agent_id}
                        </span>
                        <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          prod
                        </span>
                      </div>
                      <div className="text-[11px] text-[var(--muted)] truncate">{selectedNode.role}</div>
                    </div>
                  </div>

                  {/* Circular Score Gauge */}
                  <div className="p-4 rounded-xl bg-[var(--surface-2)]/60 border border-[var(--border)] flex items-center gap-4">
                    <div className="relative w-16 h-16 shrink-0 flex items-center justify-center">
                      <svg className="w-16 h-16 transform -rotate-90" viewBox="0 0 36 36">
                        <path
                          className="text-[var(--surface)]"
                          strokeWidth="3.5"
                          stroke="currentColor"
                          fill="none"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                        />
                        <path
                          className={
                            selectedNode.blast_radius.score >= 60
                              ? "text-amber-500"
                              : selectedNode.blast_radius.score >= 35
                              ? "text-purple-400"
                              : "text-emerald-400"
                          }
                          strokeDasharray={`${selectedNode.blast_radius.score}, 100`}
                          strokeWidth="3.5"
                          strokeLinecap="round"
                          stroke="currentColor"
                          fill="none"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                        />
                      </svg>
                      <div className="absolute text-center">
                        <span className="text-base font-bold font-mono text-[var(--fg)]">
                          {selectedNode.blast_radius.score}
                        </span>
                        <span className="text-[8px] text-[var(--muted)] block -mt-1 font-mono">/100</span>
                      </div>
                    </div>

                    <div>
                      <div className="text-xs font-bold font-mono text-amber-400">
                        {selectedNode.blast_radius.risk_level}
                      </div>
                      <p className="text-[10px] text-[var(--muted)] mt-1 leading-tight">
                        {selectedNode.depth === 0
                          ? "Root supervisor has bounded organizational spending authority."
                          : `Attenuated to Depth ${selectedNode.depth}. Blast radius reduced by least privilege constraints.`}
                      </p>
                    </div>
                  </div>

                  {/* Mitigation Comparison Pill */}
                  <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30 font-mono text-xs">
                    <div className="flex items-center gap-2 text-emerald-400 font-bold mb-2">
                      <ShieldCheck className="w-4 h-4" />
                      <span>{selectedNode.blast_radius.mitigated_percentage}% reduced by governance</span>
                    </div>

                    <div className="space-y-1.5 text-[10px]">
                      <div>
                        <div className="flex justify-between text-[var(--muted)] mb-0.5">
                          <span>WITHOUT policies</span>
                          <span>100</span>
                        </div>
                        <div className="h-1.5 w-full bg-[var(--surface)] rounded-full overflow-hidden">
                          <div className="h-full bg-rose-500 rounded-full w-full" />
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-[var(--muted)] mb-0.5">
                          <span>WITH policies</span>
                          <span className="text-emerald-400 font-bold">{selectedNode.blast_radius.score}</span>
                        </div>
                        <div className="h-1.5 w-full bg-[var(--surface)] rounded-full overflow-hidden">
                          <div
                            className="h-full bg-emerald-400 rounded-full"
                            style={{ width: `${selectedNode.blast_radius.score}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Impact Breakdown (Matching KeyRunner) */}
                  <div className="space-y-2 pt-2 border-t border-[var(--border)] font-mono text-xs">
                    <span className="text-[10px] uppercase font-bold text-[var(--muted)] tracking-wider">
                      IMPACT BREAKDOWN
                    </span>

                    <div className="flex items-center justify-between p-2 rounded bg-[var(--surface-2)]/40">
                      <span className="flex items-center gap-1.5 text-[11px] text-[var(--fg)]">
                        <span className="w-2 h-2 rounded bg-amber-400" /> Financial exposure
                      </span>
                      <span className="font-bold text-amber-400">
                        {selectedNode.blast_radius.impact_breakdown.financial_exposure}
                      </span>
                    </div>

                    <div className="flex items-center justify-between p-2 rounded bg-[var(--surface-2)]/40">
                      <span className="flex items-center gap-1.5 text-[11px] text-[var(--fg)]">
                        <span className="w-2 h-2 rounded bg-rose-400" /> Lateral movement
                      </span>
                      <span className="font-bold text-rose-400">
                        {selectedNode.blast_radius.impact_breakdown.lateral_movement}
                      </span>
                    </div>

                    <div className="flex items-center justify-between p-2 rounded bg-[var(--surface-2)]/40">
                      <span className="flex items-center gap-1.5 text-[11px] text-[var(--fg)]">
                        <span className="w-2 h-2 rounded bg-orange-400" /> Destructive ops
                      </span>
                      <span className="font-bold text-orange-400">
                        {selectedNode.blast_radius.impact_breakdown.destructive_ops}
                      </span>
                    </div>

                    <div className="flex items-center justify-between p-2 rounded bg-[var(--surface-2)]/40">
                      <span className="flex items-center gap-1.5 text-[11px] text-[var(--fg)]">
                        <span className="w-2 h-2 rounded bg-purple-400" /> Data exfiltration
                      </span>
                      <span className="font-bold text-purple-400">
                        {selectedNode.blast_radius.impact_breakdown.data_exfiltration}
                      </span>
                    </div>
                  </div>

                  {/* Quick Action: Execute Delegated Action on Spot */}
                  {selectedNode.status === "ACTIVE" && (
                    <Button
                      type="button"
                      variant="emerald"
                      onClick={() =>
                        executeOnSpotMutation.mutate({
                          agent_id: selectedNode.agent_id,
                          action: selectedNode.effective_actions[0] || "CREATE_PURCHASE_ORDER",
                          amount: Math.min(12000, selectedNode.remaining_budget > 0 ? selectedNode.remaining_budget : 5000),
                          resource: "SUPPLIER-101",
                          token_id: selectedNode.incoming_token_id || undefined,
                        })
                      }
                      disabled={executeOnSpotMutation.isPending}
                      className="w-full text-xs font-mono font-bold mt-3 gap-1.5 bg-emerald-500 hover:bg-emerald-400 text-black shadow-md shadow-emerald-950/20"
                    >
                      {executeOnSpotMutation.isPending ? (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Zap className="w-3.5 h-3.5" />
                      )}
                      <span>⚡ Execute On Spot (₹{Math.min(12000, selectedNode.remaining_budget > 0 ? selectedNode.remaining_budget : 5000).toLocaleString()})</span>
                    </Button>
                  )}

                  {/* Quick Action: Cascade Revoke */}
                  {selectedNode.incoming_token_id && (
                    <Button
                      type="button"
                      variant="secondary"
                      onClick={() => revokeMutation.mutate(selectedNode.incoming_token_id!)}
                      disabled={revokeMutation.isPending}
                      className="w-full text-xs font-mono text-rose-400 hover:bg-rose-950/20 border-rose-500/30 mt-2 gap-1.5"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Cascade Revoke Agent Subtree</span>
                    </Button>
                  )}
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-[var(--muted)] font-mono">
                  Select an agent to inspect blast radius.
                </div>
              )}
            </Card>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: DELEGATION TOKENS & CASCADING REVOCATION */}
      {/* ========================================================================= */}
      {activeTab === "TOKENS" && (
        <Card className="p-4">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
            <div>
              <h3 className="font-semibold text-sm text-[var(--fg)]">Signed Delegation Tokens</h3>
              <p className="text-xs text-[var(--muted)] mt-0.5">
                Every delegation is signed with the issuer&apos;s RSA-PSS private key, bound to delegate ID, with TTL and depth cap.
              </p>
            </div>
            <Button
              type="button"
              variant="emerald"
              onClick={() => setIssueModalOpen(true)}
              className="h-8 text-xs font-mono font-bold"
            >
              <Plus className="w-3.5 h-3.5 mr-1" /> Issue Delegation
            </Button>
          </div>

          <div className="overflow-x-auto font-mono text-xs">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[var(--border)] text-[var(--muted)] uppercase text-[10px]">
                  <th className="py-2.5 px-3">Token ID</th>
                  <th className="py-2.5 px-3">Issuer (Parent)</th>
                  <th className="py-2.5 px-3">Delegate (Child)</th>
                  <th className="py-2.5 px-3">Depth</th>
                  <th className="py-2.5 px-3">Budget Cap</th>
                  <th className="py-2.5 px-3">Actions Scope</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {edges.map((edge) => (
                  <tr key={edge.token_id} className="hover:bg-[var(--surface-2)]/40 transition-colors">
                    <td className="py-3 px-3 font-bold text-[var(--fg)]">{edge.token_id}</td>
                    <td className="py-3 px-3 text-[var(--muted)]">{edge.issuer_agent_id}</td>
                    <td className="py-3 px-3 text-emerald-400">{edge.delegate_agent_id}</td>
                    <td className="py-3 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)]">
                        L{edge.depth}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-bold text-amber-400">
                      ₹{edge.delegated_budget.toLocaleString()}
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {edge.delegated_actions.map((act) => (
                          <span
                            key={act}
                            className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-950/20 border border-emerald-500/20 text-emerald-300"
                          >
                            {act}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded-full border ${
                          edge.status === "ACTIVE"
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                            : "bg-rose-500/10 text-rose-400 border-rose-500/30"
                        }`}
                      >
                        {edge.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      {edge.status === "ACTIVE" ? (
                        <button
                          type="button"
                          onClick={() => revokeMutation.mutate(edge.token_id)}
                          disabled={revokeMutation.isPending}
                          className="px-2 py-1 rounded text-[11px] text-rose-400 bg-rose-950/20 hover:bg-rose-900/30 border border-rose-500/30 transition-colors"
                          title="Revoke this token and cascade through all sub-delegates"
                        >
                          Cascade Revoke
                        </button>
                      ) : (
                        <span className="text-[10px] text-[var(--muted)]">Revoked</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: SECURITY INVARIANT LAB (5 ATTACK SIMULATIONS) */}
      {/* ========================================================================= */}
      {activeTab === "ATTACK_LAB" && (
        <div className="space-y-4">
          <Card className="p-4">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
              <div>
                <h3 className="font-semibold text-sm text-[var(--fg)] flex items-center gap-2">
                  <Flame className="w-4 h-4 text-rose-400" />
                  <span>Delegation Security Invariant Test Suite</span>
                </h3>
                <p className="text-xs text-[var(--muted)] mt-0.5">
                  Verify how AgentTrust blocks privilege escalation, cyclic authority loops, overdrafts, and depth breaches.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
              {/* Test 1 */}
              <div className="p-3.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:border-[var(--border-strong)] transition-all">
                <div className="flex items-center justify-between text-xs font-bold text-[var(--fg)]">
                  <span>1. Privilege Amplification</span>
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                </div>
                <p className="text-[10px] text-[var(--muted)] mt-1">
                  Vendor Verification Agent (PO only) attempts to delegate TRANSFER_FUNDS to an external bot.
                </p>
                <div className="mt-2 text-[9px] text-emerald-400">Invariant: Non-Expanding Scope</div>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => attackMutation.mutate("PRIVILEGE_AMPLIFICATION")}
                  disabled={attackMutation.isPending}
                  className="w-full mt-3 h-8 text-[11px] gap-1.5"
                >
                  <Play className="w-3 h-3 text-rose-400" />
                  <span>Execute Attack Simulation</span>
                </Button>
              </div>

              {/* Test 2 */}
              <div className="p-3.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:border-[var(--border-strong)] transition-all">
                <div className="flex items-center justify-between text-xs font-bold text-[var(--fg)]">
                  <span>2. Cyclic Authority Loop</span>
                  <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
                </div>
                <p className="text-[10px] text-[var(--muted)] mt-1">
                  Reporting Agent D attempts to delegate authority back to Supervisor A (A &rarr; B &rarr; D &rarr; A).
                </p>
                <div className="mt-2 text-[9px] text-emerald-400">Invariant: Strict Directed Acyclic Graph</div>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => attackMutation.mutate("CYCLIC_DELEGATION_LOOP")}
                  disabled={attackMutation.isPending}
                  className="w-full mt-3 h-8 text-[11px] gap-1.5"
                >
                  <Play className="w-3 h-3 text-amber-400" />
                  <span>Execute Attack Simulation</span>
                </Button>
              </div>

              {/* Test 3 */}
              <div className="p-3.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:border-[var(--border-strong)] transition-all">
                <div className="flex items-center justify-between text-xs font-bold text-[var(--fg)]">
                  <span>3. Budget Overdraft</span>
                  <Coins className="w-3.5 h-3.5 text-purple-400" />
                </div>
                <p className="text-[10px] text-[var(--muted)] mt-1">
                  Agent D with remaining allowance of ₹25k attempts to delegate ₹100,000 to a shadow agent.
                </p>
                <div className="mt-2 text-[9px] text-emerald-400">Invariant: Monotonic Budget Bounds</div>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => attackMutation.mutate("BUDGET_OVERDRAFT")}
                  disabled={attackMutation.isPending}
                  className="w-full mt-3 h-8 text-[11px] gap-1.5"
                >
                  <Play className="w-3 h-3 text-purple-400" />
                  <span>Execute Attack Simulation</span>
                </Button>
              </div>

              {/* Test 4 */}
              <div className="p-3.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:border-[var(--border-strong)] transition-all">
                <div className="flex items-center justify-between text-xs font-bold text-[var(--fg)]">
                  <span>4. Depth Cap Exceeded</span>
                  <Layers className="w-3.5 h-3.5 text-blue-400" />
                </div>
                <p className="text-[10px] text-[var(--muted)] mt-1">
                  Chaining delegations beyond depth 4 (A &rarr; B &rarr; D &rarr; E &rarr; F &rarr; G).
                </p>
                <div className="mt-2 text-[9px] text-emerald-400">Invariant: Max Depth Limit (4)</div>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => attackMutation.mutate("DEPTH_EXCEEDED")}
                  disabled={attackMutation.isPending}
                  className="w-full mt-3 h-8 text-[11px] gap-1.5"
                >
                  <Play className="w-3 h-3 text-blue-400" />
                  <span>Execute Attack Simulation</span>
                </Button>
              </div>

              {/* Test 5 */}
              <div className="p-3.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:border-[var(--border-strong)] transition-all">
                <div className="flex items-center justify-between text-xs font-bold text-[var(--fg)]">
                  <span>5. Cascading Revocation Check</span>
                  <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                </div>
                <p className="text-[10px] text-[var(--muted)] mt-1">
                  Revoking A &rarr; B and verifying that B &rarr; D is instantly and automatically blocked.
                </p>
                <div className="mt-2 text-[9px] text-emerald-400">Invariant: Transitive Revocation</div>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => attackMutation.mutate("CASCADING_REVOCATION_ATTACK")}
                  disabled={attackMutation.isPending}
                  className="w-full mt-3 h-8 text-[11px] gap-1.5"
                >
                  <Play className="w-3 h-3 text-rose-400" />
                  <span>Execute Attack Simulation</span>
                </Button>
              </div>
            </div>
          </Card>

          {/* Simulation Outcome Card */}
          {simulationResult && (
            <Card className="p-4 border-emerald-500/40 bg-emerald-950/10 font-mono text-xs animate-in fade-in slide-in-from-top-2">
              <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
                <div className="flex items-center gap-2 text-emerald-400 font-bold">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Simulation Verdict: {simulationResult.decision || "BLOCKED"}</span>
                </div>
                <span className="text-[10px] text-[var(--muted)]">{simulationResult.timestamp}</span>
              </div>

              <div className="mt-3 space-y-2">
                <div>
                  <span className="text-[var(--muted)]">Scenario: </span>
                  <span className="font-bold text-[var(--fg)]">{simulationResult.title}</span>
                </div>
                <div>
                  <span className="text-[var(--muted)]">Enforced Invariant: </span>
                  <span className="text-emerald-300 font-bold">{simulationResult.enforced_invariant}</span>
                </div>
                <div>
                  <span className="text-[var(--muted)]">Defense Reason: </span>
                  <span className="text-rose-300">{simulationResult.reason}</span>
                </div>
                {simulationResult.target_loop && (
                  <div>
                    <span className="text-[var(--muted)]">Cycle Path Blocked: </span>
                    <span className="text-amber-400">{simulationResult.target_loop}</span>
                  </div>
                )}
                <div className="text-[10px] text-emerald-400/80 pt-1">
                  &check; Event committed to immutable cryptographic delegation audit trail.
                </div>
              </div>
            </Card>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: CRYPTOGRAPHIC AUDIT TRAIL */}
      {/* ========================================================================= */}
      {activeTab === "AUDIT" && (
        <Card className="p-4">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
            <div>
              <h3 className="font-semibold text-sm text-[var(--fg)]">Delegation Audit Trail</h3>
              <p className="text-xs text-[var(--muted)] mt-0.5">
                Cryptographically hashed audit log of every delegation issuance, attenuation check, cycle rejection, and revocation.
              </p>
            </div>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {auditTrail.map((log) => (
              <div
                key={log.event_id}
                className="p-3 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-2)]/40 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-2"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        log.decision === "ALLOWED"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                      }`}
                    >
                      {log.decision}
                    </span>
                    <span className="font-bold text-[var(--fg)]">{log.event_type}</span>
                    {log.token_id && (
                      <span className="text-[10px] text-[var(--muted)]">{log.token_id}</span>
                    )}
                  </div>
                  <div className="text-[11px] text-[var(--muted)]">
                    {log.issuer_agent_id && `Issuer: ${log.issuer_agent_id} `}
                    {log.delegate_agent_id && `→ Delegate: ${log.delegate_agent_id}`}
                    {Boolean(log.details?.reason) && ` • ${String(log.details.reason)}`}
                  </div>
                </div>

                <div className="text-right text-[10px] text-[var(--muted)]">
                  <div>{new Date(log.timestamp).toLocaleTimeString()}</div>
                  <div className="text-[9px] text-[var(--subtle)] font-mono truncate max-w-xs">
                    {log.record_hash}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* ========================================================================= */}
      {/* MODAL: ISSUE NEW DELEGATION TOKEN */}
      {/* ========================================================================= */}
      {issueModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <Card className="w-full max-w-lg p-5 border-[var(--border)] shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
              <h3 className="font-bold text-sm text-[var(--fg)] flex items-center gap-2">
                <Plus className="w-4 h-4 text-emerald-400" />
                <span>Issue Capability Delegation Token</span>
              </h3>
              <button
                type="button"
                onClick={() => setIssueModalOpen(false)}
                className="text-[var(--muted)] hover:text-[var(--fg)] text-lg"
              >
                &times;
              </button>
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                issueMutation.mutate({
                  issuer_agent_id: formIssuer,
                  delegate_agent_id: formDelegate,
                  allowed_actions: formActions,
                  delegated_budget: formBudget,
                  reason: formReason,
                });
              }}
              className="space-y-4 font-mono text-xs"
            >
              {/* Select Issuer */}
              <div>
                <label className="block text-[var(--muted)] font-medium mb-1">
                  Issuer (Parent Agent)
                </label>
                <select
                  value={formIssuer}
                  onChange={(e) => {
                    setFormIssuer(e.target.value);
                    const found = nodes.find((n) => n.agent_id === e.target.value);
                    if (found) {
                      setFormActions(found.effective_actions.slice(0, 2));
                      setFormBudget(Math.min(formBudget, found.remaining_budget));
                    }
                  }}
                  className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] focus:outline-none focus:border-emerald-500"
                >
                  {nodes.map((n) => (
                    <option key={n.agent_id} value={n.agent_id}>
                      {n.agent_id} (Rem. Budget: ₹{n.remaining_budget.toLocaleString()})
                    </option>
                  ))}
                </select>
              </div>

              {/* Select Delegate */}
              <div>
                <label className="block text-[var(--muted)] font-medium mb-1">
                  Delegate (Child Agent)
                </label>
                <input
                  type="text"
                  value={formDelegate}
                  onChange={(e) => setFormDelegate(e.target.value)}
                  placeholder="e.g. SUB-AGENT-005"
                  className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] focus:outline-none focus:border-emerald-500"
                  required
                />
              </div>

              {/* Action Scope (Attenuated subset) */}
              <div>
                <label className="block text-[var(--muted)] font-medium mb-1 flex justify-between">
                  <span>Delegated Actions (Must be subset of Issuer)</span>
                  <span className="text-[10px] text-emerald-400">Transitive Attenuation</span>
                </label>
                <div className="grid grid-cols-2 gap-2 mt-1">
                  {(selectedIssuerNode?.effective_actions || ["CREATE_PURCHASE_ORDER"]).map((act) => (
                    <label
                      key={act}
                      className="flex items-center gap-2 p-2 rounded bg-[var(--surface-2)]/60 border border-[var(--border)] cursor-pointer text-[11px]"
                    >
                      <input
                        type="checkbox"
                        checked={formActions.includes(act)}
                        onChange={() => handleActionToggle(act)}
                        className="rounded accent-emerald-500"
                      />
                      <span className="truncate">{act}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Budget Allocation */}
              <div>
                <label className="block text-[var(--muted)] font-medium mb-1 flex justify-between">
                  <span>Allocated Budget Cap (₹)</span>
                  <span className="text-[10px] text-amber-400">
                    Max: ₹{selectedIssuerNode?.remaining_budget.toLocaleString() || "0"}
                  </span>
                </label>
                <input
                  type="number"
                  value={formBudget}
                  onChange={(e) => setFormBudget(Number(e.target.value))}
                  min={1000}
                  max={selectedIssuerNode?.remaining_budget || 500000}
                  className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] focus:outline-none focus:border-emerald-500"
                  required
                />
              </div>

              {/* Reason */}
              <div>
                <label className="block text-[var(--muted)] font-medium mb-1">
                  Delegation Justification
                </label>
                <input
                  type="text"
                  value={formReason}
                  onChange={(e) => setFormReason(e.target.value)}
                  className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => setIssueModalOpen(false)}
                  className="h-9 text-xs"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="emerald"
                  disabled={issueMutation.isPending || formActions.length === 0}
                  className="h-9 text-xs font-bold gap-1.5"
                >
                  {issueMutation.isPending ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  <span>Sign & Issue Token</span>
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}
    </div>
  );
}
