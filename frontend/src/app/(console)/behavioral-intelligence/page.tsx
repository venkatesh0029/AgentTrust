"use client";

import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Brain,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Activity,
  ArrowRight,
  RefreshCw,
  Play,
  RotateCcw,
  Zap,
  Clock,
  User,
  ExternalLink,
  ChevronRight,
  TrendingUp,
  Sliders,
  Sparkles,
} from "lucide-react";
import { Card, Button } from "@/components/ui/primitives";
import {
  api,
  BehaviorEvent,
  AgentBehaviorProfile,
  BehaviorSummaryResponse,
} from "@/lib/api";

type ViewTab = "UEBA_FEED" | "PROFILES" | "SIMULATOR";

export default function BehavioralIntelligencePage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<ViewTab>("UEBA_FEED");
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Custom Simulator Form State
  const [simAgentId, setSimAgentId] = useState("FINANCE_AGENT_01");
  const [simAction, setSimAction] = useState("TRANSFER_FUNDS");
  const [simResource, setSimResource] = useState("UNKNOWN-OFFSHORE-CORP-999");
  const [simAmount, setSimAmount] = useState(95000);
  const [simTime, setSimTime] = useState("2026-11-07T02:15:00Z");
  const [simBurst, setSimBurst] = useState(48);

  // Fetch summary and events
  const { data: summaryData, isLoading, refetch } = useQuery<BehaviorSummaryResponse>({
    queryKey: ["behaviorSummary"],
    queryFn: () => api.fetchBehaviorSummary(),
    refetchInterval: 3000,
  });

  // Execute Live Action on Spot Mutation
  const executeOnSpotMutation = useMutation({
    mutationFn: (data: { agent_id: string; action: string; amount: number; resource?: string }) =>
      api.executeBehaviorActionOnSpot(data),
    onSuccess: (data: any) => {
      const oc = data.outcome || {};
      const ueba = oc.behavioral_intelligence || {};
      setActionMessage({
        type: "success",
        text: `⚡ Live Gateway Action Executed on Spot! Decision: ${oc.decision} • UEBA Anomaly Score: ${ueba.anomaly_score ?? "Normal"}/100 [${ueba.enforcement || "ALLOW"}] • Moving baseline updated.`,
      });
      queryClient.invalidateQueries({ queryKey: ["behaviorSummary"] });
    },
    onError: (err: Error) => {
      setActionMessage({ type: "error", text: err.message || "Failed to execute live action." });
    },
  });

  // Scenario Simulation Mutation
  const scenarioMutation = useMutation({
    mutationFn: (scenario: string) => api.simulateBehaviorScenario(scenario),
    onSuccess: (data: any) => {
      const evaluation = data.evaluation || data;
      setActionMessage({
        type: "success",
        text: `Simulation executed! Anomaly score: ${evaluation.anomaly_score}/100 [${evaluation.enforcement}]`,
      });
      if (evaluation.event_id) {
        setSelectedEventId(evaluation.event_id);
      }
      queryClient.invalidateQueries({ queryKey: ["behaviorSummary"] });
    },
    onError: (err: Error) => {
      setActionMessage({ type: "error", text: err.message || "Simulation failed." });
    },
  });

  // Custom Analyze Mutation
  const customAnalyzeMutation = useMutation({
    mutationFn: (payload: {
      agent_id: string;
      action: string;
      resource: string;
      amount: number;
      request_timestamp_iso: string;
      simulate_window_burst: number;
    }) => api.analyzeBehaviorRequest(payload),
    onSuccess: (data: any) => {
      const evaluation = data.evaluation || data;
      setActionMessage({
        type: "success",
        text: `Custom request evaluated! Anomaly score: ${evaluation.anomaly_score}/100 [${evaluation.enforcement}]`,
      });
      if (evaluation.event_id) {
        setSelectedEventId(evaluation.event_id);
      }
      queryClient.invalidateQueries({ queryKey: ["behaviorSummary"] });
    },
    onError: (err: Error) => {
      setActionMessage({ type: "error", text: err.message || "Evaluation failed." });
    },
  });

  // Reset Baselines Mutation
  const resetMutation = useMutation({
    mutationFn: () => api.resetBehaviorProfiles(),
    onSuccess: () => {
      setActionMessage({ type: "success", text: "Behavioral profiles reset to canonical enterprise baselines." });
      setSelectedEventId(null);
      queryClient.invalidateQueries({ queryKey: ["behaviorSummary"] });
    },
    onError: (err: Error) => {
      setActionMessage({ type: "error", text: err.message || "Failed to reset baselines." });
    },
  });

  const events = useMemo(() => summaryData?.recent_events || [], [summaryData]);
  const profiles = useMemo(() => summaryData?.profiles || [], [summaryData]);
  const topEntities = useMemo(() => summaryData?.top_anomalous_entities || [], [summaryData]);

  // Selected event for deep JSON-like enrichment
  const selectedEvent = useMemo(() => {
    if (!selectedEventId && events.length > 0) return events[0];
    return events.find((e) => e.event_id === selectedEventId) || events[0] || null;
  }, [events, selectedEventId]);

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

      {/* Page Header (Sentinel Style) */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-cyan-400">
              <Brain className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-[var(--fg)]">
                  AI Agent Behavioral Intelligence Engine
                </h1>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  Sentinel UEBA
                </span>
              </div>
              <p className="text-xs text-[var(--muted)] mt-0.5">
                Continuous dynamic profiling, multi-dimensional statistical baselining, and explainable behavioral anomaly governance.
              </p>
            </div>
          </div>
        </div>

        {/* Action Triggers */}
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            type="button"
            variant="secondary"
            onClick={() => scenarioMutation.mutate("FINANCE_AGENT_DEVIATION")}
            disabled={scenarioMutation.isPending}
            className="h-8 text-xs font-mono font-bold text-rose-400 hover:bg-rose-950/20 border-rose-500/30 gap-1.5"
            title="Simulate prompt scenario: 50 transactions, ₹95k amount, unfamiliar recipient, 02:15 AM off-schedule"
          >
            <Zap className={`w-3.5 h-3.5 ${scenarioMutation.isPending ? "animate-spin" : ""}`} />
            <span>Simulate Finance Deviation (50 Txns)</span>
          </Button>

          <Button
            type="button"
            variant="emerald"
            onClick={() =>
              executeOnSpotMutation.mutate({
                agent_id: "FINANCE_AGENT_01",
                action: "TRANSFER_FUNDS",
                amount: 14500,
                resource: "SUPPLIER-101",
              })
            }
            disabled={executeOnSpotMutation.isPending}
            className="h-8 text-xs font-mono font-bold gap-1.5 bg-cyan-500 hover:bg-cyan-400 text-black shadow-md shadow-cyan-950/20"
          >
            {executeOnSpotMutation.isPending ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Zap className="w-3.5 h-3.5" />
            )}
            <span>⚡ Live Action On Spot</span>
          </Button>

          <Button
            type="button"
            variant="secondary"
            onClick={() => scenarioMutation.mutate("NORMAL_BASELINE_TRANSACTION")}
            disabled={scenarioMutation.isPending}
            className="h-8 text-xs font-mono text-emerald-400 hover:bg-emerald-950/20 border-emerald-500/30 gap-1.5"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Simulate Normal (₹12.5k)</span>
          </Button>

          <Button
            type="button"
            variant="secondary"
            onClick={() => resetMutation.mutate()}
            disabled={resetMutation.isPending}
            className="h-8 text-xs font-mono gap-1.5"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${resetMutation.isPending ? "animate-spin" : ""}`} />
            <span>Reset Baselines</span>
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

      {/* Sentinel Pipeline Ribbon (Matching Image) */}
      <Card className="p-3 bg-[var(--surface)] border-[var(--border)] font-mono text-xs overflow-x-auto">
        <div className="flex items-center gap-2 min-w-[700px]">
          <div className="px-3 py-1.5 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-[var(--fg)] flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-blue-400" />
            <span className="font-bold">Raw Action Stream</span>
            <span className="text-[10px] text-[var(--muted)]">Gateway Telemetry</span>
          </div>

          <ArrowRight className="w-4 h-4 text-[var(--muted)] shrink-0" />

          <div className="px-3 py-1.5 rounded-lg bg-cyan-950/30 border border-cyan-500/30 text-cyan-300 flex items-center gap-2">
            <Brain className="w-3.5 h-3.5 text-cyan-400" />
            <span className="font-bold">Sentinel UEBA Profiler</span>
            <span className="text-[10px] text-cyan-400/80">Dynamic Baseline</span>
          </div>

          <ArrowRight className="w-4 h-4 text-[var(--muted)] shrink-0" />

          <div className="px-3 py-1.5 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-[var(--fg)] flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-purple-400" />
            <span className="font-bold">Behavior Flags (0/1)</span>
            <span className="text-[10px] text-[var(--muted)]">5 Binary Indicators</span>
          </div>

          <ArrowRight className="w-4 h-4 text-[var(--muted)] shrink-0" />

          <div className="px-3 py-1.5 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-emerald-300 flex items-center gap-2">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span className="font-bold">Gateway Escalation</span>
            <span className="text-[10px] text-emerald-400/80">Human Approval Ticket</span>
          </div>
        </div>
      </Card>

      {/* Global Activity KPI Overview (Matching Image) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="p-3">
          <div className="text-[10px] font-mono uppercase text-[var(--muted)] flex items-center justify-between">
            <span>Monitored Agents</span>
            <User className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-xl font-bold font-mono text-[var(--fg)] mt-1">
            {summaryData?.monitored_agents || profiles.length}
          </div>
          <div className="text-[10px] text-emerald-400 mt-0.5">&uarr; 18% Active Baselines</div>
        </Card>

        <Card className="p-3">
          <div className="text-[10px] font-mono uppercase text-[var(--muted)] flex items-center justify-between">
            <span>Analyzed Actions</span>
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
            {summaryData?.total_events_analyzed || events.length}
          </div>
          <div className="text-[10px] text-[var(--muted)] mt-0.5">Continuous ML Evaluation</div>
        </Card>

        <Card className="p-3">
          <div className="text-[10px] font-mono uppercase text-[var(--muted)] flex items-center justify-between">
            <span>Behavioral Anomalies</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400 mt-1">
            {summaryData?.anomalies_detected || 0}
          </div>
          <div className="text-[10px] text-amber-500/80 mt-0.5">Deviations Beyond 3.0σ</div>
        </Card>

        <Card className="p-3 border-rose-500/30 bg-rose-950/10">
          <div className="text-[10px] font-mono uppercase text-rose-400 flex items-center justify-between">
            <span>Critical Escalations</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400 mt-1">
            {summaryData?.critical_deviations_count || 0}
          </div>
          <div className="text-[10px] text-rose-400/80 mt-0.5">Rerouted to Human Approval</div>
        </Card>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-[var(--border)] pb-2 font-mono text-xs">
        <button
          type="button"
          onClick={() => setActiveTab("UEBA_FEED")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium transition-colors ${
            activeTab === "UEBA_FEED"
              ? "bg-[var(--surface-2)] text-cyan-400 border border-[var(--border)]"
              : "text-[var(--muted)] hover:text-[var(--fg)]"
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Behavior Analytics Feed & Inspector</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("PROFILES")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium transition-colors ${
            activeTab === "PROFILES"
              ? "bg-[var(--surface-2)] text-cyan-400 border border-[var(--border)]"
              : "text-[var(--muted)] hover:text-[var(--fg)]"
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Learned Agent Baselines ({profiles.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("SIMULATOR")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium transition-colors ${
            activeTab === "SIMULATOR"
              ? "bg-[var(--surface-2)] text-cyan-400 border border-[var(--border)]"
              : "text-[var(--muted)] hover:text-[var(--fg)]"
          }`}
        >
          <Sparkles className="w-3.5 h-3.5 text-amber-400" />
          <span>Interactive Anomaly Simulator</span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: BEHAVIOR ANALYTICS FEED & SENTINEL INSPECTOR (Exact Image Match) */}
      {/* ========================================================================= */}
      {activeTab === "UEBA_FEED" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left: 8 Cols - Behavior Analytics Table with 0/1 Flags */}
          <div className="lg:col-span-8 space-y-4">
            <Card className="p-4">
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
                <div>
                  <h3 className="font-semibold text-sm text-[var(--fg)] flex items-center gap-2">
                    <span>Behavior Analytics Telemetry</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      Behavior Flags (0/1)
                    </span>
                  </h3>
                  <p className="text-[11px] text-[var(--muted)] mt-0.5">
                    Select any evaluated action to inspect deep behavioral insights and explainable anomaly tags.
                  </p>
                </div>
              </div>

              {/* Table with 0/1 Behavior Flags matching Microsoft Sentinel */}
              <div className="overflow-x-auto font-mono text-xs">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-[var(--border)] text-[var(--muted)] uppercase text-[10px]">
                      <th className="py-2.5 px-2">Time (UTC)</th>
                      <th className="py-2.5 px-2">Agent ID</th>
                      <th className="py-2.5 px-2">Action</th>
                      <th className="py-2.5 px-2">Resource</th>
                      <th className="py-2.5 px-1.5 text-center" title="Amount deviation >= 3.0 sigma">Amount</th>
                      <th className="py-2.5 px-1.5 text-center" title="Unfamiliar or unverified recipient">Dest</th>
                      <th className="py-2.5 px-1.5 text-center" title="Off-hours schedule (e.g. 02:00 AM)">Time</th>
                      <th className="py-2.5 px-1.5 text-center" title="Burst velocity > hourly threshold">Burst</th>
                      <th className="py-2.5 px-1.5 text-center" title="Action sequence transition anomaly">Seq</th>
                      <th className="py-2.5 px-2 text-right">Anomaly Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border)]">
                    {events.map((ev) => {
                      const isSelected = selectedEvent?.event_id === ev.event_id;
                      return (
                        <tr
                          key={ev.event_id}
                          onClick={() => setSelectedEventId(ev.event_id)}
                          className={`cursor-pointer transition-colors ${
                            isSelected
                              ? "bg-[var(--surface-2)] text-[var(--fg)] border-l-2 border-cyan-400"
                              : "hover:bg-[var(--surface-2)]/40 text-[var(--muted)]"
                          }`}
                        >
                          <td className="py-2.5 px-2 text-[10px]">
                            {new Date(ev.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="py-2.5 px-2 font-bold text-[var(--fg)] truncate max-w-[110px]">
                            {ev.agent_id}
                          </td>
                          <td className="py-2.5 px-2 truncate max-w-[120px]">
                            {ev.action.replace("CREATE_", "").replace("TRANSFER_", "TRX_")}
                          </td>
                          <td className="py-2.5 px-2 text-cyan-300 truncate max-w-[120px]">
                            {ev.resource}
                          </td>

                          {/* Behavior Indicator Flags (0 or 1) */}
                          <td className="py-2.5 px-1.5 text-center">
                            <span
                              className={`inline-block px-1.5 py-0.2 rounded text-[10px] font-bold ${
                                ev.flags.unusual_amount
                                  ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                                  : "text-[var(--subtle)]"
                              }`}
                            >
                              {ev.flags.unusual_amount ? "1" : "0"}
                            </span>
                          </td>

                          <td className="py-2.5 px-1.5 text-center">
                            <span
                              className={`inline-block px-1.5 py-0.2 rounded text-[10px] font-bold ${
                                ev.flags.unfamiliar_recipient
                                  ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                                  : "text-[var(--subtle)]"
                              }`}
                            >
                              {ev.flags.unfamiliar_recipient ? "1" : "0"}
                            </span>
                          </td>

                          <td className="py-2.5 px-1.5 text-center">
                            <span
                              className={`inline-block px-1.5 py-0.2 rounded text-[10px] font-bold ${
                                ev.flags.unusual_schedule
                                  ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                                  : "text-[var(--subtle)]"
                              }`}
                            >
                              {ev.flags.unusual_schedule ? "1" : "0"}
                            </span>
                          </td>

                          <td className="py-2.5 px-1.5 text-center">
                            <span
                              className={`inline-block px-1.5 py-0.2 rounded text-[10px] font-bold ${
                                ev.flags.burst_velocity
                                  ? "bg-purple-500/20 text-purple-400 border border-purple-500/30"
                                  : "text-[var(--subtle)]"
                              }`}
                            >
                              {ev.flags.burst_velocity ? "1" : "0"}
                            </span>
                          </td>

                          <td className="py-2.5 px-1.5 text-center">
                            <span
                              className={`inline-block px-1.5 py-0.2 rounded text-[10px] font-bold ${
                                ev.flags.sequence_anomaly
                                  ? "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                                  : "text-[var(--subtle)]"
                              }`}
                            >
                              {ev.flags.sequence_anomaly ? "1" : "0"}
                            </span>
                          </td>

                          {/* Anomaly Score */}
                          <td className="py-2.5 px-2 text-right">
                            <span
                              className={`font-bold px-2 py-0.5 rounded ${
                                ev.anomaly_score >= 70
                                  ? "bg-rose-950/40 text-rose-400 border border-rose-500/30"
                                  : ev.anomaly_score >= 35
                                  ? "bg-amber-950/40 text-amber-400 border border-amber-500/30"
                                  : "bg-emerald-950/40 text-emerald-400 border border-emerald-500/30"
                              }`}
                            >
                              {ev.anomaly_score}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Card>

            {/* Behavior Analytics Details (JSON-Like Enrichment Matching Image) */}
            {selectedEvent && (
              <Card className="p-4 border-[var(--border)]">
                <div className="flex items-center justify-between pb-3 border-b border-[var(--border)] mb-3">
                  <h4 className="font-semibold text-xs text-[var(--fg)] uppercase tracking-wider font-mono">
                    BEHAVIOR ANALYTICS DETAILS (JSON-LIKE ENRICHMENT)
                  </h4>
                  <span className="text-[10px] font-mono text-cyan-400">
                    Event ID: {selectedEvent.event_id}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
                  {/* Card 1: Agent Insights */}
                  <div className="p-3 rounded-lg bg-[var(--surface-2)]/60 border border-[var(--border)] space-y-2">
                    <div className="flex items-center gap-1.5 font-bold text-[var(--fg)] text-[11px] pb-1 border-b border-[var(--border)]">
                      <User className="w-3.5 h-3.5 text-blue-400" />
                      <span>AgentInsights</span>
                    </div>
                    <pre className="text-[10px] text-[var(--muted)] leading-relaxed overflow-x-auto">
{`{
  "agentId": "${selectedEvent.agent_id}",
  "action": "${selectedEvent.action}",
  "amount": "₹${selectedEvent.amount.toLocaleString()}",
  "baseline": "${selectedEvent.insights.agent_insights?.baseline_status || "LEARNED_STABLE"}",
  "samples": ${selectedEvent.insights.agent_insights?.historical_samples || 840}
}`}
                    </pre>
                  </div>

                  {/* Card 2: Destination Insights */}
                  <div className="p-3 rounded-lg bg-[var(--surface-2)]/60 border border-[var(--border)] space-y-2">
                    <div className="flex items-center gap-1.5 font-bold text-[var(--fg)] text-[11px] pb-1 border-b border-[var(--border)]">
                      <ExternalLink className="w-3.5 h-3.5 text-purple-400" />
                      <span>DestinationInsights</span>
                    </div>
                    <pre className="text-[10px] text-[var(--muted)] leading-relaxed overflow-x-auto">
{`{
  "resource": "${selectedEvent.resource}",
  "isFamiliar": ${selectedEvent.insights.destination_insights?.isFamiliar ?? true},
  "trustedPeersCount": ${selectedEvent.insights.destination_insights?.trusted_peer_count || 4},
  "anomalyFlag": ${selectedEvent.flags.unfamiliar_recipient ? 1 : 0}
}`}
                    </pre>
                  </div>

                  {/* Card 3: Activity Insights */}
                  <div className="p-3 rounded-lg bg-[var(--surface-2)]/60 border border-[var(--border)] space-y-2">
                    <div className="flex items-center gap-1.5 font-bold text-[var(--fg)] text-[11px] pb-1 border-b border-[var(--border)]">
                      <Activity className="w-3.5 h-3.5 text-cyan-400" />
                      <span>ActivityInsights</span>
                    </div>
                    <pre className="text-[10px] text-[var(--muted)] leading-relaxed overflow-x-auto">
{`{
  "operationVolume1h": ${selectedEvent.insights.activity_insights?.operation_volume_1h || 1},
  "burstThreshold": ${selectedEvent.insights.activity_insights?.burst_threshold || 10},
  "riskLevel": "${selectedEvent.risk_level}",
  "enforcement": "${selectedEvent.enforcement}"
}`}
                    </pre>
                  </div>
                </div>
              </Card>
            )}
          </div>

          {/* Right: 4 Cols - ANOMALIES (TOP) & Explainability Breakdown (Exact Image Match) */}
          <div className="lg:col-span-4 space-y-4">
            <Card className="p-4 border-rose-500/40 bg-[var(--surface)]">
              {/* Header */}
              <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
                <span className="text-[11px] font-mono uppercase tracking-wider text-rose-400 font-bold flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>ANOMALY ALERT (UEBA)</span>
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  Enforcement Active
                </span>
              </div>

              {selectedEvent ? (
                <div className="mt-4 space-y-4 font-mono">
                  {/* Big Risk Score Display (Matching Microsoft Sentinel) */}
                  <div className="p-4 rounded-xl bg-[var(--surface-2)]/70 border border-[var(--border)] flex items-center justify-between">
                    <div>
                      <span className="text-[10px] text-[var(--muted)] uppercase block">Behavioral Risk Score</span>
                      <div className="flex items-baseline gap-2 mt-0.5">
                        <span
                          className={`text-4xl font-extrabold ${
                            selectedEvent.anomaly_score >= 70
                              ? "text-rose-500"
                              : selectedEvent.anomaly_score >= 35
                              ? "text-amber-400"
                              : "text-emerald-400"
                          }`}
                        >
                          {selectedEvent.anomaly_score}
                        </span>
                        <span className="text-xs text-[var(--muted)]">/ 100</span>
                        <span
                          className={`text-xs font-bold px-2 py-0.5 rounded ${
                            selectedEvent.anomaly_score >= 70
                              ? "bg-rose-500/20 text-rose-400"
                              : selectedEvent.anomaly_score >= 35
                              ? "bg-amber-500/20 text-amber-400"
                              : "bg-emerald-500/20 text-emerald-400"
                          }`}
                        >
                          {selectedEvent.risk_level}
                        </span>
                      </div>
                    </div>

                    <div className="text-right text-[10px] text-[var(--muted)]">
                      <div>Target: <span className="text-[var(--fg)] font-bold">{selectedEvent.agent_id}</span></div>
                      <div>Decision: <span className="text-rose-400 font-bold">{selectedEvent.enforcement}</span></div>
                    </div>
                  </div>

                  {/* Top Explainable Reasons (with color-coded dots matching Sentinel) */}
                  <div className="space-y-2">
                    <span className="text-[10px] uppercase font-bold text-[var(--muted)] tracking-wider block">
                      TOP REASONS (EXPLAINABILITY)
                    </span>

                    <div className="space-y-1.5 text-xs">
                      {selectedEvent.explainable_reasons.map((reason, idx) => {
                        const dotColors = [
                          "bg-rose-500",
                          "bg-amber-400",
                          "bg-purple-400",
                          "bg-blue-400",
                          "bg-cyan-400",
                        ];
                        const dotColor = dotColors[idx % dotColors.length];
                        return (
                          <div
                            key={idx}
                            className="p-2.5 rounded-lg bg-[var(--surface-2)]/50 border border-[var(--border)] flex items-start gap-2.5 text-[11px] leading-relaxed"
                          >
                            <span className={`w-2 h-2 rounded-full ${dotColor} shrink-0 mt-1`} />
                            <span className="text-[var(--fg)]">{reason}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Invariant Guarantee Box */}
                  <div className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-500/30 text-[10px] text-cyan-300">
                    <span className="font-bold">Principle of Non-Amplification: </span>
                    <span>The ML behavioral model recommends additional restrictions or human escalation; it never independently grants authorization.</span>
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-[var(--muted)] font-mono">
                  Select an event to inspect explainable reasons.
                </div>
              )}
            </Card>

            {/* Top Anomalous Agents Leaderboard */}
            <Card className="p-4">
              <div className="flex items-center justify-between pb-3 border-b border-[var(--border)] mb-3">
                <span className="text-[11px] font-mono uppercase font-bold text-[var(--muted)]">
                  TOP ANOMALOUS AGENTS
                </span>
                <span className="text-[10px] font-mono text-[var(--muted)]">Max Score</span>
              </div>

              <div className="space-y-2 font-mono text-xs">
                {topEntities.map((item) => (
                  <div
                    key={item.agent_id}
                    onClick={() => {
                      const found = events.find((e) => e.agent_id === item.agent_id);
                      if (found) setSelectedEventId(found.event_id);
                    }}
                    className="p-2.5 rounded-lg border border-[var(--border)] hover:bg-[var(--surface-2)]/60 cursor-pointer flex items-center justify-between transition-colors"
                  >
                    <div>
                      <div className="font-bold text-[var(--fg)]">{item.agent_id}</div>
                      <div className="text-[10px] text-[var(--muted)]">{item.profile?.role || "Autonomous Agent"}</div>
                    </div>
                    <span
                      className={`font-bold px-2 py-0.5 rounded text-[11px] ${
                        item.max_anomaly_score >= 70
                          ? "bg-rose-500/20 text-rose-400"
                          : item.max_anomaly_score >= 35
                          ? "bg-amber-500/20 text-amber-400"
                          : "bg-emerald-500/20 text-emerald-400"
                      }`}
                    >
                      {item.max_anomaly_score}
                    </span>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: LEARNED AGENT BASELINES */}
      {/* ========================================================================= */}
      {activeTab === "PROFILES" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
          {profiles.map((prof) => (
            <Card key={prof.agent_id} className="p-4 space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-[var(--border)]">
                <div>
                  <span className="font-bold text-sm text-[var(--fg)]">{prof.agent_id}</span>
                  <div className="text-[10px] text-[var(--muted)]">{prof.agent_name}</div>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Stable
                </span>
              </div>

              <div className="space-y-1.5 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-[var(--muted)]">Normal Amount:</span>
                  <span className="text-amber-400 font-bold">
                    ₹{prof.amount_min.toLocaleString()} – ₹{prof.amount_max.toLocaleString()}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--muted)]">Historical Mean (&mu; &plusmn; &sigma;):</span>
                  <span className="text-[var(--fg)]">
                    ₹{prof.amount_mean.toLocaleString()} &plusmn; ₹{prof.amount_std.toLocaleString()}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--muted)]">Daily Frequency:</span>
                  <span className="text-[var(--fg)]">{prof.daily_frequency_mean} txns/day</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--muted)]">Hourly Burst Cap:</span>
                  <span className="text-purple-400 font-bold">{prof.hourly_burst_threshold} txns/hr</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--muted)]">Schedule Window:</span>
                  <span className="text-[var(--fg)]">
                    {prof.schedule_start_hour}:00 – {prof.schedule_end_hour}:00 UTC
                  </span>
                </div>
              </div>

              <div>
                <span className="text-[10px] uppercase text-[var(--muted)] font-bold block mb-1">
                  Trusted Peer Destinations ({prof.known_destinations.length}):
                </span>
                <div className="flex flex-wrap gap-1">
                  {prof.known_destinations.map((dst) => (
                    <span
                      key={dst}
                      className="text-[9px] px-1.5 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)] text-cyan-300"
                    >
                      {dst}
                    </span>
                  ))}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: INTERACTIVE BEHAVIORAL SIMULATOR */}
      {/* ========================================================================= */}
      {activeTab === "SIMULATOR" && (
        <Card className="p-5 font-mono text-xs space-y-4 max-w-2xl">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
            <div>
              <h3 className="font-bold text-sm text-[var(--fg)] flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-amber-400" />
                <span>Synthetic Behavioral Request Generator</span>
              </h3>
              <p className="text-[11px] text-[var(--muted)] mt-0.5">
                Submit custom synthetic actions with varying velocity, amounts, and off-hour times to observe real-time UEBA scoring.
              </p>
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              customAnalyzeMutation.mutate({
                agent_id: simAgentId,
                action: simAction,
                resource: simResource,
                amount: simAmount,
                request_timestamp_iso: simTime,
                simulate_window_burst: simBurst,
              });
            }}
            className="space-y-4"
          >
            <div>
              <label className="block text-[var(--muted)] font-medium mb-1">Agent Identifier</label>
              <select
                value={simAgentId}
                onChange={(e) => setSimAgentId(e.target.value)}
                className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)]"
              >
                {profiles.map((p) => (
                  <option key={p.agent_id} value={p.agent_id}>
                    {p.agent_id} ({p.agent_name})
                  </option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[var(--muted)] font-medium mb-1">Action</label>
                <select
                  value={simAction}
                  onChange={(e) => setSimAction(e.target.value)}
                  className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)]"
                >
                  <option value="TRANSFER_FUNDS">TRANSFER_FUNDS</option>
                  <option value="CREATE_PURCHASE_ORDER">CREATE_PURCHASE_ORDER</option>
                  <option value="QUERY_BALANCE">QUERY_BALANCE</option>
                </select>
              </div>

              <div>
                <label className="block text-[var(--muted)] font-medium mb-1">Target Resource / Recipient</label>
                <input
                  type="text"
                  value={simResource}
                  onChange={(e) => setSimResource(e.target.value)}
                  placeholder="e.g. UNKNOWN-SHELL-CORP-999"
                  className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)]"
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[var(--muted)] font-medium mb-1">Transfer Amount (₹)</label>
                <input
                  type="number"
                  value={simAmount}
                  onChange={(e) => setSimAmount(Number(e.target.value))}
                  className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)]"
                  required
                />
              </div>

              <div>
                <label className="block text-[var(--muted)] font-medium mb-1">Burst Window Volume (txns)</label>
                <input
                  type="number"
                  value={simBurst}
                  onChange={(e) => setSimBurst(Number(e.target.value))}
                  className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)]"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-[var(--muted)] font-medium mb-1">Execution Timestamp (ISO)</label>
              <input
                type="text"
                value={simTime}
                onChange={(e) => setSimTime(e.target.value)}
                className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)]"
                required
              />
            </div>

            <Button
              type="submit"
              variant="emerald"
              disabled={customAnalyzeMutation.isPending}
              className="w-full h-10 font-bold gap-1.5"
            >
              {customAnalyzeMutation.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              <span>Analyze Against Behavioral Baseline</span>
            </Button>
          </form>
        </Card>
      )}
    </div>
  );
}

