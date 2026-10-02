"use client";

import React, { useState, useEffect } from "react";
import { PipelineStrip, DecisionPill, HashText } from "@/components/domain/components";
import { Card, Button } from "@/components/ui/primitives";
import { Cpu, Play, RefreshCw, ShieldCheck, AlertTriangle, XCircle, CheckCircle2, Lock, Filter } from "lucide-react";
import { api, AgentRecord, PolicyRecord, GatewaySubmitResponse } from "@/lib/api";

interface ExtendedAgent {
  agent_id: string;
  agent_name: string;
  owner: string;
  organization: string;
  role: string;
  status: string;
  policy_id: string;
  capabilities: string[];
  max_limit: number;
  approval_above: number;
  category: "PASS_13_STAGES" | "HELD_APPROVAL" | "POLICY_EXCEEDED" | "SUSPENDED" | "REVOKED";
  recommended_action: string;
  recommended_amount: number;
  expected_outcome: string;
}

export default function GatewayPage() {
  const [agents, setAgents] = useState<ExtendedAgent[]>([]);
  const [loadingAgents, setLoadingAgents] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");

  const [agentId, setAgentId] = useState("FINANCE-AGENT-001");
  const [action, setAction] = useState("CREATE_PURCHASE_ORDER");
  const [resource, setResource] = useState("SUPPLIER-101");
  const [amount, setAmount] = useState(5000);

  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<GatewaySubmitResponse | null>(null);
  const [stoppedStage, setStoppedStage] = useState<number | undefined>(undefined);
  const [reasonCode, setReasonCode] = useState<string | undefined>(undefined);

  // Fetch all registered agents and policies on mount
  useEffect(() => {
    async function loadData() {
      try {
        setLoadingAgents(true);
        const [agentList, policyList] = await Promise.all([
          api.fetchAgents().catch(() => []),
          api.fetchPolicies().catch(() => [])
        ]);

        const policyMap = new Map<string, PolicyRecord>();
        policyList.forEach(p => policyMap.set(p.policy_id, p));

        const extendedList: ExtendedAgent[] = agentList.map(a => {
          const pol = policyMap.get(a.policy_id);
          const maxLimit = pol?.maximum_amount ?? 100000;
          const approvalAbove = pol?.human_approval_above ?? 10000;
          const caps = pol?.allowed_actions || ["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS", "CREATE_REIMBURSEMENT"];
          const status = (a.status || "ACTIVE").toUpperCase();

          let category: ExtendedAgent["category"] = "PASS_13_STAGES";
          let recAction = caps[0] || "CREATE_PURCHASE_ORDER";
          let recAmount = 5000;
          let expected = "Passes All 13 Stages (100% Valid)";

          if (status === "SUSPENDED") {
            category = "SUSPENDED";
            expected = "Blocked at Stage 4 (Agent Suspended)";
          } else if (status === "REVOKED") {
            category = "REVOKED";
            expected = "Blocked at Stage 2 (Certificate Revoked)";
          } else if (a.agent_id.includes("CAPEX") || a.agent_id.includes("MERGER") || a.agent_id.includes("BONUS") || a.agent_id.includes("EMERGENCY") || a.agent_id.includes("RESEARCH") || a.agent_id.includes("PARTNER") || a.agent_id.includes("SOFTWARE")) {
            category = "HELD_APPROVAL";
            recAmount = Math.min(maxLimit - 1000, approvalAbove + 5000);
            expected = "Held at Stage 8 (Human Approval Ticket)";
          } else if (a.agent_id.includes("STRICT") || a.agent_id.includes("MICRO") || a.agent_id.includes("INTERN") || a.agent_id.includes("TEMP") || a.agent_id.includes("RESTRICTED")) {
            category = "POLICY_EXCEEDED";
            recAmount = maxLimit + 10000;
            expected = "Blocked at Stage 7 (Policy Limit Exceeded)";
          } else {
            category = "PASS_13_STAGES";
            recAmount = Math.min(5000, approvalAbove - 500);
            expected = "Passes All 13 Stages (100% Valid)";
          }

          return {
            agent_id: a.agent_id,
            agent_name: a.agent_name || a.agent_id,
            owner: a.owner || "Enterprise Dept",
            organization: a.organization || "EnterpriseOrg",
            role: a.role || "autonomous_agent",
            status: status,
            policy_id: a.policy_id,
            capabilities: caps,
            max_limit: maxLimit,
            approval_above: approvalAbove,
            category: category,
            recommended_action: recAction,
            recommended_amount: recAmount,
            expected_outcome: expected
          };
        });

        setAgents(extendedList);

        if (extendedList.length > 0) {
          const first = extendedList[0];
          setAgentId(first.agent_id);
          setAction(first.recommended_action);
          setAmount(first.recommended_amount);
        }
      } catch (err) {
        console.error("Failed loading agents:", err);
      } finally {
        setLoadingAgents(false);
      }
    }

    loadData();
  }, []);

  // Sync selected agent's recommended parameters
  const handleAgentSelect = (selectedId: string) => {
    setAgentId(selectedId);
    const ag = agents.find(a => a.agent_id === selectedId);
    if (ag) {
      if (ag.capabilities.length > 0 && !ag.capabilities.includes(action)) {
        setAction(ag.capabilities[0]);
      }
      setAmount(ag.recommended_amount);
    }
  };

  const selectedAgent = agents.find(a => a.agent_id === agentId);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setResult(null);

    const reqId = `REQ-GW-${Math.random().toString(16).substring(2, 8).toUpperCase()}`;
    const nonce = `N-GW-${Math.random().toString(16).substring(2, 10).toUpperCase()}`;
    const timestamp = new Date().toISOString();

    const payload = {
      request_id: reqId,
      agent_id: agentId,
      action: action,
      resource: resource,
      amount: amount,
      parameters: {
        item_name: "Hardware Server Rack",
        quantity: 1,
        amount: amount,
        supplier_id: resource,
      },
      nonce: nonce,
      timestamp: timestamp,
      key_version: 1,
      signature: "AUTO_SIGN", // Backend auto-signs with RSA Private Key for demo agents
    };

    try {
      const res = await api.submitAction(payload);
      setResult(res);

      const decision = (res.decision || "").toUpperCase();
      const reason = (res.reason || "").toUpperCase();

      if (decision.includes("ALLOW") || decision.includes("COMMIT")) {
        setStoppedStage(13); // All 13 stages passed
        setReasonCode(undefined);
      } else if (decision.includes("PENDING") || decision.includes("APPROVAL") || reason.includes("APPROVAL")) {
        setStoppedStage(8); // Stopped at Stage 8 (Decision / Human Approval Ticket)
        setReasonCode(res.reason || "HELD_FOR_HUMAN_APPROVAL");
      } else if (reason.includes("REVOKED")) {
        setStoppedStage(2);
        setReasonCode(res.reason || "CERTIFICATE_REVOKED");
      } else if (reason.includes("SUSPEND")) {
        setStoppedStage(4);
        setReasonCode(res.reason || "AGENT_SUSPENDED");
      } else if (reason.includes("SIGNATURE")) {
        setStoppedStage(3);
        setReasonCode(res.reason || "INVALID_SIGNATURE");
      } else if (reason.includes("LIMIT") || reason.includes("POLICY") || reason.includes("EXCEEDED") || reason.includes("AUTHORITY")) {
        setStoppedStage(7);
        setReasonCode(res.reason || "AUTHORITY_LIMIT_EXCEEDED");
      } else {
        setStoppedStage(7);
        setReasonCode(res.reason || "POLICY_VIOLATION");
      }
    } catch (err: unknown) {
      const errMsg = (err as Error).message || "GATEWAY_ERROR";
      setStoppedStage(7);
      setReasonCode(errMsg);
      setResult({
        decision: "BLOCKED",
        reason: errMsg,
        protected_api_result: "NOT_EXECUTED",
      });
    } finally {
      setSubmitting(false);
    }
  };

  // Filter agents by category button
  const filteredAgents = agents.filter(a => {
    if (selectedCategory === "PASS_13_STAGES") return a.category === "PASS_13_STAGES";
    if (selectedCategory === "HELD_APPROVAL") return a.category === "HELD_APPROVAL";
    if (selectedCategory === "POLICY_EXCEEDED") return a.category === "POLICY_EXCEEDED";
    if (selectedCategory === "SUSPENDED_REVOKED") return a.category === "SUSPENDED" || a.category === "REVOKED";
    return true; // ALL
  });

  const countPass13 = agents.filter(a => a.category === "PASS_13_STAGES").length;
  const countHeld = agents.filter(a => a.category === "HELD_APPROVAL").length;
  const countExceeded = agents.filter(a => a.category === "POLICY_EXCEEDED").length;
  const countSuspendedRevoked = agents.filter(a => a.category === "SUSPENDED" || a.category === "REVOKED").length;

  return (
    <div className="space-y-6">
      
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <h1 className="text-xl font-bold text-[var(--fg)] tracking-tight flex items-center gap-2">
            <Cpu className="w-5 h-5 text-[var(--emerald)]" />
            13-Stage Gateway Inspector
          </h1>
          <p className="text-xs text-[var(--muted)] mt-1">
            Submit signed AI agent requests and observe step-by-step pipeline evaluation across Identity, Policy, and Execution phases.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono bg-[var(--surface-2)] px-3 py-1.5 rounded-lg border border-[var(--border)] text-[var(--emerald)]">
          <ShieldCheck className="w-4 h-4" />
          <span>{agents.length} Registered AI Agents Available</span>
        </div>
      </div>

      {/* Quick Category Filter Bar */}
      <div className="flex flex-wrap items-center gap-2 pb-2">
        <span className="text-xs text-[var(--muted)] font-mono flex items-center gap-1 mr-1">
          <Filter className="w-3.5 h-3.5" /> Filter Agents:
        </span>
        <button
          onClick={() => setSelectedCategory("ALL")}
          className={`px-3 py-1 rounded-full text-xs font-medium font-mono transition-colors ${
            selectedCategory === "ALL"
              ? "bg-[var(--emerald)] text-black font-bold"
              : "bg-[var(--surface-2)] text-[var(--muted)] hover:text-[var(--fg)] border border-[var(--border)]"
          }`}
        >
          All Agents ({agents.length})
        </button>
        <button
          onClick={() => setSelectedCategory("PASS_13_STAGES")}
          className={`px-3 py-1 rounded-full text-xs font-medium font-mono transition-colors ${
            selectedCategory === "PASS_13_STAGES"
              ? "bg-[var(--emerald)] text-black font-bold"
              : "bg-[var(--surface-2)] text-[var(--emerald)] hover:opacity-80 border border-[var(--emerald)]/30"
          }`}
        >
          ✅ 13-Stage Pass Valid ({countPass13})
        </button>
        <button
          onClick={() => setSelectedCategory("HELD_APPROVAL")}
          className={`px-3 py-1 rounded-full text-xs font-medium font-mono transition-colors ${
            selectedCategory === "HELD_APPROVAL"
              ? "bg-amber-500 text-black font-bold"
              : "bg-[var(--surface-2)] text-amber-400 hover:opacity-80 border border-amber-500/30"
          }`}
        >
          ⏳ Stage 8 Held Approval ({countHeld})
        </button>
        <button
          onClick={() => setSelectedCategory("POLICY_EXCEEDED")}
          className={`px-3 py-1 rounded-full text-xs font-medium font-mono transition-colors ${
            selectedCategory === "POLICY_EXCEEDED"
              ? "bg-rose-500 text-white font-bold"
              : "bg-[var(--surface-2)] text-rose-400 hover:opacity-80 border border-rose-500/30"
          }`}
        >
          🛑 Stage 7 Policy Exceeded ({countExceeded})
        </button>
        <button
          onClick={() => setSelectedCategory("SUSPENDED_REVOKED")}
          className={`px-3 py-1 rounded-full text-xs font-medium font-mono transition-colors ${
            selectedCategory === "SUSPENDED_REVOKED"
              ? "bg-purple-600 text-white font-bold"
              : "bg-[var(--surface-2)] text-purple-400 hover:opacity-80 border border-purple-500/30"
          }`}
        >
          🔒 Suspended / Revoked ({countSuspendedRevoked})
        </button>
      </div>

      {/* Animated Pipeline Strip */}
      <PipelineStrip stoppedStage={stoppedStage} reasonCode={reasonCode} />

      {/* Request Simulation Form & Result Split */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left Form Box */}
        <Card>
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[var(--emerald)]" />
              <h3 className="font-semibold text-sm">Submit Signed Action Request</h3>
            </div>
            {selectedAgent && (
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                selectedAgent.status === "ACTIVE" 
                  ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" 
                  : selectedAgent.status === "SUSPENDED" 
                  ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                  : "bg-rose-500/10 text-rose-400 border-rose-500/30"
              }`}>
                {selectedAgent.status}
              </span>
            )}
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            <div>
              <label className="block text-[var(--muted)] font-medium mb-1 flex justify-between">
                <span>Select Registered Agent Identifier ({filteredAgents.length})</span>
                {loadingAgents && <span className="text-[var(--emerald)] animate-pulse">Loading agents...</span>}
              </label>
              <select
                value={agentId}
                onChange={(e) => handleAgentSelect(e.target.value)}
                className="w-full h-10 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] font-mono focus:outline-none focus:border-[var(--emerald)] text-xs"
              >
                {filteredAgents.map(ag => (
                  <option key={ag.agent_id} value={ag.agent_id}>
                    {ag.status === "REVOKED" ? "🚫 " : ag.status === "SUSPENDED" ? "🔒 " : ag.category === "HELD_APPROVAL" ? "⏳ " : ag.category === "POLICY_EXCEEDED" ? "🛑 " : "🟢 "}
                    {ag.agent_id} | {ag.agent_name} ({ag.owner}) - Limit ₹{ag.max_limit.toLocaleString()}
                  </option>
                ))}
              </select>
            </div>

            {/* Selected Agent Security Profile Card */}
            {selectedAgent && (
              <div className="p-3 rounded-lg bg-[#060913] border border-[var(--border)] space-y-2 text-[11px]">
                <div className="flex justify-between items-center pb-1 border-b border-[var(--border)]/50">
                  <span className="font-semibold text-[var(--fg)] flex items-center gap-1.5 font-mono">
                    <ShieldCheck className="w-3.5 h-3.5 text-[var(--emerald)]" />
                    {selectedAgent.agent_name} ({selectedAgent.agent_id})
                  </span>
                  <span className="text-[10px] text-[var(--muted)]">{selectedAgent.owner}</span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                  <div>
                    <span className="text-[var(--muted)] block">Organization:</span>
                    <span className="text-[var(--fg)] font-semibold">{selectedAgent.organization}</span>
                  </div>
                  <div>
                    <span className="text-[var(--muted)] block">Policy ID:</span>
                    <span className="text-[var(--emerald)]">{selectedAgent.policy_id}</span>
                  </div>
                  <div>
                    <span className="text-[var(--muted)] block">Policy Max Limit:</span>
                    <span className="text-[var(--fg)]">₹{selectedAgent.max_limit.toLocaleString()}</span>
                  </div>
                  <div>
                    <span className="text-[var(--muted)] block">Human Approval Threshold:</span>
                    <span className="text-amber-400">&gt; ₹{selectedAgent.approval_above.toLocaleString()}</span>
                  </div>
                </div>

                <div className="pt-1.5 border-t border-[var(--border)]/50 flex items-center justify-between text-[10px]">
                  <span className="text-[var(--muted)]">Expected Pipeline Result:</span>
                  <span className={`font-mono font-semibold flex items-center gap-1 ${
                    selectedAgent.category === "PASS_13_STAGES" ? "text-[var(--emerald)]" :
                    selectedAgent.category === "HELD_APPROVAL" ? "text-amber-400" :
                    selectedAgent.category === "POLICY_EXCEEDED" ? "text-rose-400" : "text-purple-400"
                  }`}>
                    {selectedAgent.category === "PASS_13_STAGES" && <CheckCircle2 className="w-3 h-3" />}
                    {selectedAgent.category === "HELD_APPROVAL" && <AlertTriangle className="w-3 h-3" />}
                    {selectedAgent.category === "POLICY_EXCEEDED" && <XCircle className="w-3 h-3" />}
                    {(selectedAgent.category === "SUSPENDED" || selectedAgent.category === "REVOKED") && <Lock className="w-3 h-3" />}
                    {selectedAgent.expected_outcome}
                  </span>
                </div>
              </div>
            )}

            <div>
              <label className="block text-[var(--muted)] font-medium mb-1">Target Action</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
                className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] font-mono focus:outline-none focus:border-[var(--emerald)]"
              >
                {selectedAgent?.capabilities.map(cap => (
                  <option key={cap} value={cap}>{cap}</option>
                )) || (
                  <>
                    <option value="CREATE_PURCHASE_ORDER">CREATE_PURCHASE_ORDER</option>
                    <option value="TRANSFER_FUNDS">TRANSFER_FUNDS</option>
                    <option value="CREATE_REIMBURSEMENT">CREATE_REIMBURSEMENT</option>
                  </>
                )}
                <option value="DELETE_SYSTEM_LOGS">DELETE_SYSTEM_LOGS (Forbidden Action Rejection)</option>
              </select>
            </div>

            <div>
              <label className="block text-[var(--muted)] font-medium mb-1">Target Resource / Recipient</label>
              <input
                type="text"
                value={resource}
                onChange={(e) => setResource(e.target.value)}
                className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] font-mono focus:outline-none focus:border-[var(--emerald)]"
              />
            </div>

            <div>
              <label className="block text-[var(--muted)] font-medium mb-1">Requested Amount (₹)</label>
              <input
                type="number"
                value={amount}
                onChange={(e) => setAmount(Number(e.target.value))}
                className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] font-mono focus:outline-none focus:border-[var(--emerald)]"
              />
              <span className="text-[10px] text-[var(--subtle)] mt-1 block font-mono">
                Amounts &le; ₹{selectedAgent?.approval_above.toLocaleString() || "10,000"} pass all 13 stages. Amounts &gt; ₹{selectedAgent?.approval_above.toLocaleString() || "10,000"} trigger Stage 8 Human Approval.
              </span>
            </div>

            <Button type="submit" variant="emerald" className="w-full mt-2 h-10 text-xs font-mono font-bold" disabled={submitting}>
              {submitting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              <span>Process Request through 13-Stage Gateway</span>
            </Button>
          </form>
        </Card>

        {/* Right Result Outcome Box */}
        <Card>
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
            <h3 className="font-semibold text-sm">Pipeline Execution Result</h3>
            {result && <DecisionPill decision={result.decision} reason={result.reason} />}
          </div>

          {!result ? (
            <div className="py-16 text-center text-xs text-[var(--muted)] font-mono space-y-2">
              <Cpu className="w-8 h-8 mx-auto text-[var(--border)] animate-pulse" />
              <p>Select any registered agent from the dropdown and click Process Request to view step-by-step 13-stage evaluation.</p>
            </div>
          ) : (
            <div className="space-y-4 text-xs font-mono">
              <div className="p-3 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] space-y-2">
                <div className="flex justify-between">
                  <span className="text-[var(--muted)]">Decision:</span>
                  <span className="font-bold text-[var(--fg)]">{result.decision}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--muted)]">Reason Code:</span>
                  <span className="text-[var(--emerald)] font-semibold">{result.reason || "PASSED"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--muted)]">Protected API Execution:</span>
                  <span className="text-[var(--fg)]">{result.protected_api_result || "NOT_EXECUTED"}</span>
                </div>
                {result.evidence_id && (
                  <div className="flex justify-between items-center pt-2 border-t border-[var(--border)]">
                    <span className="text-[var(--muted)]">Evidence Reference:</span>
                    <HashText hash={result.evidence_id} />
                  </div>
                )}
              </div>

              <div>
                <span className="text-[var(--muted)] block mb-1">Raw Gateway Response Payload:</span>
                <pre className="p-3 rounded-lg bg-[#060913] text-[var(--fg)] overflow-x-auto text-[11px] border border-[var(--border)] max-h-72">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </Card>

      </div>

    </div>
  );
}
