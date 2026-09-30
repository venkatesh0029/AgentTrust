"use client";

import React, { useState } from "react";
import { PipelineStrip, DecisionPill, HashText } from "@/components/domain/components";
import { Card, Button } from "@/components/ui/primitives";
import { Cpu, Play, RefreshCw } from "lucide-react";
import { api, GatewaySubmitResponse } from "@/lib/api";

export default function GatewayPage() {
  const [agentId, setAgentId] = useState("FINANCE-AGENT-001");
  const [action, setAction] = useState("CREATE_PURCHASE_ORDER");
  const [resource, setResource] = useState("SUPPLIER-101");
  const [amount, setAmount] = useState(5000);

  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<GatewaySubmitResponse | null>(null);
  const [stoppedStage, setStoppedStage] = useState<number | undefined>(undefined);
  const [reasonCode, setReasonCode] = useState<string | undefined>(undefined);

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
      signature: "MEYCIQC...SIMULATED_RSA_PSS_SIGNATURE...",
    };

    try {
      const res = await api.submitAction(payload);
      setResult(res);

      const decision = (res.decision || "").toUpperCase();

      if (decision.includes("ALLOW") || decision.includes("COMMIT")) {
        setStoppedStage(13); // All 13 stages passed
        setReasonCode(undefined);
      } else if (decision.includes("PENDING") || decision.includes("APPROVAL")) {
        setStoppedStage(8); // Stopped at Stage 8 (Decision / Human Approval Ticket)
        setReasonCode(res.reason || "HELD_FOR_HUMAN_APPROVAL");
      } else {
        // Find specific stage failure based on reason
        const reason = res.reason || "";
        if (reason.includes("JSON") || reason.includes("FORMAT")) setStoppedStage(1);
        else if (reason.includes("CERT") || reason.includes("REVOKED")) setStoppedStage(2);
        else if (reason.includes("SIGNATURE")) setStoppedStage(3);
        else if (reason.includes("SUSPEND") || reason.includes("KEY")) setStoppedStage(4);
        else if (reason.includes("REPLAY") || reason.includes("NONCE")) setStoppedStage(5);
        else if (reason.includes("RISK")) setStoppedStage(6);
        else if (reason.includes("LIMIT") || reason.includes("POLICY") || reason.includes("EXCEEDED")) setStoppedStage(7);
        else setStoppedStage(7);

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

  return (
    <div className="space-y-6">
      
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <h1 className="text-xl font-bold text-[var(--fg)] tracking-tight">13-Stage Gateway Inspector</h1>
          <p className="text-xs text-[var(--muted)] mt-1">
            Submit signed AI agent requests and observe step-by-step pipeline evaluation across Identity, Policy, and Execution phases.
          </p>
        </div>
      </div>

      {/* Animated Pipeline Strip */}
      <PipelineStrip stoppedStage={stoppedStage} reasonCode={reasonCode} />

      {/* Request Simulation Form & Result Split */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left Form Box */}
        <Card>
          <div className="flex items-center gap-2 mb-4 pb-3 border-b border-[var(--border)]">
            <Cpu className="w-4 h-4 text-[var(--emerald)]" />
            <h3 className="font-semibold text-sm">Submit Signed Action Request</h3>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            <div>
              <label className="block text-[var(--muted)] font-medium mb-1">Agent Identifier</label>
              <select
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
                className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] font-mono focus:outline-none focus:border-[var(--emerald)]"
              >
                <option value="FINANCE-AGENT-001">FINANCE-AGENT-001 (Active, Limit ₹100k)</option>
                <option value="SUSPENDED-AGENT-002">SUSPENDED-AGENT-002 (Suspended Status)</option>
                <option value="REVOKED-AGENT-003">REVOKED-AGENT-003 (Revoked Cert)</option>
              </select>
            </div>

            <div>
              <label className="block text-[var(--muted)] font-medium mb-1">Target Action</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
                className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] font-mono focus:outline-none focus:border-[var(--emerald)]"
              >
                <option value="CREATE_PURCHASE_ORDER">CREATE_PURCHASE_ORDER (Limit ₹100,000)</option>
                <option value="TRANSFER_FUNDS">TRANSFER_FUNDS (Human Approval above ₹10,000)</option>
                <option value="DELETE_SYSTEM_LOGS">DELETE_SYSTEM_LOGS (Forbidden Action)</option>
              </select>
            </div>

            <div>
              <label className="block text-[var(--muted)] font-medium mb-1">Resource</label>
              <input
                type="text"
                value={resource}
                onChange={(e) => setResource(e.target.value)}
                className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] font-mono focus:outline-none focus:border-[var(--emerald)]"
              />
            </div>

            <div>
              <label className="block text-[var(--muted)] font-medium mb-1">Amount (₹)</label>
              <input
                type="number"
                value={amount}
                onChange={(e) => setAmount(Number(e.target.value))}
                className="w-full h-9 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 text-[var(--fg)] font-mono focus:outline-none focus:border-[var(--emerald)]"
              />
              <span className="text-[10px] text-[var(--subtle)] mt-1 block">
                Values &gt; ₹10,000 trigger Human Approval Ticket (Stage 8). Values &gt; ₹100,000 block at Policy Engine (Stage 7).
              </span>
            </div>

            <Button type="submit" variant="emerald" className="w-full mt-2" disabled={submitting}>
              {submitting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              <span>Process Request through Gateway</span>
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
            <div className="py-12 text-center text-xs text-[var(--muted)] font-mono">
              Fill the form and submit a request to see real-time pipeline execution details.
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
                <pre className="p-3 rounded-lg bg-[#060913] text-[var(--fg)] overflow-x-auto text-[11px] border border-[var(--border)]">
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
