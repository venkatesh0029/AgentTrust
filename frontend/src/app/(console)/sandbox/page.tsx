"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, Button, Badge } from "@/components/ui/primitives";
import { SandboxBanner } from "@/components/domain/components";
import { Flame, Settings2, ShieldAlert } from "lucide-react";

export default function SandboxPage() {
  const queryClient = useQueryClient();

  // Mode Switch State
  const [selectedMode, setSelectedMode] = useState("MODE_D_AGENTTRUST_FABRIC");
  const [modeFeedback, setModeFeedback] = useState<string | null>(null);

  // Chain Tamper State
  const [sequenceNum, setSequenceNum] = useState<number>(1);
  const [tamperField, setTamperField] = useState("decision");
  const [tamperValue, setTamperValue] = useState("FORGED_ALLOWED");
  const [chainTamperResult, setChainTamperResult] = useState<Record<string, unknown> | null>(null);

  // Evidence Tamper State
  const [evidenceId, setEvidenceId] = useState("REQ-PO-DEMO01");
  const [evField, setEvField] = useState("amount");
  const [evValue, setEvValue] = useState("999999.00");
  const [evTamperResult, setEvTamperResult] = useState<Record<string, unknown> | null>(null);

  const { data: modeData } = useQuery({
    queryKey: ["mode"],
    queryFn: () => api.fetchMode(),
  });

  const modeMutation = useMutation({
    mutationFn: (mode: string) => api.setMode(mode),
    onSuccess: (data) => {
      setModeFeedback(`Operational mode changed to '${data.current_mode}'.`);
      queryClient.invalidateQueries({ queryKey: ["mode"] });
      queryClient.invalidateQueries({ queryKey: ["health"] });
    },
    onError: (err: Error) => {
      setModeFeedback(`Error: ${err.message}`);
    }
  });

  const chainTamperMutation = useMutation({
    mutationFn: () => api.simulateChainTamper(sequenceNum, tamperField, tamperValue),
    onSuccess: (data) => {
      setChainTamperResult(data as Record<string, unknown>);
      queryClient.invalidateQueries({ queryKey: ["auditChain"] });
    },
    onError: (err: Error) => {
      setChainTamperResult({ error: err.message });
    }
  });

  const evidenceTamperMutation = useMutation({
    mutationFn: () => api.simulateEvidenceTamper(evidenceId, evField, evValue),
    onSuccess: (data) => {
      setEvTamperResult(data as Record<string, unknown>);
    },
    onError: (err: Error) => {
      setEvTamperResult({ error: err.message });
    }
  });

  return (
    <div className="space-y-6">
      {/* Prominent Sandbox Warning Banner */}
      <SandboxBanner />

      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[var(--fg)]">
              Sandbox & Tamper Testing Ground
            </h1>
            <Badge variant="outline" className="text-xs font-mono text-amber-400 border-amber-500/30">
              Isolated Testing
            </Badge>
          </div>
          <p className="text-sm text-[var(--muted)] mt-1">
            Simulate cryptographic integrity violations, inject tampered values, and test mode switching.
          </p>
        </div>
      </div>

      {/* Grid: 3 Sandbox Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 1. Operating Mode Switcher */}
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
            <h3 className="font-bold text-sm text-[var(--fg)] flex items-center gap-2">
              <Settings2 className="w-4 h-4 text-[var(--accent)]" />
              Runtime Mode Switcher
            </h3>
            <span className="font-mono text-xs text-[var(--accent)]">
              {modeData?.current_mode || "MODE_D"}
            </span>
          </div>

          <p className="text-xs text-[var(--muted)] leading-relaxed">
            Switch AgentTrust framework between standalone agent validation, policy enforcement, and Fabric ledger commit modes.
          </p>

          <div className="space-y-3 pt-2">
            <div>
              <label className="text-xs text-[var(--muted)] block mb-1">
                Select Framework Operational Mode
              </label>
              <select
                value={selectedMode}
                onChange={(e) => setSelectedMode(e.target.value)}
                className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--fg)] focus:outline-none focus:border-[var(--accent)]"
              >
                <option value="MODE_A_STANDALONE_AGENT">MODE_A_STANDALONE_AGENT (No Gateway)</option>
                <option value="MODE_B_IDENTITY_REPLAY">MODE_B_IDENTITY_REPLAY (Identity Only)</option>
                <option value="MODE_C_POLICY_RISK">MODE_C_POLICY_RISK (Policy & Risk)</option>
                <option value="MODE_D_AGENTTRUST_FABRIC">MODE_D_AGENTTRUST_FABRIC (Full 13-Stage)</option>
              </select>
            </div>

            <Button
              variant="primary"
              className="w-full"
              onClick={() => modeMutation.mutate(selectedMode)}
              disabled={modeMutation.isPending}
            >
              {modeMutation.isPending ? "Switching Mode..." : "Apply Mode Switch"}
            </Button>

            {modeFeedback && (
              <p className="text-xs font-mono p-2 rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--accent)] mt-2">
                {modeFeedback}
              </p>
            )}
          </div>
        </Card>

        {/* 2. Audit Chain Tamper Simulator */}
        <Card className="p-5 space-y-4 border-red-500/30">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
            <h3 className="font-bold text-sm text-[var(--fg)] flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Audit Chain Record Tamper
            </h3>
            <span className="font-mono text-[11px] text-red-400">
              SHA-256 Link Break
            </span>
          </div>

          <p className="text-xs text-[var(--muted)] leading-relaxed">
            Mutate a record in the in-memory audit chain sequence to trigger cryptographic chain verification failure.
          </p>

          <div className="space-y-3 pt-2">
            <div>
              <label className="text-xs text-[var(--muted)] block mb-1">
                Target Block Sequence #
              </label>
              <input
                type="number"
                value={sequenceNum}
                onChange={(e) => setSequenceNum(Number(e.target.value))}
                className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--fg)] focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">Field Name</label>
                <input
                  type="text"
                  value={tamperField}
                  onChange={(e) => setTamperField(e.target.value)}
                  className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-lg px-2.5 py-1.5 text-xs font-mono text-[var(--fg)]"
                />
              </div>
              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">New Value</label>
                <input
                  type="text"
                  value={tamperValue}
                  onChange={(e) => setTamperValue(e.target.value)}
                  className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-lg px-2.5 py-1.5 text-xs font-mono text-[var(--fg)]"
                />
              </div>
            </div>

            <Button
              variant="outline"
              className="w-full text-red-400 border-red-500/40 hover:bg-red-950/30"
              onClick={() => chainTamperMutation.mutate()}
              disabled={chainTamperMutation.isPending}
            >
              {chainTamperMutation.isPending ? "Injecting Tamper..." : "Simulate Chain Tamper"}
            </Button>

            {chainTamperResult && (
              <div className="p-2.5 rounded bg-red-950/20 border border-red-500/30 font-mono text-[11px] text-red-300 space-y-1">
                <div className="font-bold">
                  {chainTamperResult.error ? "Failed" : "Tamper Injected!"}
                </div>
                <div className="text-[10px] opacity-80">
                  {(chainTamperResult.message as string) || (chainTamperResult.error as string) || "Chain verification now fails."}
                </div>
              </div>
            )}
          </div>
        </Card>

        {/* 3. Off-Chain Evidence Tamper Simulator */}
        <Card className="p-5 space-y-4 border-amber-500/30">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
            <h3 className="font-bold text-sm text-[var(--fg)] flex items-center gap-2">
              <Flame className="w-4 h-4 text-amber-400" />
              Evidence Store Tamper
            </h3>
            <span className="font-mono text-[11px] text-amber-400">
              Digest Mismatch
            </span>
          </div>

          <p className="text-xs text-[var(--muted)] leading-relaxed">
            Modify off-chain evidence parameters to break SHA-256 digest matching against Fabric ledger commits.
          </p>

          <div className="space-y-3 pt-2">
            <div>
              <label className="text-xs text-[var(--muted)] block mb-1">
                Target Request / Evidence ID
              </label>
              <input
                type="text"
                value={evidenceId}
                onChange={(e) => setEvidenceId(e.target.value)}
                className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--fg)] focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">Field Name</label>
                <input
                  type="text"
                  value={evField}
                  onChange={(e) => setEvField(e.target.value)}
                  className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-lg px-2.5 py-1.5 text-xs font-mono text-[var(--fg)]"
                />
              </div>
              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">New Value</label>
                <input
                  type="text"
                  value={evValue}
                  onChange={(e) => setEvValue(e.target.value)}
                  className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-lg px-2.5 py-1.5 text-xs font-mono text-[var(--fg)]"
                />
              </div>
            </div>

            <Button
              variant="outline"
              className="w-full text-amber-400 border-amber-500/40 hover:bg-amber-950/30"
              onClick={() => evidenceTamperMutation.mutate()}
              disabled={evidenceTamperMutation.isPending}
            >
              {evidenceTamperMutation.isPending ? "Mutating Evidence..." : "Simulate Evidence Tamper"}
            </Button>

            {evTamperResult && (
              <div className="p-2.5 rounded bg-amber-950/20 border border-amber-500/30 font-mono text-[11px] text-amber-300 space-y-1">
                <div className="font-bold">
                  {evTamperResult.error ? "Failed" : "Evidence Tampered!"}
                </div>
                <div className="text-[10px] opacity-80">
                  {(evTamperResult.message as string) || (evTamperResult.error as string) || "Evidence digest now mismatches ledger."}
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
