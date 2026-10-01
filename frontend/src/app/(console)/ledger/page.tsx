"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, Button, Badge, Skeleton } from "@/components/ui/primitives";
import { DecisionPill, HashText, EmptyState } from "@/components/domain/components";
import { 
  ShieldCheck, 
  ShieldAlert, 
  RefreshCw, 
  Database, 
  Link as LinkIcon, 
  Search, 
  ArrowRight,
  Layers,
  Cpu
} from "lucide-react";

import { useRouter } from "next/navigation";

export default function LedgerPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{
    valid: boolean;
    status: string;
    verified_blocks: number;
    message?: string;
  } | null>(null);

  const { data: chain = [], isLoading: isLoadingChain, refetch: refetchChain } = useQuery({
    queryKey: ["auditChain"],
    queryFn: () => api.fetchAuditChain(),
    refetchInterval: 3000,
  });

  const { data: fabricStatus } = useQuery({
    queryKey: ["fabricStatus"],
    queryFn: () => api.fetchFabricStatus(),
  });

  const verifyMutation = useMutation({
    mutationFn: () => api.verifyChain(),
    onMutate: () => setVerifying(true),
    onSuccess: (data) => {
      setVerifyResult(data);
      setVerifying(false);
    },
    onError: (err: Error) => {
      setVerifyResult({
        valid: false,
        status: "VERIFICATION_ERROR",
        verified_blocks: 0,
        message: err.message || "Failed to verify chain integrity.",
      });
      setVerifying(false);
    }
  });

  const filteredChain = chain.filter((record) => {
    if (!search.trim()) return true;
    const query = search.toLowerCase();
    return (
      record.request_id.toLowerCase().includes(query) ||
      record.agent_id.toLowerCase().includes(query) ||
      record.event_type.toLowerCase().includes(query) ||
      record.record_hash.toLowerCase().includes(query)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[var(--fg)]">
              Ledger Explorer
            </h1>
            <Badge variant="outline" className="text-xs font-mono text-[var(--muted)]">
              Fabric Simulator
            </Badge>
          </div>
          <p className="text-sm text-[var(--muted)] mt-1">
            Hash-chained immutable audit log & Fabric-compatible permissioned block ledger.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              refetchChain();
              queryClient.invalidateQueries({ queryKey: ["fabricStatus"] });
            }}
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => verifyMutation.mutate()}
            disabled={verifying}
          >
            <ShieldCheck className="w-4 h-4 mr-2 text-[var(--accent-fg)]" />
            {verifying ? "Verifying Chain..." : "Verify Chain Integrity"}
          </Button>
        </div>
      </div>

      {/* Verification Banner Result */}
      {verifyResult && (
        <div
          className={`p-4 rounded-xl border flex items-start gap-3 transition-all ${
            verifyResult.valid
              ? "bg-emerald-950/20 border-emerald-500/30 text-emerald-400"
              : "bg-red-950/20 border-red-500/30 text-red-400"
          }`}
        >
          {verifyResult.valid ? (
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          )}
          <div className="flex-1 text-sm">
            <div className="font-semibold flex items-center justify-between">
              <span>
                {verifyResult.valid
                  ? "Audit Chain Integrity Verified"
                  : "Chain Tamper / Corruption Detected!"}
              </span>
              <span className="font-mono text-xs opacity-80">
                {verifyResult.verified_blocks} blocks verified
              </span>
            </div>
            <p className="text-xs opacity-90 mt-1">
              {verifyResult.message ||
                (verifyResult.valid
                  ? "All block cryptographic signatures (SHA-256) match their predecessor hash links."
                  : "Hash mismatch detected in chain sequence! The ledger has been tampered with.")}
            </p>
          </div>
          <button
            onClick={() => setVerifyResult(null)}
            className="text-xs opacity-60 hover:opacity-100"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Network Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4 space-y-1">
          <div className="flex items-center justify-between text-xs text-[var(--muted)]">
            <span>Total Blocks</span>
            <Layers className="w-4 h-4 text-[var(--muted)]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[var(--fg)]">
            {chain.length}
          </div>
          <div className="text-[11px] text-[var(--muted)]">
            Height: #{chain.length > 0 ? chain[chain.length - 1].sequence_number : 0}
          </div>
        </Card>

        <Card className="p-4 space-y-1">
          <div className="flex items-center justify-between text-xs text-[var(--muted)]">
            <span>Network Engine</span>
            <Cpu className="w-4 h-4 text-[var(--muted)]" />
          </div>
          <div className="text-sm font-semibold text-[var(--fg)] truncate">
            {fabricStatus?.network || "Fabric Simulator"}
          </div>
          <div className="text-[11px] text-[var(--muted)] truncate">
            {fabricStatus?.consensus || "In-Memory / SQLite"}
          </div>
        </Card>

        <Card className="p-4 space-y-1">
          <div className="flex items-center justify-between text-xs text-[var(--muted)]">
            <span>Chaincode Version</span>
            <Database className="w-4 h-4 text-[var(--muted)]" />
          </div>
          <div className="text-sm font-mono text-[var(--accent)] font-semibold">
            {fabricStatus?.chaincode || "agent_trust_cc:v2.0"}
          </div>
          <div className="text-[11px] text-[var(--muted)] truncate">
            Channel: {fabricStatus?.channel || "agenttrust-channel"}
          </div>
        </Card>

        <Card className="p-4 space-y-1">
          <div className="flex items-center justify-between text-xs text-[var(--muted)]">
            <span>Ledger Status</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-sm font-semibold text-emerald-400">
              {fabricStatus?.status || "HEALTHY"}
            </span>
          </div>
          <div className="text-[11px] text-[var(--muted)]">
            Zero-Trust Enforcement Active
          </div>
        </Card>
      </div>

      {/* Honest Mode Banner */}
      <div className="p-3 bg-[var(--surface-2)] border border-[var(--border)] rounded-xl flex items-center justify-between text-xs text-[var(--muted)]">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
          <span>
            <strong className="text-[var(--fg)]">Honest Ledger Architecture:</strong> Running local Fabric-compatible permissioned ledger simulator. All SHA-256 block hashes are calculated deterministically.
          </span>
        </div>
        <Link 
          href="/evidence" 
          className="text-[var(--accent)] hover:underline flex items-center gap-1 font-medium"
        >
          Inspect Evidence Storage <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Search Bar */}
      <div className="relative">
        <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
        <input
          type="text"
          placeholder="Filter audit blocks by Request ID, Agent ID, or Block Hash..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-xl pl-9 pr-4 py-2 text-sm text-[var(--fg)] placeholder:text-[var(--muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
        />
      </div>

      {/* Block Cards List */}
      <div className="space-y-4">
        {isLoadingChain ? (
          <div className="space-y-3">
            {[1, 2, 3].map((n) => (
              <Skeleton key={n} className="h-28 w-full rounded-xl" />
            ))}
          </div>
        ) : filteredChain.length === 0 ? (
          <EmptyState
            title="No Ledger Records Found"
            description={
              search
                ? "No blocks match your search query."
                : "Submit requests through the Gateway page to populate the ledger."
            }
            actionLabel="Go to Gateway"
            onAction={() => router.push("/gateway")}
          />
        ) : (
          filteredChain.slice().reverse().map((block, idx) => (
            <Card
              key={block.sequence_number || block.event_id || idx}
              className="p-4 transition-all hover:border-[var(--border-strong)] relative overflow-hidden"
            >
              {/* Card Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[var(--border)]/60">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-[var(--surface-2)] text-[var(--accent)] border border-[var(--border)]">
                    BLOCK #{block.sequence_number}
                  </span>
                  <span className="text-xs font-semibold text-[var(--fg)]">
                    {block.event_type || "ACTION_EXECUTION"}
                  </span>
                  <DecisionPill decision={block.decision} />
                </div>
                <div className="text-xs font-mono text-[var(--muted)]">
                  {block.timestamp}
                </div>
              </div>

              {/* Block Content Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-3 text-xs">
                <div>
                  <span className="text-[var(--muted)] block mb-1">Request ID</span>
                  <HashText value={block.request_id} />
                </div>

                <div>
                  <span className="text-[var(--muted)] block mb-1">Agent ID</span>
                  <span className="font-mono text-[var(--fg)]">{block.agent_id}</span>
                </div>

                <div>
                  <span className="text-[var(--muted)] block mb-1">Risk Score / Policy</span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[var(--fg)] font-semibold">
                      Risk: {block.risk_score}
                    </span>
                    <span className="text-[var(--muted)]">|</span>
                    <span className="font-mono text-[var(--muted)]">
                      v{block.policy_version}
                    </span>
                  </div>
                </div>
              </div>

              {/* Linked Hash Strip (prev_hash -> record_hash) */}
              <div className="mt-3 pt-3 border-t border-[var(--border)]/40 bg-[var(--bg)]/50 -mx-4 -mb-4 p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 font-mono text-[11px]">
                <div className="flex items-center gap-2 text-[var(--muted)] overflow-hidden">
                  <LinkIcon className="w-3.5 h-3.5 text-[var(--muted)] shrink-0" />
                  <span className="shrink-0 text-[var(--subtle)]">Prev:</span>
                  <HashText value={block.previous_record_hash} truncateLen={10} />
                </div>

                <div className="hidden sm:block text-[var(--subtle)]">
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>

                <div className="flex items-center gap-2 overflow-hidden">
                  <span className="shrink-0 text-[var(--subtle)]">Record Hash:</span>
                  <HashText value={block.record_hash} truncateLen={12} />
                </div>
              </div>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
