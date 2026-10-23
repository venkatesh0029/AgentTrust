"use client";

import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, Button, Badge, Skeleton } from "@/components/ui/primitives";
import { DecisionPill, HashText, EmptyState } from "@/components/domain/components";
import { 
  FileCheck, 
  Search, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle,
  Clock,
  Fingerprint,
  FileCode,
  GitBranch,
  Network
} from "lucide-react";

export default function EvidencePage() {
  const [searchId, setSearchId] = useState("");
  const [activeEvidenceId, setActiveEvidenceId] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<Record<string, unknown> | null>(null);
  const [provenanceData, setProvenanceData] = useState<Record<string, unknown> | null>(null);
  const [provenanceError, setProvenanceError] = useState<string | null>(null);
  const [loadingProvenance, setLoadingProvenance] = useState(false);
  const [merkleProofData, setMerkleProofData] = useState<Record<string, unknown> | null>(null);
  const [merkleProofError, setMerkleProofError] = useState<string | null>(null);
  const [loadingMerkleProof, setLoadingMerkleProof] = useState(false);
  const [merkleVerification, setMerkleVerification] = useState<Record<string, unknown> | null>(null);
  const [verifyingMerkleProof, setVerifyingMerkleProof] = useState(false);

  const { data: chain = [], isLoading: isLoadingChain } = useQuery({
    queryKey: ["auditChain"],
    queryFn: () => api.fetchAuditChain(),
    refetchInterval: 3000,
  });

  const {
    data: evidenceData,
    isLoading: isLoadingEvidence,
    error: evidenceError,
  } = useQuery({
    queryKey: ["evidence", activeEvidenceId],
    queryFn: () => (activeEvidenceId ? api.fetchEvidence(activeEvidenceId) : null),
    enabled: !!activeEvidenceId,
  });

  const verifyMutation = useMutation({
    mutationFn: (id: string) => api.verifyEvidence(id),
    onSuccess: (data) => {
      setVerificationResult(data as Record<string, unknown>);
    },
    onError: (err: Error) => {
      setVerificationResult({
        verified: false,
        status: "VERIFICATION_FAILED",
        detail: err.message || "Failed to verify evidence digest.",
      });
    },
  });

  const normalizeRequestId = (identifier: string) =>
    identifier.startsWith("EVIDENCE-") ? identifier.slice("EVIDENCE-".length) : identifier;

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchId.trim()) {
      setActiveEvidenceId(searchId.trim());
      setVerificationResult(null);
      setProvenanceData(null);
      setProvenanceError(null);
      setMerkleProofData(null);
      setMerkleProofError(null);
      setMerkleVerification(null);
    }
  };

  const handleSelectRecord = (reqId: string) => {
    setActiveEvidenceId(reqId);
    setSearchId(reqId);
    setVerificationResult(null);
    setProvenanceData(null);
    setProvenanceError(null);
    setMerkleProofData(null);
    setMerkleProofError(null);
    setMerkleVerification(null);
  };

  const handleLoadProvenance = async () => {
    if (!activeEvidenceId) return;
    const requestId = normalizeRequestId(activeEvidenceId);
    if (!chain.some((record) => record.request_id === requestId)) {
      setProvenanceData(null);
      setProvenanceError(
        "This request ID is not present in the loaded audit chain. The backend can synthesize fallback provenance for missing records, so the UI did not request or display a fallback as authoritative evidence."
      );
      return;
    }

    setLoadingProvenance(true);
    setProvenanceError(null);
    try {
      const data = await api.fetchEvidenceProvenance(requestId);
      setProvenanceData(data as Record<string, unknown>);
    } catch (err: unknown) {
      setProvenanceError(err instanceof Error ? err.message : "Failed to load provenance");
    } finally {
      setLoadingProvenance(false);
    }
  };

  const handleLoadMerkleProof = async () => {
    if (!activeEvidenceId) return;
    const requestId = normalizeRequestId(activeEvidenceId);
    if (!chain.some((record) => record.request_id === requestId)) {
      setMerkleProofData(null);
      setMerkleProofError(
        "This request ID is not present in the loaded audit chain. The backend can generate fallback proofs for missing records, so the UI did not request or display a fallback as authoritative evidence."
      );
      return;
    }

    setLoadingMerkleProof(true);
    setMerkleProofError(null);
    setMerkleVerification(null);
    try {
      const data = await api.fetchMerkleProof(requestId);
      setMerkleProofData(data as Record<string, unknown>);
    } catch (err: unknown) {
      setMerkleProofError(err instanceof Error ? err.message : "Failed to load Merkle proof");
    } finally {
      setLoadingMerkleProof(false);
    }
  };

  const handleVerifyMerkleProof = async () => {
    if (!merkleProofData) return;
    setVerifyingMerkleProof(true);
    try {
      const data = await api.verifyMerkleProof({
        leaf_hash: merkleProofData.leaf_hash,
        proof: merkleProofData.proof,
        merkle_root: merkleProofData.merkle_root,
      });
      setMerkleVerification(data as Record<string, unknown>);
    } catch (err: unknown) {
      setMerkleVerification({
        is_valid: false,
        error: err instanceof Error ? err.message : "Merkle verification failed",
      });
    } finally {
      setVerifyingMerkleProof(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[var(--fg)]">
              SHA-256 Evidence Inspector
            </h1>
            <Badge variant="outline" className="text-xs font-mono text-[var(--muted)]">
              Cryptographic Proof
            </Badge>
          </div>
          <p className="text-sm text-[var(--muted)] mt-1">
            Verify off-chain execution evidence digests against Fabric-compatible ledger state commits.
          </p>
        </div>
      </div>

      {/* Search Input Box */}
      <Card className="p-4">
        <form onSubmit={handleSearchSubmit} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
            <input
              type="text"
              placeholder="Enter Request ID or Evidence ID (e.g. REQ-PO-a1b2c3)..."
              value={searchId}
              onChange={(e) => setSearchId(e.target.value)}
              className="w-full bg-[var(--surface-1)] border border-[var(--border)] rounded-xl pl-9 pr-4 py-2.5 text-sm text-[var(--fg)] placeholder:text-[var(--muted)] focus:outline-none focus:border-[var(--accent)] font-mono transition-colors"
            />
          </div>
          <Button type="submit" variant="primary" className="shrink-0">
            <FileCheck className="w-4 h-4 mr-2" />
            Inspect Evidence
          </Button>
        </form>

        {/* Quick Select Chips from Audit Log */}
        {chain.length > 0 && (
          <div className="mt-3 pt-3 border-t border-[var(--border)]/50 flex items-center gap-2 flex-wrap text-xs">
            <span className="text-[var(--muted)] shrink-0">Recent Requests:</span>
            {chain.slice(-5).reverse().map((rec, idx) => (
              <button
                key={`${rec.request_id || 'ev'}-${idx}`}
                onClick={() => handleSelectRecord(rec.request_id)}
                className={`font-mono px-2 py-0.5 rounded border transition-colors ${
                  activeEvidenceId === rec.request_id
                    ? "bg-[var(--accent)]/15 border-[var(--accent)] text-[var(--accent)]"
                    : "bg-[var(--surface-2)] border-[var(--border)] text-[var(--muted)] hover:text-[var(--fg)] hover:border-[var(--border-strong)]"
                }`}
              >
                {rec.request_id}
              </button>
            ))}
          </div>
        )}
      </Card>

      {/* Main Grid Display */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Side: Recent Requests List */}
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-[var(--fg)] flex items-center gap-2">
            <Clock className="w-4 h-4 text-[var(--muted)]" />
            Audit Ledger Evidence Index
          </h2>
          <Card className="p-2 space-y-1 max-h-[500px] overflow-y-auto">
            {isLoadingChain ? (
              <div className="space-y-2 p-2">
                {[1, 2, 3, 4].map((n) => (
                  <Skeleton key={n} className="h-14 w-full rounded-lg" />
                ))}
              </div>
            ) : chain.length === 0 ? (
              <p className="text-xs text-[var(--muted)] text-center py-6">
                No audit records found.
              </p>
            ) : (
              chain.slice().reverse().map((rec, idx) => (
                <div
                  key={`${rec.request_id || 'ev'}-${idx}`}
                  onClick={() => handleSelectRecord(rec.request_id)}
                  className={`p-2.5 rounded-lg border text-xs cursor-pointer transition-all ${
                    activeEvidenceId === rec.request_id
                      ? "bg-[var(--surface-2)] border-[var(--accent)] shadow-sm"
                      : "bg-transparent border-transparent hover:bg-[var(--surface-2)]/50 hover:border-[var(--border)]"
                  }`}
                >
                  <div className="flex items-center justify-between font-mono font-medium">
                    <span className="text-[var(--fg)]">{rec.request_id}</span>
                    <DecisionPill decision={rec.decision} />
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-[var(--muted)] mt-1 font-mono">
                    <span>{rec.agent_id}</span>
                    <span>Risk: {rec.risk_score}</span>
                  </div>
                </div>
              ))
            )}
          </Card>
        </div>

        {/* Right Side: Active Evidence Details & Verification */}
        <div className="lg:col-span-2 space-y-4">
          {!activeEvidenceId ? (
            <EmptyState
              title="Select or Search an Evidence Record"
              description="Click on any request ID from the index or type a Request ID above to inspect its cryptographic digest."
            />
          ) : isLoadingEvidence ? (
            <Skeleton className="h-96 w-full rounded-xl" />
          ) : evidenceError || !evidenceData ? (
            <Card className="p-6 text-center space-y-3">
              <ShieldAlert className="w-10 h-10 text-red-400 mx-auto" />
              <h3 className="text-base font-semibold text-[var(--fg)]">
                Evidence Record Not Found
              </h3>
              <p className="text-xs text-[var(--muted)] max-w-md mx-auto">
                No off-chain evidence record exists for ID &quot;{activeEvidenceId}&quot;. Verify the request ID or submit a request via Gateway.
              </p>
            </Card>
          ) : (
            <div className="space-y-4">
              {/* Verification Result Banner */}
              {verificationResult && (() => {
                const vRes = verificationResult as {
                  verified?: boolean;
                  detail?: string;
                  verification_result?: { verified?: boolean; message?: string };
                };
                const isValid = vRes.verification_result?.verified !== false && vRes.verified !== false;
                const msg = vRes.verification_result?.message || vRes.detail || "Calculated off-chain SHA-256 hash matches the ledger state commitment.";
                
                return (
                  <div
                    className={`p-4 rounded-xl border flex items-start gap-3 transition-all ${
                      isValid
                        ? "bg-emerald-950/20 border-emerald-500/30 text-emerald-400"
                        : "bg-red-950/20 border-red-500/30 text-red-400"
                    }`}
                  >
                    {isValid ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                      <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1 text-sm">
                      <div className="font-semibold flex items-center justify-between">
                        <span>
                          {isValid
                            ? "Cryptographic Digest Match (VALID)"
                            : "Digest Mismatch Detected (TAMPERED)"}
                        </span>
                      </div>
                      <p className="text-xs opacity-90 mt-1">{msg}</p>
                    </div>
                  </div>
                );
              })()}

              {/* Evidence Inspector Card */}
              <Card className="p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border)]">
                  <div>
                    <span className="text-xs text-[var(--muted)]">Evidence Record</span>
                    <h3 className="text-lg font-bold font-mono text-[var(--fg)]">
                      {evidenceData.evidence_id || activeEvidenceId}
                    </h3>
                  </div>
                  <div className="flex items-center gap-3">
                    {evidenceData.decision && (
                      <DecisionPill decision={evidenceData.decision} />
                    )}
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => verifyMutation.mutate(activeEvidenceId)}
                      disabled={verifyMutation.isPending}
                    >
                      <ShieldCheck className="w-4 h-4 mr-1.5" />
                      {verifyMutation.isPending ? "Verifying..." : "Verify Digest"}
                    </Button>
                  </div>
                </div>

                {/* Metadata Fields */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div>
                    <span className="text-[var(--muted)] block mb-1">Agent Identity</span>
                    <span className="font-mono text-[var(--fg)] font-semibold">
                      {evidenceData.agent_id || "N/A"}
                    </span>
                  </div>

                  <div>
                    <span className="text-[var(--muted)] block mb-1">Target Action</span>
                    <span className="font-mono text-[var(--accent)] font-semibold">
                      {evidenceData.action || "N/A"}
                    </span>
                  </div>

                  <div>
                    <span className="text-[var(--muted)] block mb-1">Target Resource</span>
                    <span className="font-mono text-[var(--fg)]">
                      {evidenceData.resource || "*"}
                    </span>
                  </div>

                  <div>
                    <span className="text-[var(--muted)] block mb-1">Policy & Risk Score</span>
                    <span className="font-mono text-[var(--fg)]">
                      {evidenceData.policy_id || "FIN-POLICY-001"} (Risk Score: {evidenceData.risk_score ?? 0})
                    </span>
                  </div>
                </div>

                {/* Hashes Section */}
                <div className="space-y-3 pt-3 border-t border-[var(--border)]">
                  <div>
                    <span className="text-xs text-[var(--muted)] block mb-1 font-mono">
                      Input Payload SHA-256 Digest
                    </span>
                    <div className="p-2.5 rounded-lg bg-[var(--bg)] border border-[var(--border)] font-mono text-xs">
                      <HashText value={evidenceData.input_hash || "N/A"} truncateLen={32} />
                    </div>
                  </div>

                  <div>
                    <span className="text-xs text-[var(--muted)] block mb-1 font-mono">
                      Off-Chain Record SHA-256 Hash
                    </span>
                    <div className="p-2.5 rounded-lg bg-[var(--bg)] border border-[var(--border)] font-mono text-xs">
                      <HashText value={evidenceData.record_hash || "N/A"} truncateLen={32} />
                    </div>
                  </div>

                  {evidenceData.certificate_fingerprint && (
                    <div>
                      <span className="text-xs text-[var(--muted)] block mb-1 flex items-center gap-1">
                        <Fingerprint className="w-3.5 h-3.5 text-[var(--muted)]" />
                        X.509 Certificate Fingerprint
                      </span>
                      <div className="p-2.5 rounded-lg bg-[var(--bg)] border border-[var(--border)] font-mono text-xs text-[var(--muted)]">
                        {evidenceData.certificate_fingerprint}
                      </div>
                    </div>
                  )}
                </div>

                {/* Parameters Payload */}
                {evidenceData.parameters && (
                  <div className="pt-3 border-t border-[var(--border)] space-y-1">
                    <span className="text-xs text-[var(--muted)] flex items-center gap-1">
                      <FileCode className="w-3.5 h-3.5 text-[var(--muted)]" />
                      Execution Parameters JSON
                    </span>
                    <pre className="p-3 rounded-lg bg-[var(--bg)] border border-[var(--border)] font-mono text-xs text-[var(--fg)] overflow-x-auto">
                      {JSON.stringify(evidenceData.parameters, null, 2)}
                    </pre>
                  </div>
                )}
              </Card>

              {/* Evidence Provenance & Lineage Panel */}
              <Card className="p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border)]">
                  <div className="flex items-center gap-2">
                    <GitBranch className="w-4 h-4 text-[var(--accent)]" />
                    <div>
                      <h3 className="font-bold text-sm text-[var(--fg)]">
                        Evidence Provenance & Cryptographic Lineage
                      </h3>
                      <p className="text-[11px] text-[var(--muted)]">
                        Inspect chronological causal lineage, policy metadata, and signing provenance.
                      </p>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleLoadProvenance}
                    disabled={loadingProvenance}
                  >
                    {loadingProvenance ? "Retrieving Lineage..." : "Inspect Lineage"}
                  </Button>
                </div>

                {provenanceError && (
                  <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-950/20 text-amber-300 text-xs">
                    {provenanceError}
                  </div>
                )}

                {provenanceData && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                      <div className="p-2.5 rounded-lg bg-[var(--bg)] border border-[var(--border)] font-mono">
                        <span className="text-[var(--muted)] block text-[10px]">Origin Agent</span>
                        <span className="text-[var(--fg)] font-semibold">
                          {String(provenanceData.origin_agent || provenanceData.agent_id || "N/A")}
                        </span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[var(--bg)] border border-[var(--border)] font-mono">
                        <span className="text-[var(--muted)] block text-[10px]">Signing Algorithm</span>
                        <span className="text-[var(--accent)] font-semibold">
                          {String(provenanceData.signing_algorithm || "SHA256withRSA")}
                        </span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[var(--bg)] border border-[var(--border)] font-mono">
                        <span className="text-[var(--muted)] block text-[10px]">Policy Reference</span>
                        <span className="text-[var(--fg)]">
                          {String(provenanceData.policy_id || "FIN-POL-001")}
                        </span>
                      </div>
                    </div>

                    <div className="pt-2">
                      <span className="text-xs text-[var(--muted)] block mb-1 font-mono">
                        Raw Provenance Attestation Record
                      </span>
                      <pre className="p-3 rounded-lg bg-[var(--bg)] border border-[var(--border)] font-mono text-xs text-[var(--fg)] overflow-x-auto">
                        {JSON.stringify(provenanceData, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </Card>

              {/* Merkle Tree Inclusion Proof Panel */}
              <Card className="p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border)]">
                  <div className="flex items-center gap-2">
                    <Network className="w-4 h-4 text-emerald-400" />
                    <div>
                      <h3 className="font-bold text-sm text-[var(--fg)]">
                        Merkle Tree Inclusion Proof
                      </h3>
                      <p className="text-[11px] text-[var(--muted)]">
                        Cryptographic tree inclusion path proving evidence presence in ledger root hash.
                      </p>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleLoadMerkleProof}
                    disabled={loadingMerkleProof}
                  >
                    {loadingMerkleProof ? "Building Proof..." : "Build Merkle Proof"}
                  </Button>
                </div>

                {merkleProofError && (
                  <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-950/20 text-amber-300 text-xs">
                    {merkleProofError}
                  </div>
                )}

                {merkleProofData && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="p-3 rounded-lg bg-[var(--bg)] border border-[var(--border)] space-y-1">
                        <span className="text-[var(--muted)] text-[10px] font-mono block">Leaf Event Hash</span>
                        <HashText value={String(merkleProofData.leaf_hash || "N/A")} truncateLen={20} />
                      </div>
                      <div className="p-3 rounded-lg bg-[var(--bg)] border border-[var(--border)] space-y-1">
                        <span className="text-[var(--muted)] text-[10px] font-mono block">Merkle Root Hash</span>
                        <HashText value={String(merkleProofData.merkle_root || "N/A")} truncateLen={20} />
                      </div>
                    </div>

                    {/* Proof Steps Path */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-[var(--muted)] font-mono">
                          Proof Path (Sibling Hashes: {Array.isArray(merkleProofData.proof) ? merkleProofData.proof.length : 0})
                        </span>
                        <Button
                          variant="primary"
                          size="sm"
                          onClick={handleVerifyMerkleProof}
                          disabled={verifyingMerkleProof}
                        >
                          <ShieldCheck className="w-4 h-4 mr-1.5" />
                          {verifyingMerkleProof ? "Verifying..." : "Verify Inclusion Proof"}
                        </Button>
                      </div>

                      {Array.isArray(merkleProofData.proof) && merkleProofData.proof.length > 0 ? (
                        <div className="space-y-1.5 max-h-40 overflow-y-auto">
                          {merkleProofData.proof.map((step: unknown, idx: number) => {
                            const hashStr = typeof step === "string" ? step : JSON.stringify(step);
                            return (
                              <div
                                key={idx}
                                className="flex items-center gap-2 p-2 rounded bg-[var(--bg)] border border-[var(--border)] font-mono text-[11px]"
                              >
                                <span className="text-[var(--muted)] w-6 shrink-0">#{idx + 1}</span>
                                <HashText value={hashStr} truncateLen={24} />
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <p className="text-xs text-[var(--muted)] italic">
                          Proof path contains direct root binding.
                        </p>
                      )}
                    </div>

                    {/* Merkle Verification Outcome Banner */}
                    {merkleVerification && (
                      <div
                        className={`p-4 rounded-xl border flex items-start gap-3 text-xs ${
                          merkleVerification.is_valid
                            ? "bg-emerald-950/20 border-emerald-500/30 text-emerald-400"
                            : "bg-red-950/20 border-red-500/30 text-red-400"
                        }`}
                      >
                        {merkleVerification.is_valid ? (
                          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                        ) : (
                          <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                        )}
                        <div>
                          <div className="font-semibold text-sm">
                            {merkleVerification.is_valid
                              ? "Inclusion Proof Mathematically Verified (VALID)"
                              : "Inclusion Proof Verification Failed"}
                          </div>
                          <p className="opacity-90 mt-0.5">
                            {merkleVerification.is_valid
                              ? "The evidence leaf hash resolves to the audit-tree Merkle root through the computed sibling proof path. Note: this verifies mathematical tree inclusion within the audit tree and does not independently prove live Fabric peer connectivity."
                              : String(merkleVerification.error || "The leaf hash could not be mathematically bound to the supplied Merkle root.")}
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
