import { z } from "zod";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

// --- ZOD SCHEMAS FOR STRICT BACKEND VALIDATION ---

export const HealthSchema = z.object({
  status: z.string().default("ONLINE"),
  system: z.string().default("AgentTrust Framework"),
  current_mode: z.string().default("MODE_D_AGENTTRUST_FABRIC"),
  timestamp: z.string().default(""),
});

export const ModeSchema = z.object({
  current_mode: z.string().default("MODE_D_AGENTTRUST_FABRIC"),
  available_modes: z.array(z.string()).default([]),
});

export const AgentRecordSchema = z.object({
  agent_id: z.string(),
  agent_name: z.string().default(""),
  owner: z.string().default(""),
  status: z.string().default("ACTIVE"),
  policy_id: z.string().default("FIN-POLICY-001"),
  agent_version: z.string().default("1.0"),
  organization: z.string().default("FinanceOrg"),
  role: z.string().default("procurement_agent"),
  key_version: z.number().default(1),
  certificate_fingerprint: z.string().nullable().optional(),
  certificate: z.string().nullable().optional(),
  public_key: z.string().nullable().optional(),
  created_at: z.string().nullable().optional(),
});

export const AgentsListSchema = z.object({
  agents: z.array(AgentRecordSchema).default([]),
});

export const WorkingHoursSchema = z.object({
  start: z.string().default("00:00"),
  end: z.string().default("23:59"),
});

export const PolicyRecordSchema = z.object({
  policy_id: z.string(),
  agent_id: z.string().default("*"),
  allowed_actions: z.array(z.string()).default([]),
  allowed_resource: z.string().default("*"),
  maximum_amount: z.number().default(0),
  human_approval_above: z.number().default(0),
  working_hours: WorkingHoursSchema.nullable().optional(),
  version: z.string().default("1.0"),
  status: z.string().default("ACTIVE"),
  updated_at: z.string().nullable().optional(),
  updated_by: z.string().nullable().optional(),
  change_reason: z.string().nullable().optional(),
});

export const PoliciesListSchema = z.object({
  policies: z.array(PolicyRecordSchema).default([]),
});

export const ApprovalTicketSchema = z.object({
  approval_id: z.string(),
  request_id: z.string(),
  agent_id: z.string(),
  action: z.string(),
  resource: z.string().default("*"),
  parameters: z.record(z.string(), z.unknown()).default({}),
  reason: z.string().default("PENDING"),
  policy_id: z.string().default("FIN-POLICY-001"),
  policy_version: z.string().nullable().optional(),
  approval_token: z.string().nullable().optional(),
  delegation_token: z.unknown().nullable().optional(),
  authorization_context: z.record(z.string(), z.unknown()).nullable().optional(),
  expires_at: z.string().nullable().optional(),
  created_at: z.string().nullable().optional(),
  approver_id: z.string().nullable().optional(),
  decision_timestamp: z.string().nullable().optional(),
  rejection_reason: z.string().nullable().optional(),
  approval_reference: z.string().nullable().optional(),
  status: z.string().default("PENDING"),
});

export const PendingApprovalsSchema = z.object({
  pending_approvals: z.array(ApprovalTicketSchema).default([]),
});

export const AuditRecordSchema = z.object({
  sequence_number: z.number(),
  timestamp: z.string(),
  event_type: z.string(),
  request_id: z.string(),
  agent_id: z.string(),
  request_hash: z.string().default(""),
  risk_score: z.number().default(0),
  policy_version: z.string().default("1.0"),
  decision: z.string(),
  execution_result: z.string().default(""),
  event_id: z.string(),
  previous_record_hash: z.string().default("GENESIS_HASH_0000000000000000"),
  record_hash: z.string().default(""),
});

export const AuditChainSchema = z.object({
  chain: z.array(AuditRecordSchema).default([]),
});

export const ChainVerifySchema = z.object({
  valid: z.boolean(),
  status: z.string().optional(),
  total_records: z.number().optional(),
  verified_blocks: z.number().optional(),
  reason: z.string().nullable().optional(),
  message: z.string().nullable().optional(),
  tampered_sequence: z.number().optional(),
  event_id: z.string().optional(),
  latest_record_hash: z.string().optional(),
});

export const EvidenceRecordSchema = z.object({
  evidence_id: z.string().nullable().optional(),
  request_id: z.string().nullable().optional(),
  agent_id: z.string().nullable().optional(),
  action: z.string().nullable().optional(),
  resource: z.string().nullable().optional(),
  parameters: z.record(z.string(), z.unknown()).nullable().optional(),
  decision: z.string().nullable().optional(),
  reason: z.string().nullable().optional(),
  policy_id: z.string().nullable().optional(),
  input_hash: z.string().nullable().optional(),
  record_hash: z.string().nullable().optional(),
  risk_score: z.number().nullable().optional(),
  certificate_fingerprint: z.string().nullable().optional(),
  timestamp: z.string().nullable().optional(),
});

export const FabricStatusSchema = z.object({
  network: z.string().default("Fabric-Compatible Permissioned Ledger Simulator"),
  channel: z.string().default("agenttrust-channel"),
  chaincode: z.string().default("agent_trust_cc:v2.0"),
  consensus: z.string().default("In-Memory / SQLite Persistent Ledger Simulator"),
  status: z.string().default("HEALTHY"),
  msps: z.record(z.string(), z.unknown()).nullable().optional(),
  peers: z.array(z.unknown()).nullable().optional(),
  orderers: z.array(z.unknown()).nullable().optional(),
  ledger_summary: z.object({
    latest_block_number: z.number().default(0),
    total_blocks: z.number().default(1),
    latest_tx_id: z.string().default("tx-genesis-000"),
    validation_code: z.string().default("VALID"),
  }).nullable().optional(),
});

export const AttackScenarioSchema = z.object({
  scenario_id: z.number(),
  title: z.string(),
  expected: z.string().default("BLOCKED"),
  actual: z.string().nullable().optional(),
  status: z.string().default("UNKNOWN"),
  error: z.string().nullable().optional(),
});

export const AttackMatrixRunSchema = z.object({
  summary: z.object({
    total: z.number().default(20),
    passed: z.number().default(0),
    failed: z.number().default(0),
    pass_rate: z.string().default("0.0%"),
  }),
  details: z.array(AttackScenarioSchema).default([]),
});

export const GatewaySubmitResponseSchema = z.object({
  request_id: z.string().nullable().optional(),
  agent_id: z.string().nullable().optional(),
  action: z.string().nullable().optional(),
  decision: z.string(),
  reason: z.string().default(""),
  protected_api_result: z.string().nullable().optional(),
  evidence_id: z.string().nullable().optional(),
  risk_score: z.number().nullable().optional(),
  mode: z.string().nullable().optional(),
});

// TYPES EXPORTED FROM SCHEMAS
export type HealthData = z.infer<typeof HealthSchema>;
export type ModeData = z.infer<typeof ModeSchema>;
export type AgentRecord = z.infer<typeof AgentRecordSchema>;
export type PolicyRecord = z.infer<typeof PolicyRecordSchema>;
export type ApprovalTicket = z.infer<typeof ApprovalTicketSchema>;
export type AuditRecord = z.infer<typeof AuditRecordSchema>;
export type ChainVerifyData = z.infer<typeof ChainVerifySchema>;
export type EvidenceRecord = z.infer<typeof EvidenceRecordSchema>;
export type FabricStatusData = z.infer<typeof FabricStatusSchema>;
export type AttackScenario = z.infer<typeof AttackScenarioSchema>;
export type GatewaySubmitResponse = z.infer<typeof GatewaySubmitResponseSchema>;

export interface ActionSubmitPayload {
  request_id?: string;
  agent_id: string;
  action: string;
  resource: string;
  parameters: Record<string, unknown>;
  nonce?: string;
  timestamp?: string;
  signature?: string;
  key_version?: number;
  idempotency_key?: string;
}

export interface GenericApiResponse {
  success?: boolean;
  message?: string;
  detail?: string;
  [key: string]: unknown;
}

// CENTRALIZED TYPED API CLIENT
export const api = {
  async fetchHealth(): Promise<HealthData> {
    const res = await fetch(`${API_BASE}/api/health`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Health check failed (${res.status})`);
    const data = await res.json();
    return HealthSchema.parse(data);
  },

  async fetchMode(): Promise<ModeData> {
    const res = await fetch(`${API_BASE}/mode`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch mode failed (${res.status})`);
    const data = await res.json();
    return ModeSchema.parse(data);
  },

  async setMode(mode: string, role: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/mode`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Role": role,
      },
      body: JSON.stringify({ mode }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Failed to set mode" }));
      throw new Error((err as { detail?: string }).detail || `Set mode failed (${res.status})`);
    }
    return res.json();
  },

  async fetchAgents(): Promise<AgentRecord[]> {
    const res = await fetch(`${API_BASE}/agents`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch agents failed (${res.status})`);
    const data = await res.json();
    const parsed = AgentsListSchema.parse(data);
    return parsed.agents;
  },

  async updateAgentStatus(agentId: string, status: string, reason: string = "", role: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/agents/${agentId}/status`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Role": role,
      },
      body: JSON.stringify({ status, reason }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Update status failed" }));
      throw new Error((err as { detail?: string }).detail || `Update status failed (${res.status})`);
    }
    return res.json();
  },

  async suspendAgent(agentId: string, reason: string = "ADMIN_SUSPENSION", role: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/agents/${agentId}/suspend?reason=${encodeURIComponent(reason)}`, {
      method: "POST",
      headers: { "X-Admin-Role": role },
    });
    if (!res.ok) throw new Error(`Suspend agent failed (${res.status})`);
    return res.json();
  },

  async reactivateAgent(agentId: string, role: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/agents/${agentId}/reactivate`, {
      method: "POST",
      headers: { "X-Admin-Role": role },
    });
    if (!res.ok) throw new Error(`Reactivate agent failed (${res.status})`);
    return res.json();
  },

  async revokeAgent(agentId: string, role: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/agents/${agentId}/revoke`, {
      method: "POST",
      headers: { "X-Admin-Role": role },
    });
    if (!res.ok) throw new Error(`Revoke agent failed (${res.status})`);
    return res.json();
  },

  async rotateAgentKey(agentId: string, role: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/agents/${agentId}/rotate-key`, {
      method: "POST",
      headers: { "X-Admin-Role": role },
    });
    if (!res.ok) throw new Error(`Rotate key failed (${res.status})`);
    return res.json();
  },

  async fetchAuditEvents(): Promise<AuditRecord[]> {
    const res = await fetch(`${API_BASE}/audit/events`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch audit events failed (${res.status})`);
    const data = await res.json();
    return data.events || [];
  },

  async fetchPolicies(): Promise<PolicyRecord[]> {
    const res = await fetch(`${API_BASE}/policies`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch policies failed (${res.status})`);
    const data = await res.json();
    const parsed = PoliciesListSchema.parse(data);
    return parsed.policies;
  },

  async rollbackPolicy(policyId: string, targetVersion: string, role: string = "POLICY_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/policies/rollback`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Role": role,
      },
      body: JSON.stringify({ policy_id: policyId, target_version: targetVersion }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Rollback policy failed" }));
      throw new Error((err as { detail?: string }).detail || `Rollback policy failed (${res.status})`);
    }
    return res.json();
  },

  async fetchPendingApprovals(): Promise<ApprovalTicket[]> {
    const res = await fetch(`${API_BASE}/approvals/pending`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch approvals failed (${res.status})`);
    const data = await res.json();
    const parsed = PendingApprovalsSchema.parse(data);
    return parsed.pending_approvals;
  },

  async approveTicket(approvalId: string, role: string = "FINANCE_APPROVER"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/approvals/${approvalId}/approve`, {
      method: "POST",
      headers: { "X-Admin-Role": role },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Approve ticket failed" }));
      throw new Error((err as { detail?: string }).detail || `Approve failed (${res.status})`);
    }
    return res.json();
  },

  async rejectTicket(approvalId: string, reason: string = "REJECTED_BY_HUMAN", role: string = "FINANCE_APPROVER"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/approvals/${approvalId}/reject?reason=${encodeURIComponent(reason)}`, {
      method: "POST",
      headers: { "X-Admin-Role": role },
    });
    if (!res.ok) throw new Error(`Reject ticket failed (${res.status})`);
    return res.json();
  },

  async fetchAuditChain(): Promise<AuditRecord[]> {
    const res = await fetch(`${API_BASE}/audit/chain`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch audit chain failed (${res.status})`);
    const data = await res.json();
    const parsed = AuditChainSchema.parse(data);
    return parsed.chain;
  },

  async verifyChain(): Promise<ChainVerifyData> {
    const res = await fetch(`${API_BASE}/audit/chain/verify`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Verify chain failed (${res.status})`);
    const data = await res.json();
    return ChainVerifySchema.parse(data);
  },

  async fetchFabricStatus(): Promise<FabricStatusData> {
    const res = await fetch(`${API_BASE}/fabric/status`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fabric status failed (${res.status})`);
    const data = await res.json();
    return FabricStatusSchema.parse(data);
  },

  async fetchBlockchainBlocks(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/audit/blockchain/blocks`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch blocks failed (${res.status})`);
    return res.json();
  },

  async fetchEvidence(id: string): Promise<EvidenceRecord> {
    const res = await fetch(`${API_BASE}/evidence/${id}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch evidence failed (${res.status})`);
    const data = await res.json();
    return EvidenceRecordSchema.parse(data.evidence || data);
  },

  async verifyEvidence(id: string): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/evidence/${id}/verify`, { method: "POST" });
    if (!res.ok) throw new Error(`Verify evidence failed (${res.status})`);
    return res.json();
  },

  async submitAction(payload: ActionSubmitPayload): Promise<GatewaySubmitResponse> {
    const res = await fetch(`${API_BASE}/actions/submit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Action submission failed" }));
      const detailMsg = typeof err.detail === "string" 
        ? err.detail 
        : Array.isArray(err.detail)
        ? err.detail.map((d: { msg?: string; loc?: (string | number)[] }) => `${d.loc ? d.loc.join('.') + ': ' : ''}${d.msg || JSON.stringify(d)}`).join(', ')
        : typeof err.detail === "object" && err.detail !== null
        ? JSON.stringify(err.detail)
        : `Action submission failed (${res.status})`;
      throw new Error(detailMsg);
    }
    const data = await res.json();
    return GatewaySubmitResponseSchema.parse(data);
  },

  async runAttackMatrix(): Promise<z.infer<typeof AttackMatrixRunSchema>> {
    const res = await fetch(`${API_BASE}/scenarios/attack-matrix/run-all`, {
      method: "POST",
    });
    if (!res.ok) throw new Error(`Attack matrix run failed (${res.status})`);
    const data = await res.json();
    return AttackMatrixRunSchema.parse(data);
  },

  async runPerformanceBenchmark(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/benchmark/run`, {
      method: "POST",
    });
    if (!res.ok) throw new Error(`Benchmark run failed (${res.status})`);
    return res.json();
  },

  async simulateEvidenceTamper(evidenceId: string, fieldName: string, newValue: unknown, role: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/evidence/${evidenceId}/simulate-tamper`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Role": role,
      },
      body: JSON.stringify({ field_name: fieldName, new_value: newValue }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Tamper simulation failed" }));
      throw new Error((err as { detail?: string }).detail || `Tamper simulation failed (${res.status})`);
    }
    return res.json();
  },

  async simulateChainTamper(sequenceNumber: number, fieldName: string, newValue: unknown, role: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/audit/chain/simulate-tamper`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Role": role,
      },
      body: JSON.stringify({ sequence_number: sequenceNumber, field_name: fieldName, new_value: newValue }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Chain tamper simulation failed" }));
      throw new Error((err as { detail?: string }).detail || `Chain tamper failed (${res.status})`);
    }
    return res.json();
  },

  async registerAgent(data: Record<string, unknown>, role: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/agents/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Role": role,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err: unknown = await res.json().catch(() => ({ detail: "Agent registration failed" }));
      const detail = typeof err === "object" && err !== null && "detail" in err
        ? (err as { detail?: unknown }).detail
        : undefined;
      let message = `Agent registration failed (${res.status})`;
      if (typeof detail === "string" && detail.length > 0) {
        message = detail;
      } else if (Array.isArray(detail)) {
        message = detail.map((item: unknown) => {
          if (typeof item === "string") return item;
          if (typeof item === "object" && item !== null) {
            const issue = item as { loc?: unknown; msg?: unknown };
            const location = Array.isArray(issue.loc) ? `${issue.loc.join(".")}: ` : "";
            return `${location}${typeof issue.msg === "string" ? issue.msg : JSON.stringify(item)}`;
          }
          return String(item);
        }).join("; ");
      } else if (typeof detail === "object" && detail !== null) {
        message = JSON.stringify(detail);
      }
      throw new Error(message);
    }
    return res.json();
  },


  async deleteAgent(agentId: string): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/agents/${agentId}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`Delete agent failed (${res.status})`);
    return res.json();
  },

  async createPolicy(data: Record<string, unknown>, role: string = "POLICY_ADMIN"): Promise<GenericApiResponse> {
    const res = await fetch(`${API_BASE}/policies`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Role": role,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Create policy failed" }));
      const detail = (err as { detail?: unknown }).detail;
      const detailMsg = typeof detail === "string"
        ? detail
        : Array.isArray(detail)
        ? detail.map((item: { msg?: string; loc?: (string | number)[] }) => `${item.loc ? item.loc.join(".") + ": " : ""}${item.msg || JSON.stringify(item)}`).join(", ")
        : detail && typeof detail === "object"
        ? JSON.stringify(detail)
        : `Create policy failed (${res.status})`;
      throw new Error(detailMsg);
    }
    return res.json();
  },

  async fetchCertificates(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/identity/certificates`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch certificates failed (${res.status})`);
    return res.json();
  },

  async issueDelegationToken(data: Record<string, unknown>, role: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const res = await fetch(`${API_BASE}/identity/delegation/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Role": role,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Issue delegation token failed (${res.status})` }));
      const detail = (err as { detail?: unknown }).detail;
      const detailMsg = typeof detail === "string"
        ? detail
        : Array.isArray(detail)
        ? detail.map((item: { msg?: string; loc?: (string | number)[] }) => `${item.loc ? item.loc.join(".") + ": " : ""}${item.msg || JSON.stringify(item)}`).join(", ")
        : detail && typeof detail === "object"
        ? JSON.stringify(detail)
        : `Issue delegation token failed (${res.status})`;
      throw new Error(detailMsg);
    }
    return res.json();
  },

  async fetchDelegationTokens(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/identity/delegation`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch delegation tokens failed (${res.status})`);
    return res.json();
  },

  async checkPromptInjection(payload: Record<string, unknown>): Promise<unknown> {
    const res = await fetch(`${API_BASE}/risk/prompt-injection/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Prompt injection check failed (${res.status})`);
    return res.json();
  },

  async fetchMcpTools(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/gateway/mcp/tools`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch MCP tools failed (${res.status})`);
    return res.json();
  },

  async callMcpTool(data: Record<string, unknown>): Promise<unknown> {
    const res = await fetch(`${API_BASE}/gateway/mcp/call`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`MCP tool call failed (${res.status})`);
    return res.json();
  },

  async fetchRetryQueue(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/gateway/retry-queue`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch retry queue failed (${res.status})`);
    return res.json();
  },

  async flushRetryQueue(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/gateway/retry-queue/flush`, { method: "POST" });
    if (!res.ok) throw new Error(`Flush retry queue failed (${res.status})`);
    return res.json();
  },

  async fetchMerkleProof(requestId: string): Promise<unknown> {
    const res = await fetch(`${API_BASE}/audit/merkle-proof/${requestId}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch Merkle proof failed (${res.status})`);
    return res.json();
  },

  async verifyMerkleProof(data: Record<string, unknown>): Promise<unknown> {
    const res = await fetch(`${API_BASE}/audit/verify-merkle-proof`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Verify Merkle proof failed (${res.status})`);
    return res.json();
  },

  async fetchEvidenceProvenance(requestId: string): Promise<unknown> {
    const res = await fetch(`${API_BASE}/evidence/provenance/${requestId}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch provenance failed (${res.status})`);
    return res.json();
  },

  async fetchReplayCache(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/replay/cache`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch replay cache failed (${res.status})`);
    return res.json();
  },

  async fetchFabricWorldState(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/fabric/world-state`, { cache: "no-store" });
    if (!res.ok) throw new Error(`Fetch Fabric world state failed (${res.status})`);
    return res.json();
  },

  async queryFabricChaincode(data: Record<string, unknown>): Promise<unknown> {
    const res = await fetch(`${API_BASE}/fabric/chaincode/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Fabric chaincode query failed (${res.status})`);
    return res.json();
  }
};
