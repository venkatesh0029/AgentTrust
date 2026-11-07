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

export const LoginResponseSchema = z.object({
  access_token: z.string(),
  token_type: z.string().default("bearer"),
  expires_in: z.number().default(28800),
  role: z.string(),
  identity: z.string().default("admin"),
  username: z.string().default("admin"),
  csrf_token: z.string().optional(),
});
export type LoginResponse = z.infer<typeof LoginResponseSchema>;

export interface AuthSession {
  token: string;
  role: string;
  username: string;
  expiresAt: number;
}

export const isDemoAuthMode = (): boolean => {
  if (
    process.env.NODE_ENV === "production" ||
    process.env.NEXT_PUBLIC_ENV === "production" ||
    process.env.NEXT_PUBLIC_DEMO_MODE === "false"
  ) {
    return false;
  }

  return true;
};

export const DEMO_CREDENTIALS: Record<string, { username: string; password: string }> = {
  SYSTEM_ADMIN: { username: "admin", password: "AdminTrust#2026!Secured" },
  POLICY_ADMIN: { username: "policy_admin", password: "PolicyTrust#2026!Secured" },
  FINANCE_APPROVER: { username: "finance_approver", password: "FinanceTrust#2026!Secured" },
  AUDITOR: { username: "auditor", password: "AuditorTrust#2026!Secured" },
};

// Scoped sessionStorage key for persisting JWT session across tab refreshes
const SESSION_STORAGE_KEY = "agenttrust_auth_session";

function saveSessionToStorage(session: AuthSession | null, csrfToken: string | null) {
  if (typeof window !== "undefined") {
    try {
      if (session) {
        sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
        if (csrfToken) sessionStorage.setItem("agenttrust_csrf_token", csrfToken);
      } else {
        sessionStorage.removeItem(SESSION_STORAGE_KEY);
        sessionStorage.removeItem("agenttrust_csrf_token");
      }
    } catch {}
  }
}

function restoreSessionFromStorage(): AuthSession | null {
  if (typeof window !== "undefined") {
    try {
      const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as AuthSession;
        if (parsed && parsed.token && Date.now() < parsed.expiresAt) {
          const csrf = sessionStorage.getItem("agenttrust_csrf_token");
          if (csrf) inMemoryCsrfToken = csrf;
          inMemoryRoleTokens[parsed.role] = { token: parsed.token, expiresAt: parsed.expiresAt };
          return parsed;
        }
      }
    } catch {}
  }
  return null;
}

// In-memory session store; tokens are scoped in memory and session storage
let inMemorySession: AuthSession | null = null;
let inMemoryCsrfToken: string | null = null;
const inMemoryRoleTokens: Record<string, { token: string; expiresAt: number }> = {};

// Clean up legacy tokens from localStorage if present
if (typeof window !== "undefined") {
  try {
    [
      "agenttrust_auth_token",
      "agenttrust_auth_user",
      "agenttrust_auth_role",
      "agenttrust_auth_expiry",
      "agenttrust_auth_token_SYSTEM_ADMIN",
      "agenttrust_auth_token_POLICY_ADMIN",
      "agenttrust_auth_token_FINANCE_APPROVER",
      "agenttrust_auth_token_AUDITOR",
    ].forEach((k) => localStorage.removeItem(k));
  } catch {}
}

// CENTRALIZED TYPED API CLIENT
export const api = {
  async login(username: string = "admin", password?: string): Promise<LoginResponse> {
    let pwd = password;
    if (!pwd) {
      if (isDemoAuthMode()) {
        const cred = Object.values(DEMO_CREDENTIALS).find((c) => c.username === username);
        pwd = cred?.password || "AdminTrust#2026!Secured";
      } else {
        throw new Error("SECURITY VIOLATION: Password is mandatory in production environment. Demo persona shortcuts are disabled.");
      }
    }
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password: pwd }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Login failed" }));
      throw new Error((err as { detail?: string }).detail || `Authentication failed (${res.status})`);
    }
    const data = LoginResponseSchema.parse(await res.json());
    const expiresAt = Date.now() + (data.expires_in || 28800) * 1000;

    // Maintain token strictly in-memory and scoped session storage
    inMemorySession = {
      token: data.access_token,
      role: data.role,
      username: data.username,
      expiresAt,
    };
    inMemoryCsrfToken = (data as { csrf_token?: string }).csrf_token || null;
    inMemoryRoleTokens[data.role] = { token: data.access_token, expiresAt };
    saveSessionToStorage(inMemorySession, inMemoryCsrfToken);

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("agenttrust-auth-changed", { detail: data }));
    }
    return data;
  },

  async logout(): Promise<void> {
    try {
      const authHeaders = this.getAuthHeaders();
      await fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: authHeaders,
      });
    } catch {
      // Ignore network errors during logout
    }
    inMemorySession = null;
    inMemoryCsrfToken = null;
    Object.keys(inMemoryRoleTokens).forEach((k) => delete inMemoryRoleTokens[k]);
    saveSessionToStorage(null, null);
    if (typeof window !== "undefined") {
      try {
        [
          "agenttrust_auth_token",
          "agenttrust_auth_user",
          "agenttrust_auth_role",
          "agenttrust_auth_expiry",
        ].forEach((k) => localStorage.removeItem(k));
      } catch {}
      window.dispatchEvent(new CustomEvent("agenttrust-auth-changed", { detail: null }));
    }
  },

  async checkServerSession(): Promise<AuthSession | null> {
    try {
      const res = await fetch(`${API_BASE}/auth/session`, {
        method: "GET",
        credentials: "include",
      });
      if (res.ok) {
        const data = await res.json();
        const existingToken = inMemorySession?.token || restoreSessionFromStorage()?.token || "";
        inMemorySession = {
          token: existingToken,
          role: data.role,
          username: data.username,
          expiresAt: (data.expires_at || 0) * 1000,
        };
        inMemoryCsrfToken = data.csrf_token || inMemoryCsrfToken;
        if (existingToken) {
          saveSessionToStorage(inMemorySession, inMemoryCsrfToken);
        }
        return inMemorySession;
      }
    } catch {
      // Ignore network errors
    }
    return null;
  },

  getStoredAuth(): AuthSession | null {
    if (!inMemorySession) {
      inMemorySession = restoreSessionFromStorage();
    }
    if (inMemorySession) {
      if (Date.now() > inMemorySession.expiresAt) {
        this.logout();
        return null;
      }
      return inMemorySession;
    }
    return null;
  },

  async ensureAuth(roleOrToken?: string): Promise<string> {
    if (roleOrToken && roleOrToken.startsWith("eyJ")) {
      return roleOrToken;
    }

    // 1. Check existing in-memory / session storage session
    const currentSession = this.getStoredAuth();
    if (currentSession?.token && currentSession.token.startsWith("eyJ")) {
      if (!roleOrToken || currentSession.role === roleOrToken) {
        return currentSession.token;
      }
    }

    // 2. Check cached role tokens in memory
    const targetRole = roleOrToken && DEMO_CREDENTIALS[roleOrToken] ? roleOrToken : null;
    if (targetRole && inMemoryRoleTokens[targetRole]) {
      const entry = inMemoryRoleTokens[targetRole];
      if (Date.now() < entry.expiresAt && entry.token.startsWith("eyJ")) {
        return entry.token;
      }
    }

    // 3. Fallback: Authenticate as the target role or default admin
    const creds = targetRole ? DEMO_CREDENTIALS[targetRole] : DEMO_CREDENTIALS.SYSTEM_ADMIN;
    try {
      const loginRes = await this.login(creds.username, creds.password);
      return loginRes.access_token;
    } catch {
      const serverSession = await this.checkServerSession();
      if (serverSession?.token && serverSession.token.startsWith("eyJ")) {
        return serverSession.token;
      }
      return "";
    }
  },

  getAuthHeaders(roleOrToken?: string): Record<string, string> {
    const headers: Record<string, string> = {};
    if (inMemoryCsrfToken) {
      headers["X-CSRF-Token"] = inMemoryCsrfToken;
    }
    if (roleOrToken && roleOrToken.startsWith("eyJ")) {
      headers["Authorization"] = `Bearer ${roleOrToken}`;
      return headers;
    }
    if (roleOrToken && inMemoryRoleTokens[roleOrToken]) {
      const entry = inMemoryRoleTokens[roleOrToken];
      if (Date.now() < entry.expiresAt && entry.token.startsWith("eyJ")) {
        headers["Authorization"] = `Bearer ${entry.token}`;
        return headers;
      }
    }
    const session = this.getStoredAuth();
    if (session?.token && session.token.startsWith("eyJ")) {
      headers["Authorization"] = `Bearer ${session.token}`;
      return headers;
    }
    return headers;
  },

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

  async setMode(mode: string, roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/mode`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
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
    const res = await fetch(`${API_BASE}/agents`, { cache: "no-store", credentials: "include" });
    if (!res.ok) throw new Error(`Fetch agents failed (${res.status})`);
    const data = await res.json();
    const parsed = AgentsListSchema.parse(data);
    return parsed.agents;
  },

  async updateAgentStatus(agentId: string, status: string, reason: string = "", roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/agents/${agentId}/status`, {
      method: "PATCH",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify({ status, reason }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Update status failed" }));
      throw new Error((err as { detail?: string }).detail || `Update status failed (${res.status})`);
    }
    return res.json();
  },

  async suspendAgent(agentId: string, reason: string = "ADMIN_SUSPENSION", roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/agents/${agentId}/suspend?reason=${encodeURIComponent(reason)}`, {
      method: "POST",
      credentials: "include",
      headers: { ...authHeaders },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Suspend agent failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Suspend agent failed (${res.status})`);
    }
    return res.json();
  },

  async reactivateAgent(agentId: string, roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/agents/${agentId}/reactivate`, {
      method: "POST",
      credentials: "include",
      headers: { ...authHeaders },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Reactivate agent failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Reactivate agent failed (${res.status})`);
    }
    return res.json();
  },

  async revokeAgent(agentId: string, roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/agents/${agentId}/revoke`, {
      method: "POST",
      credentials: "include",
      headers: { ...authHeaders },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Revoke agent failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Revoke agent failed (${res.status})`);
    }
    return res.json();
  },

  async rotateAgentKey(agentId: string, roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/agents/${agentId}/rotate-key`, {
      method: "POST",
      credentials: "include",
      headers: { ...authHeaders },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Rotate key failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Rotate key failed (${res.status})`);
    }
    return res.json();
  },

  async fetchAuditEvents(): Promise<AuditRecord[]> {
    const res = await fetch(`${API_BASE}/audit/events`, { cache: "no-store", credentials: "include" });
    if (!res.ok) throw new Error(`Fetch audit events failed (${res.status})`);
    const data = await res.json();
    return data.events || [];
  },

  async fetchPolicies(): Promise<PolicyRecord[]> {
    const res = await fetch(`${API_BASE}/policies`, { cache: "no-store", credentials: "include" });
    if (!res.ok) throw new Error(`Fetch policies failed (${res.status})`);
    const data = await res.json();
    const parsed = PoliciesListSchema.parse(data);
    return parsed.policies;
  },

  async rollbackPolicy(policyId: string, targetVersion: string, roleOrToken: string = "POLICY_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/policies/rollback`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
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
    const res = await fetch(`${API_BASE}/approvals/pending`, { cache: "no-store", credentials: "include" });
    if (!res.ok) throw new Error(`Fetch approvals failed (${res.status})`);
    const data = await res.json();
    const parsed = PendingApprovalsSchema.parse(data);
    return parsed.pending_approvals;
  },

  async approveTicket(approvalId: string, roleOrToken: string = "FINANCE_APPROVER"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/approvals/${approvalId}/approve`, {
      method: "POST",
      credentials: "include",
      headers: { ...authHeaders },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Approve ticket failed" }));
      throw new Error((err as { detail?: string }).detail || `Approve failed (${res.status})`);
    }
    return res.json();
  },

  async rejectTicket(approvalId: string, reason: string = "REJECTED_BY_HUMAN", roleOrToken: string = "FINANCE_APPROVER"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/approvals/${approvalId}/reject?reason=${encodeURIComponent(reason)}`, {
      method: "POST",
      credentials: "include",
      headers: { ...authHeaders },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Reject ticket failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Reject ticket failed (${res.status})`);
    }
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

  async simulateEvidenceTamper(evidenceId: string, fieldName: string, newValue: unknown, roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/evidence/${evidenceId}/simulate-tamper`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify({ field_name: fieldName, new_value: newValue }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Tamper simulation failed" }));
      throw new Error((err as { detail?: string }).detail || `Tamper simulation failed (${res.status})`);
    }
    return res.json();
  },

  async simulateChainTamper(sequenceNumber: number, fieldName: string, newValue: unknown, roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/audit/chain/simulate-tamper`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify({ sequence_number: sequenceNumber, field_name: fieldName, new_value: newValue }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Chain tamper simulation failed" }));
      throw new Error((err as { detail?: string }).detail || `Chain tamper failed (${res.status})`);
    }
    return res.json();
  },

  async registerAgent(data: Record<string, unknown>, roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/agents/register`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
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

  async deleteAgent(agentId: string, roleOrToken: string = "SYSTEM_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/agents/${agentId}`, {
      method: "DELETE",
      credentials: "include",
      headers: { ...authHeaders },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Delete agent failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Delete agent failed (${res.status})`);
    }
    return res.json();
  },

  async createPolicy(data: Record<string, unknown>, roleOrToken: string = "POLICY_ADMIN"): Promise<GenericApiResponse> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/policies`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
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

  async issueDelegationToken(data: Record<string, unknown>, roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(roleOrToken || token);
    const res = await fetch(`${API_BASE}/identity/delegation/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
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

  async flushRetryQueue(roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(roleOrToken || token);
    const res = await fetch(`${API_BASE}/gateway/retry-queue/flush`, {
      method: "POST",
      headers: { ...authHeaders },
    });
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
  },

  async fetchDelegationGraph(): Promise<DelegationGraphResponse> {
    const res = await fetch(`${API_BASE}/delegation/graph`, { cache: "no-store", credentials: "include" });
    if (!res.ok) throw new Error(`Fetch delegation graph failed (${res.status})`);
    return res.json();
  },

  async issueGraphDelegation(data: {
    issuer_agent_id: string;
    delegate_agent_id: string;
    allowed_actions: string[];
    delegated_budget: number;
    ttl_seconds?: number;
    reason?: string;
  }, roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/delegation/graph/issue`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Issue delegation failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Issue delegation failed (${res.status})`);
    }
    return res.json();
  },

  async revokeGraphDelegation(tokenId: string, reason: string = "MANUAL_ADMIN_REVOCATION", roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/delegation/graph/revoke`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify({ token_id: tokenId, reason }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Revoke delegation failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Revoke delegation failed (${res.status})`);
    }
    return res.json();
  },

  async simulateGraphAttack(scenario: string, roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/delegation/graph/simulate-attack`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify({ scenario }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Simulate attack failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Simulate attack failed (${res.status})`);
    }
    return res.json();
  },

  async resetGraphDelegation(roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/delegation/graph/reset`, {
      method: "POST",
      credentials: "include",
      headers: {
        ...authHeaders,
      },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Reset graph failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Reset graph failed (${res.status})`);
    }
    return res.json();
  },

  async executeDelegatedActionOnSpot(data: {
    agent_id: string;
    action: string;
    amount: number;
    resource?: string;
    token_id?: string;
  }, roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/delegation/graph/execute-on-spot`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Execute delegated action failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Execute delegated action failed (${res.status})`);
    }
    return res.json();
  },

  async executeBehaviorActionOnSpot(data: {
    agent_id: string;
    action: string;
    amount: number;
    resource?: string;
  }, roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/behavior/execute-on-spot`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Execute live behavior action failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Execute live behavior action failed (${res.status})`);
    }
    return res.json();
  },

  async fetchBehaviorSummary(): Promise<BehaviorSummaryResponse> {
    const res = await fetch(`${API_BASE}/behavior/summary`, { cache: "no-store", credentials: "include" });
    if (!res.ok) throw new Error(`Fetch behavior summary failed (${res.status})`);
    return res.json();
  },

  async simulateBehaviorScenario(scenario: string, roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/behavior/simulate-scenario`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify({ scenario }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Simulation failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Simulation failed (${res.status})`);
    }
    return res.json();
  },

  async analyzeBehaviorRequest(data: {
    agent_id: string;
    action: string;
    resource?: string;
    amount?: number;
    request_timestamp_iso?: string;
    simulate_window_burst?: number;
  }, roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/behavior/analyze`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Analyze failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Analyze failed (${res.status})`);
    }
    return res.json();
  },

  async resetBehaviorProfiles(roleOrToken: string = "SYSTEM_ADMIN"): Promise<unknown> {
    const token = await this.ensureAuth(roleOrToken);
    const authHeaders = this.getAuthHeaders(token || roleOrToken);
    const res = await fetch(`${API_BASE}/behavior/reset`, {
      method: "POST",
      credentials: "include",
      headers: {
        ...authHeaders,
      },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Reset profiles failed (${res.status})` }));
      throw new Error((err as { detail?: string }).detail || `Reset profiles failed (${res.status})`);
    }
    return res.json();
  }
};

export interface DelegationNode {
  agent_id: string;
  agent_name: string;
  role: string;
  organization: string;
  status: string;
  base_budget: number;
  allocated_budget: number;
  remaining_budget: number;
  spent_budget: number;
  effective_actions: string[];
  depth: number;
  parent_agent_id: string | null;
  incoming_token_id: string | null;
  risk_score: number;
  blast_radius: {
    score: number;
    risk_level: string;
    mitigated_percentage: number;
    without_policies_score: number;
    with_policies_score: number;
    impact_breakdown: {
      financial_exposure: number;
      lateral_movement: number;
      destructive_ops: number;
      data_exfiltration: number;
    };
  };
}

export interface DelegationEdge {
  token_id: string;
  issuer_agent_id: string;
  delegate_agent_id: string;
  delegated_actions: string[];
  delegated_budget: number;
  spent_budget: number;
  depth: number;
  status: string;
  issued_at: number;
  expires_at: number;
  revocation_reason?: string | null;
  parent_token_id?: string | null;
  signature: string;
}

export interface DelegationGraphSummary {
  total_agents: number;
  total_delegations: number;
  active_delegations: number;
  revoked_delegations: number;
  max_depth_observed: number;
  max_depth_limit: number;
  aggregate_delegated_budget: number;
  aggregate_spent_budget: number;
  overall_blast_radius_score: number;
  risk_reduction_percentage: number;
}

export interface DelegationAuditRecord {
  event_id: string;
  event_type: string;
  issuer_agent_id?: string | null;
  delegate_agent_id?: string | null;
  token_id?: string | null;
  decision: string;
  details: Record<string, unknown>;
  timestamp: string;
  record_hash: string;
}

export interface DelegationGraphResponse {
  nodes: DelegationNode[];
  edges: DelegationEdge[];
  summary: DelegationGraphSummary;
  audit_trail: DelegationAuditRecord[];
}

export interface BehaviorFlags {
  unusual_amount: boolean;
  unfamiliar_recipient: boolean;
  unusual_schedule: boolean;
  burst_velocity: boolean;
  sequence_anomaly: boolean;
}

export interface BehaviorEvent {
  event_id: string;
  request_id: string;
  agent_id: string;
  action: string;
  resource: string;
  amount: number;
  timestamp: string;
  flags: BehaviorFlags;
  anomaly_score: number;
  risk_level: string;
  enforcement: string;
  explainable_reasons: string[];
  insights: {
    agent_insights?: Record<string, unknown>;
    destination_insights?: Record<string, unknown>;
    activity_insights?: Record<string, unknown>;
  };
}

export interface AgentBehaviorProfile {
  agent_id: string;
  agent_name: string;
  role: string;
  sample_count: number;
  amount_mean: number;
  amount_std: number;
  amount_min: number;
  amount_max: number;
  daily_frequency_mean: number;
  daily_frequency_std: number;
  hourly_burst_threshold: number;
  known_destinations: string[];
  schedule_start_hour: number;
  schedule_end_hour: number;
  action_transitions: Record<string, Record<string, number>>;
  baseline_risk_score: number;
}

export interface BehaviorSummaryResponse {
  monitored_agents: number;
  total_events_analyzed: number;
  anomalies_detected: number;
  critical_deviations_count: number;
  top_anomalous_entities: Array<{
    agent_id: string;
    max_anomaly_score: number;
    profile?: AgentBehaviorProfile;
  }>;
  recent_events: BehaviorEvent[];
  profiles: AgentBehaviorProfile[];
}
