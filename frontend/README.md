# AgentTrust Web Console — Obsidian Sentinel Edition

A dark, high-density, enterprise security operations console for the **AgentTrust Framework**, built with **Next.js 16 (App Router)**, **React 19**, **TypeScript (Strict)**, and **Tailwind CSS v4**.

---

## 🛡️ Product Context & Honest Ledger Architecture

AgentTrust gates autonomous AI agent actions through a strict 13-stage governance pipeline:
1. **Canonical JSON Ingestion** — Schema normalization
2. **X.509 Certificate Verification** — Identity validation & CRL check
3. **RSA-PSS Digital Signature** — Payload authenticity verification
4. **Agent Registry & Key Version** — Active status & key version matching
5. **Replay Protection** — Nonce tracking & timestamp freshness (300s window)
6. **Server-Side Risk Evaluation** — Dynamic risk score assignment (0.0 to 1.0)
7. **Versioned Policy Engine** — Declarative deny-by-default boundary check
8. **Decision / HITL Ticket** — Branching to ALLOW, BLOCK, or HELD FOR HUMAN APPROVAL
9. **Protected API Execution** — Gated execution of finance/procurement endpoints
10. **Evidence Generation** — Off-chain SHA-256 execution digest creation
11. **Local Audit Chain Commit** — Atomic, hash-linked audit log write
12. **Fabric Ledger State Commit** — Permissioned ledger state commitment
13. **Gateway Response Telemetry** — Full execution provenance return

> [!NOTE]
> **Honest Ledger Architecture Notice**: The default ledger backend runs a **Fabric-Compatible Permissioned Ledger Simulator** (In-Memory / SQLite Persistent). All SHA-256 block hash chains are calculated deterministically. The UI explicitly states this mode status across all views.

---

## 🎨 Design System — "Obsidian Sentinel"

The console adheres to the **Obsidian Sentinel** enterprise security theme:

- **Surfaces**:
  - Background: `#0a0d12` (`bg-[var(--bg)]`)
  - Surface 1: `#0f141b` (`bg-[var(--surface)]`)
  - Surface 2: `#151c26` (`bg-[var(--surface-2)]`)
  - Border: `#1f2a37` (`border-[var(--border)]`)
  - Border Strong: `#2b3a4d` (`border-[var(--border-strong)]`)
- **Typography & Numerals**:
  - Primary UI Font: `Inter` (Google Fonts via `next/font/google`)
  - Monospace Font: `JetBrains Mono` (Google Fonts via `next/font/google`)
  - Tabular Numerals: `font-mono` & tabular number alignment on all stats, hashes, and amounts.
- **Brand Accent**: Single accent emerald `#34d399` (`text-[var(--accent)]`, `bg-[var(--emerald)]`)
- **Decision Colors**:
  - Allowed / Commit: Emerald `#34d399`
  - Held / Approval: Amber `#fbbf24`
  - Blocked / Rejected: Rose Red `#f87171`
  - Info / System: Sky Blue `#60a5fa`
  - Tampered / Mismatch: Crimson `#f43f5e`

---

## 📁 Application Structure

```text
frontend/src/
├── app/
│   ├── (console)/             # Console Route Group
│   │   ├── layout.tsx         # Sidebar, Topbar, Search, Command Palette, ModeBadge
│   │   ├── overview/          # KPI Stats, Audit Events Table, Chain Integrity
│   │   ├── gateway/           # 13-Stage PipelineStrip, Request Submission
│   │   ├── agents/            # X.509 Registry, Suspend/Revoke/Rotate-Key Actions
│   │   ├── approvals/         # Human-in-the-Loop Pending Approvals Queue
│   │   ├── policies/          # Policy Engine Bounds & Rollback Engine
│   │   ├── ledger/            # Block Explorer with Linked Hashes (prev_hash -> hash)
│   │   ├── evidence/          # SHA-256 Digest Verification Inspector
│   │   ├── attack-lab/        # 20 Threat Vector Adversarial Matrix Runner
│   │   ├── benchmarks/        # Stage Latency & Concurrency Profiler
│   │   └── sandbox/           # Isolated Tamper Simulator & Mode Switcher
│   ├── globals.css            # Tailwind CSS v4 `@theme` Tokens
│   ├── layout.tsx             # Root Provider & Google Fonts Configuration
│   └── page.tsx               # Root Redirect to /overview
├── components/
│   ├── domain/                # PipelineStrip, DecisionPill, HashText, StatCard, ModeBadge
│   ├── ui/                    # Button, Card, Badge, Skeleton, Dialog, CommandPalette
│   └── providers.tsx          # TanStack Query Client & Next-Themes Provider
└── lib/
    └── api.ts                 # Centralized Typed API Client with Zod Validation
```

---

## ⚙️ Running Locally

### 1. Start FastAPI Backend (Port 8000)
```bash
python server.py
```

### 2. Launch Next.js Dev Server (Port 3000)
```bash
cd frontend
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Verification & Build Commands

```bash
# Type check and build Next.js App Router static pages
npm run build

# Run ESLint validation (0 errors, 0 warnings)
npm run lint
```
