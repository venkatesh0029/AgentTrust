"use client";

import React, { useState } from "react";
import { Shield, Key, CheckCircle, LogOut, User, Lock, AlertCircle } from "lucide-react";
import { Button } from "./primitives";
import { api, type AuthSession } from "@/lib/api";

const PRESET_ACCOUNTS = [
  {
    username: "admin",
    role: "SYSTEM_ADMIN",
    title: "System Administrator",
    description: "Full control over nodes, mode changes, agents, and delegation",
    password: "AdminTrust#2026!Secured",
    color: "var(--emerald)",
  },
  {
    username: "policy_admin",
    role: "POLICY_ADMIN",
    title: "Security Policy Admin",
    description: "Author, update, and rollback security and spending policies",
    password: "PolicyTrust#2026!Secured",
    color: "#3b82f6",
  },
  {
    username: "finance_approver",
    role: "FINANCE_APPROVER",
    title: "Finance Approver",
    description: "Review and approve/reject high-value human-in-the-loop tickets",
    password: "FinanceTrust#2026!Secured",
    color: "#f59e0b",
  },
  {
    username: "auditor",
    role: "AUDITOR",
    title: "Compliance Auditor",
    description: "Read-only access to audit chain, cryptographic evidence, and Fabric ledgers",
    password: "AuditorTrust#2026!Secured",
    color: "#a855f7",
  },
];

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentSession: AuthSession | null;
}

export function AuthModal({ isOpen, onClose, currentSession }: AuthModalProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handlePresetLogin = async (acc: typeof PRESET_ACCOUNTS[0]) => {
    setLoading(true);
    setError(null);
    try {
      await api.login(acc.username, acc.password);
      onClose();
    } catch (err: unknown) {
      setError((err as Error).message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleCustomLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError("Please enter both username and password");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await api.login(username.trim(), password);
      onClose();
    } catch (err: unknown) {
      setError((err as Error).message || "Invalid credentials");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    api.logout();
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
      <div
        id="auth-modal"
        className="w-full max-w-lg rounded-2xl border border-[var(--border)] bg-[var(--surface)] shadow-2xl p-6 text-[var(--fg)] relative"
      >
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-[var(--border)] mb-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-[var(--emerald)]/10 text-[var(--emerald)] flex items-center justify-center border border-[var(--emerald)]/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[var(--fg)]">Authentication & RBAC Manager</h2>
              <p className="text-xs text-[var(--muted)]">Signed JWT Bearer tokens with strict role binding</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-2)] transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Current Session Banner */}
        <div className="p-3 rounded-xl bg-[var(--surface-2)] border border-[var(--border)] mb-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[var(--allowed)] animate-pulse" />
              <span className="text-xs font-semibold text-[var(--fg)]">
                Active Identity: <span className="font-mono text-[var(--emerald)]">{currentSession?.username || "Not Authenticated"}</span>
              </span>
            </div>
            {currentSession && (
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--surface)] border border-[var(--border)] text-[var(--muted)]">
                {currentSession.role}
              </span>
            )}
          </div>
          {currentSession?.token && (
            <div className="mt-2 text-[10px] font-mono text-[var(--muted)] truncate">
              Token: Bearer {currentSession.token.slice(0, 24)}...{currentSession.token.slice(-12)}
            </div>
          )}
        </div>

        {error && (
          <div className="p-3 mb-4 rounded-lg bg-[var(--blocked)]/10 border border-[var(--blocked)]/30 text-xs text-[var(--blocked)] flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* 1-Click Role Switcher */}
        <div className="mb-5">
          <label className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)] block mb-2">
            Switch Administrator Persona (PBKDF2 Authenticated)
          </label>
          <div className="grid grid-cols-2 gap-2">
            {PRESET_ACCOUNTS.map((acc) => {
              const isActive = currentSession?.username === acc.username;
              return (
                <button
                  key={acc.username}
                  type="button"
                  id={`auth-switch-${acc.username}`}
                  disabled={loading}
                  onClick={() => handlePresetLogin(acc)}
                  className={`p-3 rounded-xl border text-left transition-all flex flex-col justify-between ${
                    isActive
                      ? "border-[var(--emerald)] bg-[var(--emerald)]/5 shadow-sm"
                      : "border-[var(--border)] bg-[var(--surface)] hover:border-[var(--border-strong)] hover:bg-[var(--surface-2)]"
                  }`}
                >
                  <div className="flex items-center justify-between w-full mb-1">
                    <span className="text-xs font-bold text-[var(--fg)]">{acc.title}</span>
                    {isActive ? (
                      <CheckCircle className="w-3.5 h-3.5 text-[var(--emerald)]" />
                    ) : (
                      <Key className="w-3 h-3 text-[var(--muted)]" />
                    )}
                  </div>
                  <span className="text-[10px] font-mono text-[var(--muted)] mb-1">{acc.role}</span>
                  <span className="text-[10px] text-[var(--subtle)] line-clamp-1">{acc.description}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Custom Login Form */}
        <form onSubmit={handleCustomLogin} className="space-y-3 pt-3 border-t border-[var(--border)]">
          <label className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)] block">
            Custom Administrator Sign In
          </label>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <User className="w-3.5 h-3.5 absolute left-3 top-3 text-[var(--muted)]" />
              <input
                id="login-username"
                type="text"
                placeholder="Username (e.g. admin)"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full pl-9 pr-3 py-2 text-xs rounded-lg border border-[var(--border)] bg-[var(--surface-2)] text-[var(--fg)] placeholder-[var(--muted)] focus:outline-none focus:border-[var(--emerald)]"
              />
            </div>
            <div className="relative flex-1">
              <Lock className="w-3.5 h-3.5 absolute left-3 top-3 text-[var(--muted)]" />
              <input
                id="login-password"
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-9 pr-3 py-2 text-xs rounded-lg border border-[var(--border)] bg-[var(--surface-2)] text-[var(--fg)] placeholder-[var(--muted)] focus:outline-none focus:border-[var(--emerald)]"
              />
            </div>
          </div>
          <div className="flex items-center justify-between pt-2">
            {currentSession ? (
              <Button
                type="button"
                id="logout-button"
                variant="outline"
                size="sm"
                onClick={handleLogout}
                className="text-[var(--blocked)] border-[var(--blocked)]/30 hover:bg-[var(--blocked)]/10"
              >
                <LogOut className="w-3.5 h-3.5 mr-1" /> Sign Out
              </Button>
            ) : <span />}
            <div className="flex gap-2">
              <Button type="button" variant="ghost" size="sm" onClick={onClose}>
                Cancel
              </Button>
              <Button
                type="submit"
                id="login-submit-button"
                variant="primary"
                size="sm"
                disabled={loading}
              >
                {loading ? "Authenticating..." : "Sign In & Issue JWT"}
              </Button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
