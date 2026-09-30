"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  Cpu,
  ShieldCheck,
  UserCheck,
  FileText,
  Database,
  Search,
  Fingerprint,
  Crosshair,
  Activity,
  AlertTriangle,
  Sun,
  Moon,
  ChevronLeft,
  ChevronRight,
  User,
  CheckCircle,
  XCircle,
  Command
} from "lucide-react";
import { ModeBadge, HashText } from "@/components/domain/components";
import { CommandPalette } from "@/components/ui/primitives";
import { useTheme } from "next-themes";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, setTheme } = useTheme();
  
  const [collapsed, setCollapsed] = useState(false);
  const [cmdOpen, setCmdOpen] = useState(false);

  // Poll Chain Integrity
  const { data: chainIntegrity } = useQuery({
    queryKey: ["chainIntegrity"],
    queryFn: () => api.verifyChain(),
    refetchInterval: 3000,
  });

  // Poll Mode
  const { data: modeData } = useQuery({
    queryKey: ["modeData"],
    queryFn: () => api.fetchMode(),
    refetchInterval: 5000,
  });

  // Keyboard shortcut Ctrl+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const navItems = [
    { label: "Overview", path: "/overview", icon: LayoutDashboard },
    { label: "Gateway Pipeline", path: "/gateway", icon: Cpu },
    { label: "Agent Governance", path: "/agents", icon: ShieldCheck },
    { label: "Human Approvals", path: "/approvals", icon: UserCheck },
    { label: "Policy Engine", path: "/policies", icon: FileText },
    { label: "Ledger Explorer", path: "/ledger", icon: Database },
    { label: "Evidence Verification", path: "/evidence", icon: Fingerprint },
    { label: "Attack Matrix Lab", path: "/attack-lab", icon: Crosshair },
    { label: "Benchmarks", path: "/benchmarks", icon: Activity },
    { label: "Sandbox & Testing", path: "/sandbox", icon: AlertTriangle, warning: true },
  ];

  return (
    <div className="min-h-screen flex bg-[var(--bg)] text-[var(--fg)]">
      
      {/* Collapsible Left Sidebar */}
      <aside
        className={`${
          collapsed ? "w-16" : "w-64"
        } bg-[var(--surface)] border-r border-[var(--border)] flex flex-col transition-all duration-200 shrink-0 z-30`}
      >
        {/* Brand Header */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-[var(--border)]">
          <Link href="/overview" className="flex items-center gap-3 overflow-hidden">
            <div className="w-8 h-8 rounded-lg bg-[var(--emerald)] text-[var(--accent-fg)] flex items-center justify-center shrink-0 font-bold">
              <Shield className="w-5 h-5" />
            </div>
            {!collapsed && (
              <div className="truncate">
                <div className="font-extrabold text-sm tracking-tight text-[var(--fg)]">
                  AgentTrust
                </div>
                <div className="text-[10px] font-mono text-[var(--muted)]">
                  OBSIDIAN SENTINEL
                </div>
              </div>
            )}
          </Link>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1 text-[var(--muted)] hover:text-[var(--fg)] rounded hover:bg-[var(--surface-2)]"
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Section */}
        <nav className="p-3 space-y-1 flex-1 overflow-y-auto">
          {navItems.map((item) => {
            const active = pathname === item.path;
            const Icon = item.icon;

            return (
              <Link
                key={item.path}
                href={item.path}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? "bg-[var(--surface-2)] text-[var(--emerald)] border border-[var(--border)]"
                    : item.warning
                    ? "text-[var(--held)] hover:bg-[var(--held)]/10"
                    : "text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-2)]"
                }`}
                title={collapsed ? item.label : undefined}
              >
                <Icon className={`w-4 h-4 shrink-0 ${active ? "text-[var(--emerald)]" : ""}`} />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Sidebar Footer System Status */}
        {!collapsed && (
          <div className="p-4 border-t border-[var(--border)] bg-[var(--surface-2)]/40 font-mono text-xs">
            <div className="flex items-center justify-between text-[var(--muted)] mb-1">
              <span>Chain Integrity:</span>
              {chainIntegrity?.valid ? (
                <span className="text-[var(--allowed)] font-semibold flex items-center gap-1">
                  <CheckCircle className="w-3 h-3" /> VERIFIED
                </span>
              ) : (
                <span className="text-[var(--blocked)] font-semibold flex items-center gap-1">
                  <XCircle className="w-3 h-3" /> TAMPERED
                </span>
              )}
            </div>
          </div>
        )}
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        
        {/* Top Header Bar */}
        <header className="h-16 glass-header border-b border-[var(--border)] px-6 flex items-center justify-between sticky top-0 z-20">
          
          {/* Search Trigger */}
          <button
            onClick={() => setCmdOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-xs text-[var(--muted)] hover:border-[var(--border-strong)] transition-colors w-64"
          >
            <Search className="w-3.5 h-3.5" />
            <span className="truncate">Search commands...</span>
            <kbd className="ml-auto font-mono text-[10px] px-1.5 py-0.5 rounded bg-[var(--surface)] text-[var(--subtle)]">
              Ctrl+K
            </kbd>
          </button>

          {/* Right Controls */}
          <div className="flex items-center gap-4">
            
            {/* Mode Badge */}
            <ModeBadge mode={modeData?.current_mode} />

            {/* Chain Indicator */}
            <div className="hidden sm:flex items-center gap-1.5 text-xs font-mono px-3 py-1 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-[var(--muted)]">
              <span className="w-2 h-2 rounded-full bg-[var(--emerald)] animate-pulse" />
              <span>Simulated Fabric Channel</span>
            </div>

            {/* Theme Toggle */}
            <button
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className="p-2 rounded-lg text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-2)] transition-colors"
              title="Toggle light/dark theme"
            >
              {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>

            {/* User Profile */}
            <div className="flex items-center gap-2 pl-2 border-l border-[var(--border)]">
              <div className="w-7 h-7 rounded-full bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center text-[var(--muted)] text-xs">
                <User className="w-4 h-4" />
              </div>
              <span className="text-xs font-mono text-[var(--fg)] hidden md:inline">SYSTEM_ADMIN</span>
            </div>
          </div>
        </header>

        {/* Main Body */}
        <main className="flex-1 p-6 max-w-[1400px] w-full mx-auto">
          {children}
        </main>
      </div>

      {/* Command Palette Modal */}
      <CommandPalette
        isOpen={cmdOpen}
        onClose={() => setCmdOpen(false)}
        onNavigate={(route) => router.push(route)}
      />
    </div>
  );
}
