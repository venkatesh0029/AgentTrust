"use client";

import React, { useState } from "react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { Search, X, Command } from "lucide-react";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// BUTTON COMPONENT
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "emerald" | "secondary" | "danger" | "ghost" | "outline";
  size?: "sm" | "md" | "lg";
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "secondary", size = "md", children, disabled, ...props }, ref) => {
    const baseStyle = "inline-flex items-center justify-center font-medium rounded-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--emerald)] disabled:opacity-50 disabled:pointer-events-none active:scale-[0.98]";
    
    const variants = {
      emerald: "bg-[var(--emerald)] text-[var(--accent-fg)] hover:opacity-90 font-semibold shadow-sm",
      secondary: "bg-[var(--surface-2)] text-[var(--fg)] border border-[var(--border)] hover:border-[var(--border-strong)] hover:bg-white/5",
      danger: "bg-[var(--blocked)] text-white hover:opacity-90 font-semibold shadow-sm",
      ghost: "text-[var(--muted)] hover:text-[var(--fg)] hover:bg-white/5",
      outline: "border border-[var(--border)] text-[var(--fg)] hover:bg-white/5",
    };

    const sizes = {
      sm: "h-8 px-3 text-xs gap-1.5",
      md: "h-9 px-4 text-sm gap-2",
      lg: "h-11 px-5 text-base gap-2.5",
    };

    return (
      <button
        ref={ref}
        disabled={disabled}
        className={cn(baseStyle, variants[variant], sizes[size], className)}
        {...props}
      >
        {children}
      </button>
    );
  }
);
Button.displayName = "Button";

// CARD COMPONENT
export function Card({ className, children, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5 text-[var(--fg)] transition-all",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

// BADGE COMPONENT
export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: "allowed" | "held" | "blocked" | "info" | "tamper" | "subtle";
  dot?: boolean;
}

export function Badge({ className, variant = "subtle", dot = true, children, ...props }: BadgeProps) {
  const styles = {
    allowed: "bg-[var(--allowed)]/15 text-[var(--allowed)] border-[var(--allowed)]/30",
    held: "bg-[var(--held)]/15 text-[var(--held)] border-[var(--held)]/30",
    blocked: "bg-[var(--blocked)]/15 text-[var(--blocked)] border-[var(--blocked)]/30",
    info: "bg-[var(--info)]/15 text-[var(--info)] border-[var(--info)]/30",
    tamper: "bg-[var(--tamper)]/15 text-[var(--tamper)] border-[var(--tamper)]/30",
    subtle: "bg-[var(--surface-2)] text-[var(--muted)] border-[var(--border)]",
  };

  const dotColors = {
    allowed: "bg-[var(--allowed)]",
    held: "bg-[var(--held)]",
    blocked: "bg-[var(--blocked)]",
    info: "bg-[var(--info)]",
    tamper: "bg-[var(--tamper)]",
    subtle: "bg-[var(--subtle)]",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border font-mono tracking-tight",
        styles[variant],
        className
      )}
      {...props}
    >
      {dot && <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", dotColors[variant])} />}
      {children}
    </span>
  );
}

// SKELETON COMPONENT
export function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-[var(--surface-2)]", className)}
      {...props}
    />
  );
}

// DIALOG / MODAL COMPONENT
export interface DialogProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

export function Dialog({ isOpen, onClose, title, children }: DialogProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-lg bg-[var(--surface)] border border-[var(--border-strong)] rounded-xl shadow-2xl p-6 text-[var(--fg)]">
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-[var(--border)]">
          <h3 className="font-semibold text-base">{title}</h3>
          <button
            onClick={onClose}
            className="p-1 text-[var(--muted)] hover:text-[var(--fg)] rounded-lg hover:bg-white/5"
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div>{children}</div>
      </div>
    </div>
  );
}

// COMMAND PALETTE
export interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (route: string) => void;
}

export function CommandPalette({ isOpen, onClose, onNavigate }: CommandPaletteProps) {
  const [query, setQuery] = useState("");

  if (!isOpen) return null;

  const items = [
    { label: "Overview Dashboard", route: "/overview", category: "Navigation" },
    { label: "13-Stage Gateway Inspector", route: "/gateway", category: "Navigation" },
    { label: "Agent Governance & PKI", route: "/agents", category: "Navigation" },
    { label: "Human Approval Queue", route: "/approvals", category: "Navigation" },
    { label: "Policy Management", route: "/policies", category: "Navigation" },
    { label: "Ledger Explorer", route: "/ledger", category: "Navigation" },
    { label: "Off-Chain Evidence Verification", route: "/evidence", category: "Navigation" },
    { label: "20 Threat Attack Matrix Lab", route: "/attack-lab", category: "Navigation" },
    { label: "Performance Benchmarks", route: "/benchmarks", category: "Navigation" },
    { label: "Sandbox & Tamper Simulator", route: "/sandbox", category: "Sandbox" },
  ];

  const filtered = items.filter((i) =>
    i.label.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 p-4 bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-xl bg-[var(--surface)] border border-[var(--border-strong)] rounded-xl shadow-2xl overflow-hidden">
        <div className="flex items-center px-4 border-b border-[var(--border)]">
          <Search className="w-4 h-4 text-[var(--muted)] mr-3" />
          <input
            type="text"
            placeholder="Type a command or search page..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full h-12 bg-transparent text-sm text-[var(--fg)] placeholder-[var(--subtle)] focus:outline-none"
            autoFocus
          />
          <kbd className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--surface-2)] text-[var(--muted)] border border-[var(--border)]">
            ESC
          </kbd>
        </div>

        <div className="max-h-80 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="py-6 text-center text-sm text-[var(--muted)]">
              No matching commands found.
            </div>
          ) : (
            filtered.map((item) => (
              <button
                key={item.route}
                onClick={() => {
                  onNavigate(item.route);
                  onClose();
                }}
                className="w-full flex items-center justify-between px-3 py-2.5 text-sm rounded-lg text-left hover:bg-[var(--surface-2)] text-[var(--fg)] transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Command className="w-3.5 h-3.5 text-[var(--emerald)]" />
                  <span>{item.label}</span>
                </div>
                <span className="text-xs font-mono text-[var(--subtle)]">{item.category}</span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
