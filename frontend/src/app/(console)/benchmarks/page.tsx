"use client";

import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, Button, Badge, Skeleton } from "@/components/ui/primitives";
import { Play, Clock, TrendingUp, BarChart3 } from "lucide-react";

interface StagePercentiles {
  mean?: number;
  p95?: number;
  p50?: number;
  min?: number;
  max?: number;
  stddev?: number;
}

interface BenchmarkResultData {
  timestamp?: string;
  stage_latencies?: Record<string, StagePercentiles | number>;
  concurrency_scaling?: Record<string, {
    throughput_rps?: number;
    mean?: number;
    p95?: number;
    failure_rate?: number;
    total_requests?: number;
  }> | Array<{
    agents?: number;
    num_agents?: number;
    throughput?: number;
    req_per_sec?: number;
    throughput_rps?: number;
    avg_latency_ms?: number;
    mean?: number;
    p95?: number;
    failure_rate?: number;
  }>;
  ablation_study?: Record<string, {
    mean?: number;
    p95?: number;
    p50?: number;
    stddev?: number;
  }>;
}

export default function BenchmarksPage() {
  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkResultData | null>(null);

  const { isFetching } = useQuery({
    queryKey: ["benchmarks"],
    queryFn: async () => {
      const data = (await api.runPerformanceBenchmark()) as BenchmarkResultData;
      setBenchmarkResult(data);
      return data;
    },
    enabled: false,
    refetchOnWindowFocus: false,
  });

  const runMutation = useMutation({
    mutationFn: () => api.runPerformanceBenchmark(),
    onSuccess: (data) => {
      setBenchmarkResult(data as BenchmarkResultData);
    },
  });

  const isExecuting = runMutation.isPending || isFetching;
  const stageLatencies = benchmarkResult?.stage_latencies || {};

  const scalingEntries: Array<{
    agents: string | number;
    throughput_rps?: number;
    mean_ms?: number;
    p95_ms?: number;
    failure_rate?: number;
  }> = [];

  if (benchmarkResult?.concurrency_scaling) {
    if (Array.isArray(benchmarkResult.concurrency_scaling)) {
      for (const item of benchmarkResult.concurrency_scaling) {
        scalingEntries.push({
          agents: item.agents ?? item.num_agents ?? "N/A",
          throughput_rps: item.throughput_rps ?? item.throughput ?? item.req_per_sec,
          mean_ms: item.mean ?? item.avg_latency_ms,
          p95_ms: item.p95,
          failure_rate: item.failure_rate,
        });
      }
    } else if (typeof benchmarkResult.concurrency_scaling === "object") {
      for (const [key, rawStats] of Object.entries(benchmarkResult.concurrency_scaling)) {
        const stats = rawStats as { throughput_rps?: number; mean?: number; p95?: number; failure_rate?: number };
        scalingEntries.push({
          agents: key,
          throughput_rps: stats?.throughput_rps,
          mean_ms: stats?.mean,
          p95_ms: stats?.p95,
          failure_rate: stats?.failure_rate,
        });
      }
    }
  }

  const ablationEntries = benchmarkResult?.ablation_study ? Object.entries(benchmarkResult.ablation_study) : [];
  const baselineMean = benchmarkResult?.ablation_study?.["Full AgentTrust"]?.mean ?? 0;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[var(--fg)]">
              Performance & Latency Benchmarks
            </h1>
            <Badge variant="outline" className="text-xs font-mono text-[var(--muted)]">
              Empirical Profiler
            </Badge>
          </div>
          <p className="text-sm text-[var(--muted)] mt-1">
            Empirical latency, throughput, concurrency scaling, and stage-by-stage pipeline profiling.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="primary"
            size="sm"
            onClick={() => runMutation.mutate()}
            disabled={isExecuting}
          >
            <Play className="w-4 h-4 mr-2" />
            {isExecuting ? "Executing Benchmarks..." : "Run Performance Profiler"}
          </Button>
        </div>
      </div>

      {/* Metadata Hardware & Sample Size Strip */}
      <Card className="p-4 bg-[var(--surface-2)] border-[var(--border)] grid grid-cols-1 sm:grid-cols-4 gap-4 text-xs">
        <div>
          <span className="text-[var(--muted)] block mb-0.5">Benchmark Run Timestamp</span>
          <span className="font-mono text-[var(--fg)] font-semibold">
            {benchmarkResult?.timestamp ? new Date(benchmarkResult.timestamp).toLocaleString() : "Awaiting Benchmark Run"}
          </span>
        </div>

        <div>
          <span className="text-[var(--muted)] block mb-0.5">Sample Size</span>
          <span className="font-mono text-[var(--accent)] font-bold">
            {benchmarkResult ? "N = 50 iterations / stage" : "N = 50 (Configured)"}
          </span>
        </div>

        <div>
          <span className="text-[var(--muted)] block mb-0.5">Execution Engine</span>
          <span className="font-mono text-[var(--fg)]">
            FastAPI + PyCryptodome + SQLite
          </span>
        </div>

        <div>
          <span className="text-[var(--muted)] block mb-0.5">Hardware Environment</span>
          <span className="font-mono text-[var(--fg)] truncate">
            Local Node Host Environment
          </span>
        </div>
      </Card>

      {/* Grid: Stage Latency Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Stage Latencies */}
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
            <h3 className="font-bold text-sm text-[var(--fg)] flex items-center gap-2">
              <Clock className="w-4 h-4 text-[var(--accent)]" />
              Pipeline Stage Latency Profiling
            </h3>
            <span className="text-xs text-[var(--muted)] font-mono">
              ms (Mean / P95)
            </span>
          </div>

          {isExecuting ? (
            <div className="space-y-2">
              {[1, 2, 3, 4, 5, 6].map((n) => (
                <Skeleton key={n} className="h-8 w-full rounded-md" />
              ))}
            </div>
          ) : Object.keys(stageLatencies).length === 0 ? (
            <p className="text-xs text-[var(--muted)] py-8 text-center">
              No latency profile recorded. Click &quot;Run Performance Profiler&quot; above to measure exact per-stage execution times.
            </p>
          ) : (
            <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
              {Object.entries(stageLatencies).map(([stageName, metrics], idx) => {
                const metricObj = metrics as StagePercentiles | number;
                const meanMs = typeof metricObj === "number" ? metricObj : metricObj?.mean;
                const p95Ms = typeof metricObj === "object" ? metricObj?.p95 : undefined;

                return (
                  <div
                    key={stageName}
                    className="p-2.5 rounded-lg bg-[var(--bg)] border border-[var(--border)] flex items-center justify-between text-xs font-mono"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-[var(--accent)] font-bold text-[11px] w-5">
                        #{idx + 1}
                      </span>
                      <span className="text-[var(--fg)] font-medium">
                        {stageName.replace(/_/g, " ")}
                      </span>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="text-[var(--muted)]">
                        Mean: <strong className="text-[var(--fg)]">{meanMs !== undefined ? `${meanMs.toFixed(3)} ms` : "N/A"}</strong>
                      </span>
                      <span className="text-[var(--muted)]">
                        P95: <strong className="text-[var(--accent)]">{p95Ms !== undefined ? `${p95Ms.toFixed(3)} ms` : "N/A"}</strong>
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* Concurrency Scaling & Ablation */}
        <div className="space-y-6">
          {/* Concurrency Card */}
          <Card className="p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
              <h3 className="font-bold text-sm text-[var(--fg)] flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-emerald-400" />
                Concurrent Agent Throughput Scaling
              </h3>
              <span className="text-xs text-[var(--muted)] font-mono">
                Req / Sec
              </span>
            </div>

            {isExecuting ? (
              <Skeleton className="h-36 w-full rounded-lg" />
            ) : scalingEntries.length === 0 ? (
              <p className="text-xs text-[var(--muted)] py-6 text-center">
                No concurrency scaling data recorded yet. Click &quot;Run Performance Profiler&quot; above.
              </p>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                {scalingEntries.map((item, i: number) => (
                  <div
                    key={`scaling-${item.agents}-${i}`}
                    className="p-3 rounded-lg bg-[var(--bg)] border border-[var(--border)] text-center space-y-1"
                  >
                    <span className="text-[11px] text-[var(--muted)] font-mono block">
                      {item.agents} Agents
                    </span>
                    <div className="font-bold font-mono text-emerald-400 text-base">
                      {item.throughput_rps !== undefined ? `${item.throughput_rps.toFixed(1)} rps` : "N/A"}
                    </div>
                    <div className="text-[10px] text-[var(--muted)] font-mono flex flex-col gap-0.5">
                      <span>Mean: {item.mean_ms !== undefined ? `${item.mean_ms.toFixed(2)} ms` : "N/A"}</span>
                      <span>P95: {item.p95_ms !== undefined ? `${item.p95_ms.toFixed(2)} ms` : "N/A"}</span>
                      {item.failure_rate !== undefined && (
                        <span className={item.failure_rate > 0 ? "text-red-400" : "text-emerald-400"}>
                          Errors: {(item.failure_rate * 100).toFixed(1)}%
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Ablation Study Card */}
          <Card className="p-5 space-y-3">
            <h3 className="font-bold text-sm text-[var(--fg)] flex items-center gap-2 pb-2 border-b border-[var(--border)]">
              <BarChart3 className="w-4 h-4 text-amber-400" />
              Security Module Ablation Overhead
            </h3>
            <p className="text-xs text-[var(--muted)]">
              Empirical latency measured by selectively disabling security stages under benchmark harness.
            </p>

            {isExecuting ? (
              <Skeleton className="h-28 w-full rounded-lg" />
            ) : ablationEntries.length === 0 ? (
              <p className="text-xs text-[var(--muted)] py-4 text-center">
                No ablation data recorded yet. Click &quot;Run Performance Profiler&quot; above.
              </p>
            ) : (
              <div className="space-y-2 text-xs font-mono">
                {ablationEntries.map(([modeName, metrics]) => {
                  const isBaseline = modeName === "Full AgentTrust";
                  const mean = metrics?.mean;
                  const delta = baselineMean > 0 && mean !== undefined && !isBaseline
                    ? ((mean - baselineMean) / baselineMean) * 100
                    : null;

                  return (
                    <div
                      key={modeName}
                      className="p-2.5 rounded bg-[var(--bg)] border border-[var(--border)] flex items-center justify-between"
                    >
                      <span className={isBaseline ? "font-bold text-[var(--fg)]" : "text-[var(--muted)]"}>
                        {modeName}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className={isBaseline ? "text-[var(--accent)] font-bold" : "text-[var(--fg)]"}>
                          {mean !== undefined ? `${mean.toFixed(2)} ms` : "N/A"}
                        </span>
                        {delta !== null && (
                          <span className={`text-[11px] ${delta <= 0 ? "text-emerald-400" : "text-amber-400"}`}>
                            ({delta <= 0 ? `${delta.toFixed(1)}%` : `+${delta.toFixed(1)}%`})
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
