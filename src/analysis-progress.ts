export type AnalysisPhase = "reading" | "loading" | "ai" | "identity" | "finishing";
export type AnalysisTimings = Record<AnalysisPhase, number>;
type TimingRuntime = { model: string; accelerator: string; cpu: string; platform?: string; architecture?: string; cpu_only?: boolean; cpu_optimization?: { threads: number; tokens_per_second: number; benchmarked_at: number } };
const phases: AnalysisPhase[] = ["reading", "loading", "ai", "identity", "finishing"];
const STORAGE_KEY = "fishstop-analysis-durations-v1";
const PHASE_STORAGE_KEY = "fishstop-analysis-phases-v1";
const validDuration = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 3_600_000;
function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}
export function analysisTimingProfile(runtime: TimingRuntime | null): string {
  // Capability stays stable when the model unloads, unlike loaded_on_gpu.
  const execution = /mlx/i.test(runtime?.accelerator || "") ? "mlx" : runtime?.cpu_only ? "cpu" : runtime?.cpu_only === false ? "accelerated" : runtime?.accelerator || "unknown";
  const optimization = runtime?.cpu_only ? runtime.cpu_optimization : undefined;
  return JSON.stringify([runtime?.model || "unknown", execution, runtime?.platform, runtime?.architecture, runtime?.cpu, optimization?.threads, optimization?.benchmarked_at]);
}
export function defaultAnalysisTimings(runtime: TimingRuntime | null): AnalysisTimings {
  const fast = /1\.7b/i.test(runtime?.model || "");
  const cpu = runtime?.cpu_only === true || /cpu/i.test(runtime?.accelerator || "");
  // Initial priors only; local measurements replace these after successful runs.
  const inference = cpu ? (fast ? 90_000 : 180_000) : (fast ? 25_000 : 55_000);
  return { reading: 5_000, loading: cpu ? 8_000 : 4_000, ai: inference, identity: inference * .22, finishing: 1_000 };
}
export function analysisDurationEstimate(storage: Pick<Storage, "getItem">, profile: string): number {
  try {
    const values = JSON.parse(storage.getItem(STORAGE_KEY) || "{}")[profile];
    const samples = Array.isArray(values) ? values.filter((v: unknown) => validDuration(v) && v >= 5_000).slice(-8) : [];
    if (samples.length) return median(samples);
  } catch { /* Timing estimates must never prevent analysis. */ }
  return 80_000;
}
export function recordAnalysisDuration(storage: Pick<Storage, "getItem" | "setItem">, profile: string, duration: number): void {
  if (!validDuration(duration) || duration < 5_000) return;
  try {
    let history;
    try { history = JSON.parse(storage.getItem(STORAGE_KEY) || "{}"); } catch { history = {}; }
    if (!history || typeof history !== "object" || Array.isArray(history)) history = {};
    const previous = Array.isArray(history[profile]) ? history[profile] : [];
    history[profile] = [...previous.filter((v: unknown) => validDuration(v) && v >= 5_000), duration].slice(-8);
    storage.setItem(STORAGE_KEY, JSON.stringify(Object.fromEntries(Object.entries(history).slice(-12))));
  } catch { /* Timing history is optional. */ }
}
export function analysisTimingEstimate(storage: Pick<Storage, "getItem">, profile: string, defaults: AnalysisTimings): AnalysisTimings {
  const estimate = { ...defaults };
  try {
    const history = JSON.parse(storage.getItem(PHASE_STORAGE_KEY) || "{}")[profile];
    if (Array.isArray(history)) for (const phase of phases) {
      const values = history.slice(-8).map(item => item?.[phase]).filter(validDuration);
      if (values.length) estimate[phase] = Math.max(250, median(values) * .6 + values[values.length - 1] * .4);
    }
  } catch { /* Unavailable or corrupt storage uses runtime-specific priors. */ }
  return estimate;
}
export function recordAnalysisTimings(storage: Pick<Storage, "getItem" | "setItem">, profile: string, timings: Partial<AnalysisTimings>): void {
  const valid = Object.fromEntries(phases.filter(phase => validDuration(timings[phase])).map(phase => [phase, timings[phase]]));
  if (!Object.keys(valid).length) return;
  try {
    let history;
    try { history = JSON.parse(storage.getItem(PHASE_STORAGE_KEY) || "{}"); } catch { history = {}; }
    if (!history || typeof history !== "object" || Array.isArray(history)) history = {};
    history[profile] = [...(Array.isArray(history[profile]) ? history[profile] : []), valid].slice(-8);
    storage.setItem(PHASE_STORAGE_KEY, JSON.stringify(Object.fromEntries(Object.entries(history).slice(-24))));
  } catch { /* Timing history is optional. */ }
}
export function createAnalysisProgress(startedAt: number, initial: number | AnalysisTimings = 80_000) {
  const fromTotal = (total: number): AnalysisTimings => ({ reading: 5_000, loading: 7_000, ai: Math.max(1_000, total - 15_000) * .8, identity: Math.max(1_000, total - 15_000) * .2, finishing: 3_000 });
  let budgets = typeof initial === "number" ? fromTotal(initial) : { ...initial };
  let phaseIndex = 0, phaseStartedAt = startedAt, percentage = 0, anchor = 0;
  let sectionStartedAt = startedAt, currentSection = 1, totalSections = 1;
  let unitAiBudget = budgets.ai;
  const measured: Partial<AnalysisTimings> = {};
  return {
    setEstimate(value: number | AnalysisTimings) {
      if (typeof value === "number") { if (Number.isFinite(value) && value > 0) budgets = fromTotal(value); }
      else if (phases.every(phase => Number.isFinite(value[phase]) && value[phase] > 0)) budgets = { ...value };
      unitAiBudget = budgets.ai;
      budgets.ai *= totalSections;
    },
    enter(phase: AnalysisPhase, now: number) {
      const next = phases.indexOf(phase);
      if (next > phaseIndex) {
        measured[phases[phaseIndex]] = Math.max(0, now - phaseStartedAt);
        // Missing events must not teach a zero duration for unobserved phases.
        phaseIndex = next; phaseStartedAt = now; sectionStartedAt = now; anchor = percentage;
      }
    },
    section(current: number, total: number, now: number) {
      if (phaseIndex !== phases.indexOf("ai") || !Number.isInteger(current) || !Number.isInteger(total) || current < 1 || total < current) return;
      if (current > currentSection) {
        const observed = (now - sectionStartedAt) / (current - currentSection);
        if (observed > 0) unitAiBudget = observed;
        currentSection = current; sectionStartedAt = now;
      }
      totalSections = total;
      budgets.ai = Math.max(now - phaseStartedAt, (currentSection - 1) * unitAiBudget) + (total - currentSection + 1) * unitAiBudget;
    },
    timings(now: number): Partial<AnalysisTimings> {
      const result = { ...measured, [phases[phaseIndex]]: Math.max(0, now - phaseStartedAt) };
      // Learn inference per section rather than treating a conversation as one email.
      if (result.ai !== undefined) result.ai /= totalSections;
      return result;
    },
    sample(now: number) {
      const elapsed = Math.max(0, now - phaseStartedAt);
      const budget = budgets[phases[phaseIndex]];
      const remaining = phases.slice(phaseIndex + 1).reduce((sum, phase) => sum + budgets[phase], 0);
      const upper = phaseIndex === phases.length - 1 ? 99.5 : anchor + (99.5 - anchor) * budget / (budget + remaining);
      const ratio = elapsed / budget;
      const fraction = ratio <= 1 ? .95 * ratio : .95 + .05 * (1 - Math.exp(-(ratio - 1) / 3));
      percentage = Math.max(percentage, Math.min(99.5, anchor + (upper - anchor) * fraction));
      const total = phases.reduce((sum, phase) => sum + budgets[phase], 0);
      const estimate = Math.max(total, now - startedAt + Math.max(0, budget - elapsed) + remaining);
      const seconds = Math.max(5, Math.round(estimate / 5_000) * 5);
      const duration = seconds < 60 ? `${seconds} seconds` : `${Math.floor(seconds / 60)} min${seconds % 60 ? ` ${seconds % 60} sec` : ""}`;
      return { percentage, hint: elapsed > budget * 1.2
        ? "This step is taking longer than estimated. Analysis is still running on this device."
        : `Estimated analysis time: about ${duration} on this computer.` };
    },
  };
}
