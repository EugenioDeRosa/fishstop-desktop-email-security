export type AnalysisPhase = "reading" | "loading" | "ai" | "finishing";
const phases: AnalysisPhase[] = ["reading", "loading", "ai", "finishing"];
const bounds = [[0, 20], [20, 28], [28, 94], [94, 99]];
const STORAGE_KEY = "fishstop-analysis-durations-v1";

export function analysisDurationEstimate(storage: Pick<Storage, "getItem">, profile: string): number {
  try {
    const values = JSON.parse(storage.getItem(STORAGE_KEY) || "{}")[profile];
    const samples = Array.isArray(values) ? values.filter((v: unknown) => typeof v === "number" && Number.isFinite(v) && v >= 5_000 && v <= 900_000).slice(-8).sort((a: number, b: number) => a - b) : [];
    if (samples.length) {
      const middle = Math.floor(samples.length / 2);
      return samples.length % 2 ? samples[middle] : (samples[middle - 1] + samples[middle]) / 2;
    }
  } catch { /* Timing estimates must never prevent analysis. */ }
  return 80_000;
}

export function recordAnalysisDuration(storage: Pick<Storage, "getItem" | "setItem">, profile: string, duration: number): void {
  if (!Number.isFinite(duration) || duration < 5_000 || duration > 900_000) return;
  try {
    let history: Record<string, number[]>;
    try { history = JSON.parse(storage.getItem(STORAGE_KEY) || "{}"); }
    catch { history = {}; }
    if (!history || typeof history !== "object" || Array.isArray(history)) history = {};
    const previous = Array.isArray(history[profile]) ? history[profile] : [];
    history[profile] = [...previous.filter(v => Number.isFinite(v) && v >= 5_000 && v <= 900_000), duration].slice(-8);
    storage.setItem(STORAGE_KEY, JSON.stringify(Object.fromEntries(Object.entries(history).slice(-12))));
  } catch { /* Private browsing or unavailable storage uses the default estimate. */ }
}

export function createAnalysisProgress(startedAt: number, estimate = 80_000) {
  let phaseIndex = 0;
  let phaseStartedAt = startedAt;
  let percentage = 0;
  return {
    setEstimate(value: number) { if (Number.isFinite(value) && value > 0) estimate = value; },
    enter(phase: AnalysisPhase, now: number) {
      const next = phases.indexOf(phase);
      if (next > phaseIndex) { phaseIndex = next; phaseStartedAt = now; }
    },
    sample(now: number) {
      const elapsed = Math.max(0, now - phaseStartedAt);
      const budget = [5_000, 7_000, Math.max(10_000, estimate - 12_000), 3_000][phaseIndex];
      const [lower, upper] = bounds[phaseIndex];
      const ratio = elapsed / budget;
      // Slow continuously as the phase approaches its estimate; leave room for completion.
      const fraction = ratio <= 1 ? .85 * (1 - Math.pow(1 - ratio, 1.5)) : .85 + .15 * (1 - Math.exp(-(ratio - 1) / 3));
      percentage = Math.max(percentage, Math.min(upper - .1, lower + (upper - lower) * fraction));
      const overdue = now - startedAt > estimate * 1.15;
      const minutes = Math.max(1, Math.floor(estimate / 60_000));
      return { percentage, hint: overdue
        ? "The analysis is taking longer than usual. It is still running on this device."
        : `Usually takes about ${minutes}-${minutes + 1} minutes on this computer.` };
    },
  };
}
