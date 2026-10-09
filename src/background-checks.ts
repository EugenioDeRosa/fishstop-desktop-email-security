// Pause admission first, then drain existing checks before analysis starts.
export function createBackgroundChecks() {
  let pauses = 0;
  const pending = new Set<Promise<unknown>>();
  return {
    get paused() { return pauses > 0; },
    async run(task: () => Promise<void>): Promise<void> {
      if (pauses) return;
      const request = Promise.resolve().then(task);
      pending.add(request);
      try { await request; } finally { pending.delete(request); }
    },
    async pause(): Promise<() => void> {
      pauses += 1;
      await Promise.allSettled([...pending]);
      let released = false;
      return () => { if (!released) { released = true; pauses -= 1; } };
    },
  };
}
