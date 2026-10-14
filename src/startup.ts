/** History must be ready; optional machine checks may continue in the background. */
export async function prepareStartup(loadHistory: () => Promise<unknown>, warmUp: () => Promise<unknown>, timeoutMs = 2500): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const warm = Promise.allSettled([Promise.resolve().then(warmUp)]);
  const boundedWarmUp = Promise.race([warm, new Promise<void>(resolve => { timer = setTimeout(resolve, timeoutMs); })]);
  try {
    await Promise.all([Promise.allSettled([Promise.resolve().then(loadHistory)]), boundedWarmUp]);
  } finally {
    clearTimeout(timer);
  }
}
