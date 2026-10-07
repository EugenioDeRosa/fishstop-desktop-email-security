/** Keep the last successful status while deduplicating concurrent refreshes. */
export function createStatusCache<T>(fetchStatus: () => Promise<T>, ttlMs: number) {
  let value: T | null = null;
  let fetchedAt = 0;
  let epoch = 0;
  let pending: Promise<T> | null = null;
  const invalidate = () => { epoch++; fetchedAt = 0; pending = null; };
  const load = (force = false): Promise<T> => {
    if (force) invalidate();
    if (pending) return pending;
    if (value !== null && fetchedAt && Date.now() - fetchedAt < ttlMs) return Promise.resolve(value);
    const requestEpoch = epoch;
    const request = fetchStatus().then((result) => {
      if (epoch === requestEpoch) { value = result; fetchedAt = Date.now(); }
      return result;
    }).finally(() => { if (pending === request) pending = null; });
    pending = request;
    return request;
  };
  return { peek: () => value, load, invalidate };
}
