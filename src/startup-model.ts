type ModelStatus = { model_ready: boolean; model_download_available: boolean; model: string };
type ModelProgress = { status: string; total?: number; completed?: number };

/** Reuse installed models; first-run downloads finish before the workspace opens. */
export async function ensureStartupModel<T extends ModelStatus>(services: {
  select: () => Promise<T>;
  install: () => Promise<unknown>;
  refresh: () => Promise<T>;
  subscribe: (onProgress: (progress: ModelProgress) => void) => Promise<() => void>;
  update: (message: string, detail: string, percentage?: number) => void;
}): Promise<T> {
  const status = await services.select();
  if (status.model_ready) return status;
  if (!status.model_download_available) throw new Error('The selected AI model is currently unavailable for download.');
  const name = /1\.7b/i.test(status.model) ? 'Fast' : 'Performance';
  const detail = `${name} mode · You only need to download this model once.`;
  services.update('Downloading AI model', detail);
  const unsubscribe = await services.subscribe(progress => {
    const percentage = progress.total && progress.completed !== undefined
      ? Math.max(0, Math.min(100, Math.round(progress.completed / progress.total * 100))) : undefined;
    const phase = (progress.status || '').toLowerCase();
    const message = /verif|checking/.test(phase) ? 'Verifying AI model'
      : percentage === 100 || /install|import|creat|writing/.test(phase) ? 'Installing AI model'
      : percentage !== undefined || /download|pull/.test(phase) ? 'Downloading AI model'
      : 'Preparing AI model';
    services.update(message, detail, percentage);
  });
  try {
    await services.install();
    services.update('Finalizing AI setup', `${name} mode · Checking that your model is ready.`);
    const installed = await services.refresh();
    if (!installed.model_ready) throw new Error('The AI model could not be verified after installation.');
    return installed;
  } finally { unsubscribe(); }
}
