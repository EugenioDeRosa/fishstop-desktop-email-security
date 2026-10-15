import { t, html } from "./i18n";
import { isTauri } from "@tauri-apps/api/core";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import "./app-updates.css";

const AUTO_UPDATES_KEY = "fishstop.automatic-update-checks";
export function automaticUpdatesEnabled(): boolean {
  try { return localStorage.getItem(AUTO_UPDATES_KEY) !== "false"; }
  catch { return true; }
}
export function setAutomaticUpdatesEnabled(enabled: boolean): boolean {
  try {
    localStorage.setItem(AUTO_UPDATES_KEY, String(enabled));
    window.dispatchEvent(new Event("fishstop:auto-updates-change"));
    return true;
  } catch { return false; }
}

export function updateCheckFailure(error: unknown): string {
  const message = String(error);
  if (/valid release JSON|release.?not.?found|\b404\b/i.test(message)) {
    return t("Updates are not available yet. Please try again after the next release.");
  }
  if (/platform.*not found|fallback platforms|unsupported.*(architecture|OS)/i.test(message)) {
    return t("No update package is available for this computer yet.");
  }
  if (/timeout|timed out|offline|dns|connect|network|error sending request/i.test(message)) {
    return t("Could not reach the update service. Please try again later.");
  }
  return t("The update service is temporarily unavailable. Please try again later.");
}

/** Kept outside the workspace root so navigation cannot discard an update. */
export function startAppUpdates(isBusy: () => boolean): void {
  if (!isTauri()) return;
  const dialog = document.createElement("dialog");
  dialog.className = "app-update-dialog";
  dialog.setAttribute("aria-labelledby", "app-update-title");
  dialog.innerHTML = html`<h2 id="app-update-title">App updates</h2><p data-update-summary></p><p data-update-notes></p><progress hidden aria-label="Update download"></progress><p data-update-status role="status" aria-live="polite"></p><div class="app-update-actions"><button type="button" data-update-later>Later</button><button type="button" data-update-install>Install update</button><button type="button" data-update-restart hidden>Restart FishSTOP</button></div>`;
  document.body.append(dialog);
  const summary = dialog.querySelector<HTMLElement>("[data-update-summary]")!;
  const notes = dialog.querySelector<HTMLElement>("[data-update-notes]")!;
  const status = dialog.querySelector<HTMLElement>("[data-update-status]")!;
  const progress = dialog.querySelector<HTMLProgressElement>("progress")!;
  const later = dialog.querySelector<HTMLButtonElement>("[data-update-later]")!;
  const install = dialog.querySelector<HTMLButtonElement>("[data-update-install]")!;
  const restart = dialog.querySelector<HTMLButtonElement>("[data-update-restart]")!;
  window.addEventListener("fishstop:language-change", () => {
    dialog.querySelector("h2")!.textContent = t("App updates");
    later.textContent = t("Later");
    install.textContent = t("Install update");
    restart.textContent = t("Restart FishSTOP");
    progress.setAttribute("aria-label", t("Update download"));
  });
  let pending: Update | null = null;
  let checking = false;
  let installing = false;
  let installed = false;
  let deferred = false;
  let nextCheck = Date.now() + 10000;
  const dismissed = new Set<string>();
  function checkStatus(message: string) {
    document.querySelectorAll<HTMLElement>("[data-app-update-check-status]").forEach(element => { element.textContent = message; });
  }
  function showUpdate() {
    if (!pending || dialog.open) return;
    if (isBusy()) { deferred = true; return; }
    deferred = false;
    summary.textContent = t("FishSTOP {0} is available (current version: {1}).", [pending.version, pending.currentVersion]);
    notes.textContent = pending.body || t("A new version of FishSTOP is ready to install.");
    status.textContent = t("Installation will close and restart FishSTOP.");
    progress.hidden = true;
    install.hidden = false;
    install.disabled = false;
    later.disabled = false;
    restart.hidden = true;
    dialog.showModal();
  }
  async function checkForUpdates(manual = false) {
    if (!manual && !automaticUpdatesEnabled()) return;
    if (checking || installing || installed || dialog.open) return;
    if (isBusy()) {
      if (manual) checkStatus(t("Finish the current operation before checking for updates."));
      return;
    }
    checking = true;
    if (manual) checkStatus(t("Checking for updates…"));
    try {
      const update = await check({ timeout: 15000 });
      await pending?.close();
      pending = update;
      checkStatus(update ? t("FishSTOP {0} is available.", [update.version]) : t("You are using the latest version of FishSTOP."));
      if (update && (manual || (automaticUpdatesEnabled() && !dismissed.has(update.version)))) { later.textContent = t("Later"); showUpdate(); }
    } catch (error) {
      console.warn("App update check failed", error);
      if (manual) checkStatus(updateCheckFailure(error));
    } finally { checking = false; nextCheck = Date.now() + 60 * 60 * 1000; }
  }
  function dismiss() {
    if (installing || installed) return;
    if (pending) dismissed.add(pending.version);
    deferred = false;
    dialog.close();
  }
  later.addEventListener("click", dismiss);
  dialog.addEventListener("cancel", event => { event.preventDefault(); dismiss(); });
  async function restartApp() {
    restart.disabled = true;
    try { await relaunch(); }
    catch { status.textContent = t("Update installed. Close and reopen FishSTOP, or try restarting again."); restart.disabled = false; }
  }
  restart.addEventListener("click", () => { void restartApp(); });
  install.addEventListener("click", async () => {
    if (!pending || installing || installed) return;
    // The modal itself counts as busy; check operations independently below.
    dialog.close();
    const busy = isBusy();
    dialog.showModal();
    if (busy) { status.textContent = t("Finish the current operation before installing."); return; }
    installing = true;
    install.disabled = true; later.disabled = true;
    progress.hidden = false; progress.removeAttribute("value");
    let downloaded = 0;
    let total = 0;
    status.textContent = t("Downloading update…");
    try {
      await pending.downloadAndInstall(event => {
        if (event.event === "Started") { total = event.data.contentLength || 0; downloaded = 0; }
        if (event.event === "Progress") {
          downloaded += event.data.chunkLength;
          if (total) { progress.max = total; progress.value = downloaded; status.textContent = t("Downloading update… {0}%", [Math.min(100, Math.round(downloaded / total * 100))]); }
        }
        if (event.event === "Finished") { status.textContent = t("Verifying and installing update…"); progress.removeAttribute("value"); }
      });
      installed = true;
      install.hidden = true; progress.hidden = true; restart.hidden = false;
      status.textContent = t("Update installed. Restarting FishSTOP…");
      await restartApp();
    } catch (error) {
      console.error("App update installation failed", error);
      status.textContent = t("Could not install the update. Check your connection and try again. Your current version is still available.");
      progress.hidden = true; install.disabled = false; later.disabled = false;
    } finally { installing = false; }
  });
  document.addEventListener("click", event => {
    const button = (event.target as Element)?.closest<HTMLButtonElement>("[data-check-app-updates]");
    if (!button) return;
    button.disabled = true;
    void checkForUpdates(true).finally(() => { button.disabled = false; });
  });
  // Silent network failures never block startup or interrupt an analysis.
  setInterval(() => {
    if (document.hidden || !automaticUpdatesEnabled()) return;
    if (deferred) showUpdate();
    else if (Date.now() >= nextCheck) void checkForUpdates();
  }, 5000);
  window.addEventListener("fishstop:auto-updates-change", () => {
    if (automaticUpdatesEnabled()) nextCheck = Date.now() + 10000;
  });
  window.addEventListener("online", () => { void checkForUpdates(); });
}
