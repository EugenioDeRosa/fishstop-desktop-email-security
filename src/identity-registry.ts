type Relation = { domain: string; role: string; scopes: string[] };
type Partner = { id: string; brand: string; reference: string; source: string; expires_at: number; relations: Relation[] };
type Response = { records?: Partner[]; record_name?: string; record_value?: string; message?: string };

export function identityRegistryMarkup(): string {
  return `<section class="settings-card identity-registry"><p class="page-kicker">IDENTITY PROTECTION</p><h2>Verified partners</h2><p class="settings-note">Confirm company domains using a known contact or an independent company record. These relationships help detect impersonation, including smaller businesses. A confirmed identity does not guarantee that a message is safe.</p><div id="identity-partners"></div><details><summary>Add a verified company</summary><form id="identity-partner-form" class="identity-partner-form"><label>Company name<input name="brand" required minlength="2" maxlength="100" autocomplete="organization" /></label><label>Official domain<input name="domain" required placeholder="company.com" /></label><label>Other company names <small>Optional, separated by commas</small><input name="aliases" maxlength="500" /></label><label>Authorized mail service domain <small>Optional. Permits sending only.</small><input name="delegate" placeholder="notifications.company-service.com" /></label><label>How you confirmed the relationship<textarea name="reference" required minlength="8" maxlength="1000" placeholder="Known supplier contact, independently verified website, or company register reference"></textarea></label><label class="identity-confirmation"><input name="confirmed" type="checkbox" required />I independently confirmed this company and its domains. I am not relying on the message being analysed.</label><button class="primary-action" type="submit">Save for 90 days</button></form></details><details><summary>Optional domain control check</summary><p class="settings-note">A domain owner can publish a verification record. This confirms control of the domain; the company identity must still be checked independently.</p><div class="identity-partner-form"><label>Domain<input id="identity-control-domain" placeholder="company.com" /></label><button class="soft-action" type="button" id="identity-create-challenge">Create verification record</button><pre id="identity-control-record" hidden></pre><button class="soft-action" type="button" id="identity-check-control">Check published record</button></div></details><details><summary>Administrator directory</summary><p class="settings-note">Import a signed directory supplied by your administrator. Signing keys must be configured separately. Each company and delegated service includes an expiry and permitted activities.</p><label class="soft-action identity-import">Import signed directory<input id="identity-import" type="file" accept="application/json,.json" /></label></details><p id="identity-registry-status" class="settings-status" aria-live="polite"></p></section>`;
}

export function bindIdentityRegistry(root: HTMLElement, call: (request: object) => Promise<Response>, escape: (value: string) => string): void {
  const status = root.querySelector<HTMLElement>("#identity-registry-status");
  const list = root.querySelector<HTMLElement>("#identity-partners");
  if (!status || !list) return;
  let busy = false;
  let revision = 0;
  const render = (result: Response) => {
    list.innerHTML = result.records?.length ? `<ul class="identity-partner-list">${result.records.map(record => `<li><div><strong>${escape(record.brand)}</strong><small>${escape(record.relations.map(relation => relation.domain).join(", "))}</small><small>Valid until ${escape(new Date(record.expires_at * 1000).toLocaleDateString())} · ${record.source === "signed_directory" ? "Signed directory" : "Administrator confirmed"}</small></div>${record.source === "administrator_confirmation" ? `<button class="soft-action" type="button" data-revoke-identity="${escape(record.id)}">Revoke</button>` : ""}</li>`).join("")}</ul>` : `<p class="settings-note">No locally confirmed companies yet. Unknown identities remain unverified.</p>`;
  };
  const perform = async (request: object) => {
    if (busy) return;
    busy = true;
    const requestRevision = ++revision;
    status.textContent = "Checking identity evidence…";
    root.querySelectorAll<HTMLButtonElement>("button").forEach(button => { button.disabled = true; });
    try {
      const result = await call(request);
      if (!root.isConnected || revision !== requestRevision) return;
      if (result.records) render(result);
      status.textContent = result.message || "Identity register updated.";
      return result;
    } catch (error) {
      if (root.isConnected) status.textContent = typeof error === "string" ? error : "Identity verification could not be completed. Please try again.";
    } finally {
      busy = false;
      root.querySelectorAll<HTMLButtonElement>("button").forEach(button => { button.disabled = false; });
    }
  };
  const initialRevision = revision;
  void call({ operation: "list" }).then(result => { if (root.isConnected && revision === initialRevision) render(result); }).catch(() => { if (root.isConnected && revision === initialRevision) status.textContent = "The identity register is unavailable."; });
  list.addEventListener("click", event => {
    const button = (event.target as HTMLElement).closest<HTMLButtonElement>("[data-revoke-identity]");
    if (button) void perform({ operation: "remove", id: button.dataset.revokeIdentity });
  });
  root.querySelector<HTMLFormElement>("#identity-partner-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const values = new FormData(form);
    const officialScopes = ["sender", "reply", "visit_link", "open_attachment", "provide_credentials", "provide_information", "pay_or_transfer", "verify_account", "change_account_settings", "claim_reward"];
    const relations = [{ domain: String(values.get("domain") || "").trim().toLowerCase(), role: "official", scopes: officialScopes }];
    if (values.get("delegate")) relations.push({ domain: String(values.get("delegate")).trim().toLowerCase(), role: "delegate", scopes: ["sender"] });
    const result = await perform({ operation: "add", brand: values.get("brand"), aliases: String(values.get("aliases") || "").split(",").map(value => value.trim()).filter(Boolean), relations, reference: values.get("reference"), identity_confirmed: values.get("confirmed") === "on" });
    if (result && form.isConnected) form.reset();
  });
  const domain = () => root.querySelector<HTMLInputElement>("#identity-control-domain")?.value.trim().toLowerCase();
  root.querySelector("#identity-create-challenge")?.addEventListener("click", async () => {
    const result = await perform({ operation: "challenge", domain: domain() });
    const record = root.querySelector<HTMLElement>("#identity-control-record");
    if (result?.record_name && record) { record.hidden = false; record.textContent = `TXT name: ${result.record_name}\nTXT value: ${result.record_value}`; }
  });
  root.querySelector("#identity-check-control")?.addEventListener("click", () => { void perform({ operation: "verify-control", domain: domain() }); });
  root.querySelector<HTMLInputElement>("#identity-import")?.addEventListener("change", async event => {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    try {
      if (file.size > 2 * 1024 * 1024) throw Error("Directory is too large.");
      await perform({ operation: "import", bundle: JSON.parse(await file.text()) });
    } catch { status.textContent = "Choose a valid signed directory JSON file smaller than 2 MB."; }
    input.value = "";
  });
}
