type HopBrowser = { select: (order: number) => void };
const browsers = new WeakMap<HTMLElement, HopBrowser>();

/** Keep the original detail nodes so Copy IP and other evidence actions retain their handlers. */
export function createHopBrowser(element: HTMLElement): HopBrowser {
  const existing = browsers.get(element);
  if (existing) return existing;
  const list = element.querySelector<HTMLElement>(".globe-hop-list")!;
  const entries = Array.from(list.querySelectorAll<HTMLDetailsElement>("details[data-hop-order]")).map((original) => {
    const order = Number(original.dataset.hopOrder);
    const summary = original.querySelector("summary")!;
    const label = summary.querySelector("strong")?.textContent || `Hop ${order}`;
    const card = document.createElement("section");
    card.className = `${original.className} hop-focus-card`;
    card.dataset.hopOrder = String(order);
    card.setAttribute("aria-label", `Hop ${order} details`);
    const heading = document.createElement("div");
    heading.className = "hop-focus-heading";
    if (summary.firstElementChild) heading.append(summary.firstElementChild);
    card.append(heading);
    const details = original.querySelector(".hop-details");
    if (details) card.append(details);
    original.replaceWith(card);
    return { order, label, card };
  });
  element.querySelector(":scope > h4")?.remove();
  element.querySelector(":scope > p")?.remove();
  const controls = document.createElement("div");
  controls.className = "hop-navigation";
  controls.innerHTML = `<div class="hop-navigation-heading"><span>MESSAGE HOPS</span><span data-hop-position role="status" aria-live="polite"></span></div><div class="hop-navigation-controls"><button type="button" data-hop-previous aria-label="Previous hop">‹</button><div class="hop-select-wrap"><select aria-label="Select hop"></select><span aria-hidden="true">⌄</span></div><button type="button" data-hop-next aria-label="Next hop">›</button></div><div class="hop-step-track" role="group" aria-label="Route hops"></div>`;
  list.before(controls);
  const select = controls.querySelector("select")!;
  const previous = controls.querySelector<HTMLButtonElement>("[data-hop-previous]")!;
  const next = controls.querySelector<HTMLButtonElement>("[data-hop-next]")!;
  const position = controls.querySelector<HTMLElement>("[data-hop-position]")!;
  const track = controls.querySelector<HTMLElement>(".hop-step-track")!;
  let active = -1;
  const steps = entries.map((entry, index) => {
    const option = document.createElement("option");
    option.value = String(entry.order); option.textContent = entry.label; select.append(option);
    const button = document.createElement("button");
    button.type = "button"; button.textContent = String(entry.order);
    button.setAttribute("aria-label", entry.label);
    button.addEventListener("click", () => choose(index, true));
    button.addEventListener("keydown", (event) => {
      const target = event.key === "ArrowRight" ? index + 1 : event.key === "ArrowLeft" ? index - 1 : event.key === "Home" ? 0 : event.key === "End" ? entries.length - 1 : -1;
      if (target < 0 || target >= entries.length) return;
      event.preventDefault(); choose(target, true); steps[target].focus();
    });
    track.append(button);
    return button;
  });
  function choose(index: number, notify: boolean) {
    if (!entries[index]) return;
    if (index !== active) {
      active = index;
      entries.forEach((entry, current) => {
        entry.card.hidden = current !== index;
        steps[current].setAttribute("aria-pressed", String(current === index));
        steps[current].tabIndex = current === index ? 0 : -1;
      });
      select.value = String(entries[index].order);
      position.textContent = `${String(index + 1).padStart(2, "0")} / ${String(entries.length).padStart(2, "0")}`;
      previous.disabled = index === 0; next.disabled = index === entries.length - 1;
      list.scrollTop = 0;
      const parent = track.getBoundingClientRect(), child = steps[index].getBoundingClientRect();
      if (child.left < parent.left || child.right > parent.right) track.scrollLeft += child.left - parent.left - 4;
    }
    if (notify) element.dispatchEvent(new CustomEvent("hop-selected", { detail: { order: entries[index].order } }));
  }
  previous.addEventListener("click", () => choose(active - 1, true));
  next.addEventListener("click", () => choose(active + 1, true));
  select.addEventListener("change", () => choose(entries.findIndex((entry) => String(entry.order) === select.value), true));
  const browser = { select: (order: number) => choose(entries.findIndex((entry) => entry.order === order), false) };
  browsers.set(element, browser);
  if (entries.length) choose(0, false);
  else { controls.hidden = true; }
  return browser;
}
