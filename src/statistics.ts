import { html, t, locale, formatNumber } from "./i18n";

export type StatisticsSample = { analyzedAt: string; tone: "danger" | "review" | "safe"; duration?: number };
export function medianDuration(samples: StatisticsSample[]): number | undefined {
  const values = samples.map(item => item.duration).filter((value): value is number => Number.isFinite(value) && Number(value) > 0).sort((a, b) => a - b);
  const middle = Math.floor(values.length / 2);
  return values.length ? values.length % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2 : undefined;
}

/** Calendar boundaries preserve local days across daylight-saving transitions. */
export function activityBuckets(samples: StatisticsSample[], start: Date, last: Date) {
  const first = new Date(start); first.setHours(0, 0, 0, 0);
  const end = new Date(last); end.setHours(0, 0, 0, 0); end.setDate(end.getDate() + 1);
  const days = Math.round((Date.UTC(last.getFullYear(), last.getMonth(), last.getDate()) - Date.UTC(first.getFullYear(), first.getMonth(), first.getDate())) / 86400000) + 1;
  const monthly = days > 62;
  const boundaries = [first];
  while (boundaries[boundaries.length - 1] < end) {
    const next = new Date(boundaries[boundaries.length - 1]);
    if (monthly) next.setFullYear(next.getFullYear(), next.getMonth() + 1, 1);
    else next.setDate(next.getDate() + (days > 10 ? 7 : 1));
    boundaries.push(next > end ? new Date(end) : next);
  }
  // Very long histories stay readable; group adjacent calendar months if needed.
  const stride = Math.max(1, Math.ceil((boundaries.length - 1) / 12));
  return boundaries.slice(0, -1).filter((_, index) => index % stride === 0).map((from, index) => {
    const to = boundaries[Math.min((index + 1) * stride, boundaries.length - 1)];
    const included = samples.filter(item => { const date = Date.parse(item.analyzedAt); return date >= +from && date < +to; });
    const counts = ["danger", "review", "safe"].map(tone => included.filter(item => item.tone === tone).length);
    const until = new Date(to); until.setDate(until.getDate() - 1);
    const label = from.toLocaleDateString(locale(), monthly ? { month: "short", year: "2-digit" } : { day: "numeric", month: "short" });
    const range = `${from.toLocaleDateString(locale())} – ${until.toLocaleDateString(locale())}`;
    return { label, range, counts, total: included.length };
  });
}

export function statisticsPanels(samples: StatisticsSample[], start: Date, end: Date, reasons: Array<{ label: string; count: number }>, unavailable = ""): string {
  const total = samples.length;
  const labels = [t("High risk"), t("To review"), t("Likely legitimate")];
  const tones = ["high", "medium", "clear"];
  const counts = ["danger", "review", "safe"].map(tone => samples.filter(item => item.tone === tone).length);
  const percentage = (count: number) => total && !unavailable ? `${formatNumber(count / total * 100)}%` : "—";
  const timed = samples.filter(item => Number.isFinite(item.duration) && Number(item.duration) > 0).length;
  const median = medianDuration(samples);
  const duration = median === undefined || unavailable ? "—" : median >= 60000 ? `${formatNumber(median / 60000, 1)} min` : `${formatNumber(median / 1000, 1)} s`;
  const buckets = activityBuckets(samples, start, end);
  const maximum = Math.max(1, ...buckets.map(item => item.total));
  const legend = labels.map((label, index) => html`<span><i class="${tones[index]}" aria-hidden="true"></i>${label}</span>`).join("");
  return html`<section class="statistics-kpis" aria-label="Statistics summary">
    <article><span>Emails analysed</span><strong>${unavailable ? "—" : formatNumber(total)}</strong><small>Saved in this period</small></article>
    <article class="stat-danger"><span>High risk</span><strong>${unavailable ? "—" : formatNumber(counts[0])}</strong><small>${percentage(counts[0])} · ${t("of analyses")}</small></article>
    <article class="stat-review"><span>To review</span><strong>${unavailable ? "—" : formatNumber(counts[1])}</strong><small>${percentage(counts[1])} · ${t("of analyses")}</small></article>
    <article><span>Typical analysis time</span><strong>${duration}</strong><small>${timed && !unavailable ? t("Median of {0} timed analyses", [timed]) : t("No timing data available")}</small></article>
  </section>
  <div class="statistics-view-switch" role="group" aria-label="Statistics view"><button type="button" data-statistics-view="overview" aria-pressed="true" aria-controls="statistics-overview">Overview</button><button type="button" data-statistics-view="signals" aria-pressed="false" aria-controls="statistics-signals">Signals</button></div>
  <div class="statistics-panels" data-view="overview">
    <section class="statistics-overview" id="statistics-overview" aria-label="Overview">
      <article class="statistics-card statistics-activity"><header><p class="page-kicker">ACTIVITY</p><h2>Analyses over time</h2></header>
        <div class="statistics-chart" style="--columns:${buckets.length}">${!total || unavailable ? html`<p class="statistics-chart-empty" role="status">${unavailable || t("No analyses in this period.")}</p>` : ""}
        ${buckets.map(bucket => { const description = `${bucket.range}: ${t("{0} analyses", [bucket.total])}. ${labels.map((label, index) => `${label}: ${bucket.counts[index]}`).join(", ")}`; return html`<div class="statistics-column"><div class="statistics-column-area"><button type="button" class="statistics-stack" style="height:${bucket.total / maximum * 82}%" aria-label="${description}" data-statistics-tooltip="${description}" ${!bucket.total || unavailable ? "hidden" : ""}><b>${bucket.total}</b>${bucket.counts.map((count, index) => html`<i class="${tones[index]}" style="height:${bucket.total ? count / bucket.total * 100 : 0}%"></i>`).join("")}</button></div><span>${bucket.label}</span></div>`; }).join("")}</div>
        <div class="statistics-chart-key">${legend}</div><p class="statistics-tooltip" role="status" aria-live="polite"></p>
      </article>
      <article class="statistics-card statistics-outcomes"><header><p class="page-kicker">DISTRIBUTION</p><h2>Analysis outcomes</h2></header><div class="statistics-segments" role="img" aria-label="${unavailable || labels.map((label, index) => `${label}: ${counts[index]}`).join(", ")}">${!unavailable ? counts.map((count, index) => html`<i class="${tones[index]}" style="width:${total ? count / total * 100 : 0}%"></i>`).join("") : ""}</div><ul>${labels.map((label, index) => html`<li><i class="${tones[index]}" aria-hidden="true"></i><span>${label}</span><strong>${unavailable ? "—" : counts[index]}</strong><small>${percentage(counts[index])}</small></li>`).join("")}</ul></article>
    </section>
    <section class="statistics-card statistics-signals" id="statistics-signals" aria-label="Signals"><header><div><p class="page-kicker">RISK PATTERNS</p><h2>Recurring signals</h2></div><small>Analyses containing each signal</small></header><ol>${reasons.length && !unavailable ? reasons.slice(0, 5).map(item => html`<li><span>${item.label}</span><div><i style="width:${total ? item.count / total * 100 : 0}%"></i></div><strong>${item.count}</strong><small>${percentage(item.count)}</small></li>`).join("") : html`<li class="statistics-signals-empty">${unavailable || t("No risk reasons were recorded in this period.")}</li>`}</ol><p>Each email is counted once per signal. An email can contain multiple signals.</p></section>
  </div><p class="statistics-footnote">Only analyses saved on this device. Clearing history also changes these statistics.</p>`;
}
