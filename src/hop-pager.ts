/** One full-height route hop per page; scrolling always navigates between hops. */
export function createHopPager(viewport: HTMLElement, count: number, onSelect: (index: number) => void, onPause: () => void) {
  let index = 0, target: number | null = null, settleTimer = 0, wheelUntil = 0, pageHeight = -1;
  const clamp = (value: number) => Math.max(0, Math.min(count - 1, value));
  const show = (next: number, smooth = true) => {
    const bounded = clamp(next);
    if (bounded === index && pageHeight === viewport.clientHeight) return;
    index = bounded;
    pageHeight = viewport.clientHeight;
    target = index;
    viewport.scrollTo({ top: index * viewport.clientHeight, behavior: smooth && !window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'smooth' : 'instant' });
  };
  const settle = () => {
    if (!viewport.clientHeight) return;
    const next = clamp(Math.round(viewport.scrollTop / viewport.clientHeight));
    if (target !== null) { if (next === target) target = null; return; }
    if (next !== index) { index = next; onSelect(index); }
  };
  const pause = () => { target = null; onPause(); };
  const scroll = () => { window.clearTimeout(settleTimer); settleTimer = window.setTimeout(settle, 180); };
  const wheel = (event: WheelEvent) => {
    if (!event.deltaY || event.ctrlKey) return;
    onPause();
    event.preventDefault();
    if (performance.now() < wheelUntil) return;
    wheelUntil = performance.now() + 450;
    const next = clamp(index + Math.sign(event.deltaY));
    if (next !== index) { onSelect(next); show(next); }
  };
  const keydown = (event: KeyboardEvent) => {
    if (event.target !== viewport || !['ArrowDown', 'ArrowUp', 'PageDown', 'PageUp', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault(); onPause();
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? count - 1 : clamp(index + (['ArrowDown', 'PageDown'].includes(event.key) ? 1 : -1));
    onSelect(next); show(next);
  };
  viewport.addEventListener('pointerdown', pause);
  viewport.addEventListener('wheel', wheel, { passive: false });
  viewport.addEventListener('keydown', keydown);
  viewport.addEventListener('scroll', scroll, { passive: true });
  viewport.addEventListener('scrollend', settle);
  const observer = new ResizeObserver(() => show(index, false));
  observer.observe(viewport);
  return { show, destroy() {
    observer.disconnect(); window.clearTimeout(settleTimer);
    viewport.removeEventListener('pointerdown', pause); viewport.removeEventListener('wheel', wheel);
    viewport.removeEventListener('keydown', keydown); viewport.removeEventListener('scroll', scroll); viewport.removeEventListener('scrollend', settle);
  } };
}
