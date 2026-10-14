type NotificationTone = 'success' | 'error' | 'info';
const dismissals: Array<() => void> = [];

export function clearNotifications(): void {
  [...dismissals].forEach(dismiss => dismiss());
}

/** App-wide feedback, kept outside the workspace so navigation cannot erase it. */
export function notify(message: string, tone: NotificationTone = 'success'): void {
  let host = document.querySelector<HTMLElement>('.app-notifications');
  if (!host) {
    host = document.createElement('div');
    host.className = 'app-notifications';
    host.setAttribute('aria-label', 'Notifications');
    document.body.append(host);
  }
  if (dismissals.length >= 2) dismissals[0]();
  const item = document.createElement('div');
  item.className = `app-notification notification-${tone}`;
  item.setAttribute('role', tone === 'error' ? 'alert' : 'status');
  item.setAttribute('aria-atomic', 'true');
  const icon = document.createElement('span');
  icon.className = 'notification-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = tone === 'success' ? '✓' : tone === 'error' ? '!' : 'i';
  const text = document.createElement('span');
  text.className = 'notification-message';
  text.textContent = message;
  const close = document.createElement('button');
  close.type = 'button';
  close.setAttribute('aria-label', 'Dismiss notification');
  close.textContent = '×';
  let timer: ReturnType<typeof setTimeout>;
  let hovered = false;
  const dismiss = () => {
    clearTimeout(timer);
    item.remove();
    const index = dismissals.indexOf(dismiss);
    if (index >= 0) dismissals.splice(index, 1);
  };
  const schedule = () => {
    clearTimeout(timer);
    if (!item.isConnected) return;
    if (!hovered && !item.contains(document.activeElement)) timer = setTimeout(dismiss, tone === 'error' ? 7000 : 4000);
  };
  close.addEventListener('click', dismiss);
  item.addEventListener('pointerenter', () => { hovered = true; clearTimeout(timer); });
  item.addEventListener('pointerleave', () => { hovered = false; schedule(); });
  item.addEventListener('focusin', () => clearTimeout(timer));
  item.addEventListener('focusout', () => queueMicrotask(schedule));
  item.append(icon, text, close);
  host.append(item);
  dismissals.push(dismiss);
  schedule();
}
