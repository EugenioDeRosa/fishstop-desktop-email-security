import { t } from "./i18n";
type NotificationTone = 'success' | 'error' | 'info';
type CloseReason = 'timeout' | 'dismissed' | 'action' | 'cleared' | 'replaced';
type NotifyOptions = {
  action?: { label: string; onAction: () => void };
  durationMs?: number;
  onClose?: (reason: CloseReason) => void;
};
const dismissals: Array<(reason?: CloseReason) => void> = [];

export function clearNotifications(): void {
  [...dismissals].forEach(dismiss => dismiss('cleared'));
}

/** App-wide feedback, kept outside the workspace so navigation cannot erase it. */
export function notify(message: string, tone: NotificationTone = 'success', options: NotifyOptions = {}): void {
  let host = document.querySelector<HTMLElement>('.app-notifications');
  if (!host) {
    host = document.createElement('div');
    host.className = 'app-notifications';
    host.setAttribute('aria-label', t("Notifications"));
    document.body.append(host);
  }
  if (dismissals.length >= 2) dismissals[0]('replaced');
  const duration = options.durationMs ?? (options.action ? 6000 : tone === 'error' ? 7000 : 4000);
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
  close.dataset.notificationClose = '';
  close.setAttribute('aria-label', t("Dismiss notification"));
  close.textContent = '×';
  let timer: ReturnType<typeof setTimeout>;
  let hovered = false;
  let closed = false;
  let countdown: HTMLElement | null = null;
  const dismiss = (reason: CloseReason = 'dismissed') => {
    if (closed) return;
    closed = true;
    clearTimeout(timer);
    item.remove();
    const index = dismissals.indexOf(dismiss);
    if (index >= 0) dismissals.splice(index, 1);
    options.onClose?.(reason);
  };
  const restartCountdown = () => {
    if (!options.action) return;
    countdown?.remove();
    countdown = document.createElement('span');
    countdown.className = 'notification-countdown';
    countdown.setAttribute('aria-hidden', 'true');
    countdown.style.setProperty('--notification-duration', `${duration}ms`);
    item.append(countdown);
  };
  const schedule = () => {
    clearTimeout(timer);
    if (!item.isConnected) return;
    if (!hovered && !item.contains(document.activeElement)) {
      restartCountdown();
      timer = setTimeout(() => dismiss('timeout'), duration);
    }
  };
  close.addEventListener('click', () => dismiss('dismissed'));
  item.addEventListener('pointerenter', () => { hovered = true; clearTimeout(timer); });
  item.addEventListener('pointerleave', () => { hovered = false; schedule(); });
  item.addEventListener('focusin', () => clearTimeout(timer));
  item.addEventListener('focusout', () => queueMicrotask(schedule));
  item.append(icon, text);
  if (options.action) {
    const action = document.createElement('button');
    action.type = 'button';
    action.className = 'notification-action';
    action.textContent = options.action.label;
    action.addEventListener('click', () => {
      if (closed) return;
      options.action!.onAction();
      dismiss('action');
    });
    item.append(action);
  }
  item.append(close);
  host.append(item);
  dismissals.push(dismiss);
  schedule();
}

/**
 * Run a destructive action after a short grace period instead of asking "are you sure?".
 * `apply` updates the interface immediately, `undo` restores it, and `commit` performs the
 * real change once the toast closes for any reason other than Undo.
 */
export function deferWithUndo(message: string, handlers: { apply?: () => void; undo: () => void; commit: () => void | Promise<void> }, durationMs = 6000): void {
  handlers.apply?.();
  notify(message, 'success', {
    durationMs,
    action: { label: t("Undo"), onAction: handlers.undo },
    onClose: reason => { if (reason !== 'action') void handlers.commit(); },
  });
}

// Best effort: if the window closes during a grace period, carry out the pending actions.
window.addEventListener('pagehide', () => clearNotifications());
