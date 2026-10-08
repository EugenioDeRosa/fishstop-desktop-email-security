export type Theme = "light" | "dark";

const THEME_STORAGE_KEY = "fishstop.theme";

export function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')
    ?.setAttribute("content", theme === "dark" ? "#10191d" : "#071b1b");
  const control = document.querySelector<HTMLInputElement>("#night-mode-enabled");
  if (control) control.checked = theme === "dark";
}

export function initializeTheme(): void {
  let theme: Theme = "light";
  try {
    if (localStorage.getItem(THEME_STORAGE_KEY) === "dark") theme = "dark";
  } catch { /* The default appearance also works without browser storage. */ }
  applyTheme(theme);
}

export function setTheme(theme: Theme): boolean {
  applyTheme(theme);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
    return true;
  } catch {
    return false;
  }
}

window.addEventListener("storage", (event) => {
  if (event.key === THEME_STORAGE_KEY || event.key === null) initializeTheme();
});
