// The UI theme: Blueprint (the default) or Paper. It is the data-theme attribute on <html>, which
// styles/tokens.css keys every colour on, and is remembered in this browser.

export type Theme = 'blueprint' | 'paper';

export const themes: { id: Theme; label: string; hint: string }[] = [
  { id: 'blueprint', label: 'Blueprint', hint: 'White lines on blue. The default.' },
  { id: 'paper', label: 'Paper', hint: 'Dark lines on white, for bright rooms and print.' },
];

const storageKey = 'hearth.theme';

/** The theme this browser chose, or Blueprint. */
export function storedTheme(): Theme {
  try {
    return localStorage.getItem(storageKey) === 'paper' ? 'paper' : 'blueprint';
  } catch {
    return 'blueprint';
  }
}

/** A design token's value under the current theme, such as token('accent'). */
export function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim();
}

/** Switches the page to a theme, and the browser chrome with it. */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  const bg = token('bg');
  if (bg) {
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', bg);
  }
}

/** Applies a theme and remembers it. */
export function chooseTheme(theme: Theme): void {
  try {
    localStorage.setItem(storageKey, theme);
  } catch {
    // Private mode: the choice lasts for this page only.
  }
  applyTheme(theme);
}
