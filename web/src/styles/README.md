# Styles

The web UI is drawn in one design language, **Blueprint**: an engineering drawing. Lines, not
shades; square corners; one action colour.

| File            | Holds                                                                              |
| --------------- | ---------------------------------------------------------------------------------- |
| `tokens.css`    | Every colour, size, line width, duration and font, for both themes. Nothing else.  |
| `../index.css`  | Layout rules shared by the whole app.                                              |
| `../components/*.css` | Layout rules of one page or component.                                       |
| `blueprint.css` | The look, loaded last: type, controls, selection, borders, banners, scroll bars.   |

`main.tsx` imports them in that order.

## Rules

- **Tokens only.** A stylesheet never holds a colour, and takes spacing, type size and weight,
  corners, line widths and timing from `var(--token)`. `npm test` (`test/tokens.test.mjs`) fails
  otherwise. One-off layout dimensions (a grid track, a max-width) may stay literal.
- **Need a new value?** Reuse the nearest token. Add one to `tokens.css`, for both themes, only when
  nothing fits and more than one rule will use it.
- **Colour has a job.** `accent` (ember): it acts, or it needs you. `warn`: it might go wrong.
  `danger`: it went wrong. `online`: it is live. `ok`: it went well. `violet`: automation. Never
  colour for decoration, and never colour alone: a status is a shape and a word too.
- **Selected is the inverse fill** (`line` behind, `bg` in front), not a tint.
- **Elevation is one hard shadow** (`shadow`), for dialogs and the drawer. Everything else is flat
  and separated by lines.
- **In TSX**, no colour literals: style with a class, or read a token with `token()` from
  `src/theme.ts` when a library wants a value (the terminal does). The QR code is the exception:
  a scanner needs black on white.

## Themes

`blueprint` (default) and `paper`. The theme is the `data-theme` attribute on `<html>`, set by
`src/theme.ts` from the choice in Settings and remembered in the browser.

## Fonts

Space Grotesk (titles and names) and Space Mono (everything else), bundled in `src/fonts/` under
the SIL Open Font License (the `OFL-*.txt` files beside them).
