# Interface languages

FishStop supports English (`en`, the default) and Italian (`it`). The login and
Settings switches share the `fishstop.language` preference on this device.
Changing it updates the current page, its accessible labels, dates and displayed
numbers. Browser storage failures do not prevent switching; the app explains that
the preference could not be saved. Other windows follow changes via storage events.

Application copy uses `t(key, values)` and the Italian catalog in
`src/locales/it.json`. English copy is the stable lookup key. `html` tagged
templates translate static visible text and accessible attributes before values
are interpolated. They do **not** escape interpolated values: retain the existing
HTML escaping at each call site. They never translate an email subject, sender,
filename or other user content just because it matches a catalog key.

Known native-engine diagnostics are localized only when displayed. Original
email content, quoted evidence, model-produced free-form text, external release
notes and the official GPL text retain their original language. Technical JSON
exports retain canonical English diagnostics, schema keys, verdicts and indicators
regardless of the interface language; localization does not change a security
decision or mutate a saved report.

When adding UI copy, add its Italian translation and preserve all `{0}`-style
placeholders. Keep provider IDs, CSS selectors, protocol values and stored keys
outside translation calls. Add engine messages to the catalog when appropriate,
but do not pass user content to `engineText`.

Run `node --test scripts/test_*.mjs` and `npm run build`. The language regressions
cover persistence, storage errors, other windows, interpolation safety, accessible
copy, engine diagnostics, catalog placeholders and verdict/export invariance.
