// Translates the UI in the browser. The app is written in English; i18n/strings.tsv holds one
// column per language with the English text as the key. Text nodes and the placeholder, title
// and aria-label attributes are swapped by exact match (ignoring surrounding space, a leading
// number such as "12 Mbit/s down" and a trailing colon). Keys with {0}, {1}... match the parts
// that change, e.g. "Last checked {0}." Unknown text stays in English.
// To add a language: add a column to strings.tsv and an entry in LANGS.
(() => {
  const LANGS = {
    en: { name: 'English', locale: 'en-GB' },
    sv: { name: 'Svenska', locale: 'sv-SE' },
    zh: { name: '中文', locale: 'zh-CN' },
    hi: { name: 'हिन्दी', locale: 'hi-IN' },
    es: { name: 'Español', locale: 'es-ES' },
    ar: { name: 'العربية', locale: 'ar', rtl: true },
    fr: { name: 'Français', locale: 'fr-FR' },
  };
  let saved = null;
  try { saved = localStorage.getItem('nm-lang'); } catch { /* storage blocked */ }
  const guess = (navigator.languages || [navigator.language || 'en']).map((l) => l.slice(0, 2).toLowerCase()).find((l) => LANGS[l]);
  const lang = LANGS[saved] ? saved : guess || 'en';
  const dict = new Map();
  const patterns = [];  // keys with {0}, {1}... placeholders, e.g. "Last checked {0} ago."
  const root = document.documentElement;
  root.lang = lang;
  if (LANGS[lang].rtl) root.dir = 'rtl';

  function tr(text) {
    if ((!dict.size && !patterns.length) || !text) return null;
    const t = text.trim();
    if (!t) return null;
    let hit = dict.get(t);
    if (hit) return text.replace(t, hit);
    // a leading number such as "18 sent" or "12 Mbit/s down" (greedy, so all digits stay in the number)
    const m = /^([\d.,\s%+\-–<>~✓✗!·•]+)(\S.*?)(:?)$/.exec(t) || /^()(.+?)(:)$/.exec(t);
    if (m && (hit = dict.get(m[2]))) return text.replace(t, `${m[1].trim() ? m[1].trim() + ' ' : ''}${hit}${m[3]}`);
    for (const [re, out] of patterns) {
      const p = re.exec(t);
      if (p) return text.replace(t, out.replace(/\{(\d)\}/g, (_, i) => (tr(p[+i + 1]) || p[+i + 1]).trim()));
    }
    return null;
  }
  const ATTRS = ['placeholder', 'title', 'aria-label'];
  function fixEl(el) {
    for (const a of ATTRS) {
      const v = el.getAttribute(a);
      const n = v && tr(v);
      if (n && n !== v) el.setAttribute(a, n);
    }
  }
  function walk(node) {
    if (node.nodeType === 3) {
      const n = tr(node.nodeValue);
      if (n && n !== node.nodeValue) node.nodeValue = n;
      return;
    }
    if (node.nodeType !== 1 || node.nodeName === 'SCRIPT' || node.nodeName === 'STYLE') return;
    fixEl(node);
    const w = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      if (n.nodeType === 3) {
        const v = tr(n.nodeValue);
        if (v && v !== n.nodeValue) n.nodeValue = v;
      } else fixEl(n);
    }
  }

  window.i18n = {
    lang,
    locale: LANGS[lang].locale,
    langs: LANGS,
    t: (s) => tr(s) || s,
    set(l) {
      try { localStorage.setItem('nm-lang', l); } catch { /* storage blocked */ }
      location.reload();
    },
    // <select> for the login page and Settings
    picker() {
      return `<select class="lang-pick" aria-label="Language">${Object.entries(LANGS).map(([k, v]) =>
        `<option value="${k}"${k === lang ? ' selected' : ''}>${v.name}</option>`).join('')}</select>`;
    },
  };
  document.addEventListener('change', (e) => { if (e.target.classList?.contains('lang-pick')) window.i18n.set(e.target.value); });
  if (lang === 'en') return;

  // Dialogs: translate the message text too.
  for (const fn of ['alert', 'confirm']) {
    const orig = window[fn].bind(window);
    window[fn] = (msg) => orig(msg == null ? msg : window.i18n.t(String(msg)));
  }

  // Hide the page until the strings are loaded, so English does not flash first.
  root.style.visibility = 'hidden';
  const show = () => { root.style.visibility = ''; };
  setTimeout(show, 2500);
  const appKeys = new Set();
  // Adds the rows of a strings.tsv. A module's rows never replace the app's own texts.
  function load(tsv, fromModule) {
    const rows = tsv.split(/\r?\n/);
    const col = rows[0].split('\t').indexOf(lang);
    if (col < 0) return;
    for (const row of rows.slice(1)) {
      const c = row.split('\t');
      if (!c[0] || !c[col] || (fromModule && appKeys.has(c[0]))) continue;
      if (!fromModule) appKeys.add(c[0]);
      if (/\{\d\}/.test(c[0])) {
        const src = c[0].split(/\{\d\}/).map((x) => x.replace(/[.*+?^$()|[\]\\{}]/g, '\\$&')).join('(.+?)');
        const i = patterns.findIndex((p) => p[0].source === `^${src}$`);
        if (i >= 0) patterns[i][1] = c[col]; else patterns.push([new RegExp(`^${src}$`), c[col]]);
      } else dict.set(c[0], c[col]);
    }
    patterns.sort((a, b) => b[0].source.length - a[0].source.length);  // most specific first
  }
  // The installed modules' own strings.tsv files (needs a login; on the login page it just finds nothing).
  const moduleStrings = () => fetch('api/i18n/modules.tsv', { cache: 'no-store' })
    .then((r) => (r.ok ? r.text() : '')).then((tsv) => { if (tsv) load(tsv, true); }).catch(() => {});
  // The app calls this when a module is installed or updated, so its texts are translated without a reload.
  window.i18n.reloadModules = () => moduleStrings().then(() => { if (document.body) walk(document.body); });
  fetch('i18n/strings.tsv').then((r) => r.text()).then((tsv) => {
    load(tsv, false);
    return moduleStrings();
  }).then(() => {
    const start = () => {
      walk(document.body);
      new MutationObserver((muts) => {
        for (const m of muts) {
          if (m.type === 'childList') m.addedNodes.forEach(walk);
          else if (m.type === 'characterData') walk(m.target);
          else fixEl(m.target);
        }
      }).observe(document.body, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
      show();
    };
    if (document.body) start(); else document.addEventListener('DOMContentLoaded', start);
  }).catch(show);
})();
