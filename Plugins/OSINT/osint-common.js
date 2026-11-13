/* Shared pieces of the OSINT dashboard panels (2026-11-04):
   Google Dorks (osint-dorks.js), Shodan (osint-shodan.js), crt.sh
   (osint-crtsh.js) and Wayback Machine (osint-wayback.js).

   1. ONE TARGET for every panel -- name or domain, extensions, ✱ wildcard
      -- stored once (TARGET_KEY) and kept in sync: typing it in any panel
      updates the others. Each panel renders its own target bar
      (renderTargetBar) so it still works when shown alone on another
      dashboard.
        abc.com            -> one domain, used as is
        abc / abc* / abc.* -> name + ticked extensions (abc.com, abc.ca, …)
                              (+ the ✱ wildcard, each panel says what it
                              turns into: engines have no real domain
                              wildcard)

   2. createBuilder(): the criteria builder used by Google Dorks and
      Shodan -- "+ Ajouter un critère", category ▾ / element ▾, the
      element's values as checkboxes (+ your own), live preview, copy,
      open. The query syntax itself comes from a "dialect" (see the two
      panel files): how one criterion's values are written and joined,
      and what the wildcard becomes.

   Everything is local: nothing is requested until the user clicks an
   "open" link (a plain target=_blank anchor). Each opened link goes to
   the System log. */

window.NeonFlareOsint = window.NeonFlareOsint || {};
// Construit une seule fois, au premier mount() (plugin : rien ne s'exécute au chargement).
window.NeonFlareOsint.kit = function () {
  if (window.OsintKit) return window.OsintKit;
  const PLACEHOLDER = "<domain>";
  const TARGET_KEY = "/dashboard.html/osintTarget";
  const LEGACY_DORKS_KEY = "/dashboard.html/dorks"; // target/tld/wild lived here first
  const PRESET_TLDS = ["com", "ca", "net", "org", "io", "fr", "co", "info", "biz", "us"];
  const DEFAULT_TLDS = ["com", "ca"];

  const L = (typeof getSavedLang === "function" && getSavedLang() === "en") ? "en" : "fr";
  const t = (key, fr) => (typeof grcT === "function" && typeof I18N_DICT === "object" && I18N_DICT[key] ? grcT(key) : fr);

  const strs = (a) => (Array.isArray(a) ? a.filter((v) => typeof v === "string") : []);

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function button(cls, text, title) {
    const b = el("button", "dash-btn dorks-btn " + (cls || ""), text);
    b.type = "button";
    if (title) b.title = title;
    return b;
  }

  function link(text, title) {
    const a = el("a", "dash-btn dorks-btn dorks-open", text);
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    if (title) a.title = title;
    return a;
  }

  function setLink(a, url) {
    a.classList.toggle("disabled", !url);
    if (url) a.href = url;
    else a.removeAttribute("href");
  }

  // Same reason as copy-commands.js's copyText(): navigator.clipboard
  // hangs under file:// -- execCommand("copy") works everywhere here.
  function copyText(text) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* no-op */ }
    document.body.removeChild(ta);
  }

  function copyButton(getText, title) {
    const label = "⧉ " + t("dorks.copyShort", "Copier");
    const b = button("", label, title || t("dorks.copy", "Copier la requête"));
    b.addEventListener("click", () => {
      const text = getText();
      if (!text) return;
      copyText(text);
      b.textContent = "✓ " + t("dorks.copied", "Copié");
      setTimeout(() => { b.textContent = label; }, 900);
    });
    return b;
  }

  function log(source, text) {
    if (window.systemLog) window.systemLog.push({ source, text });
  }

  // Shared checkbox list: presets + the user's own values (with ×), plus
  // an "autre…  +" adder. `get()` returns { values, extra }, `set()` saves.
  function checklist(opts) {
    const box = el("div", "dorks-values");
    const cur = opts.get();
    const options = opts.presets.concat(cur.extra.filter((v) => opts.presets.indexOf(v) === -1));
    options.forEach((v) => {
      const opt = el("label", "dorks-opt");
      const cb = el("input");
      cb.type = "checkbox";
      cb.checked = cur.values.indexOf(v) !== -1;
      opt.classList.toggle("off", !cb.checked);
      cb.addEventListener("change", () => {
        const now = opts.get();
        const picked = new Set(now.values.filter((x) => x !== v));
        if (cb.checked) picked.add(v);
        // Keep the options' order, whatever the click order.
        opts.set({ values: options.filter((o) => picked.has(o)), extra: now.extra }, false);
        opt.classList.toggle("off", !cb.checked);
      });
      opt.appendChild(cb);
      opt.appendChild(el("span", null, opts.display ? opts.display(v) : v));
      if (opts.presets.indexOf(v) === -1) {
        const x = el("button", "dorks-chip-x", "×");
        x.type = "button";
        x.title = t("dorks.removeValue", "Retirer cette valeur");
        x.addEventListener("click", (ev) => {
          ev.preventDefault();
          const now = opts.get();
          opts.set({ values: now.values.filter((e) => e !== v), extra: now.extra.filter((e) => e !== v) }, true);
        });
        opt.appendChild(x);
      }
      box.appendChild(opt);
    });

    const adder = el("span", "dorks-value-adder");
    const input = el("input", "dorks-value-input");
    input.type = "text";
    input.spellcheck = false;
    input.autocomplete = "off";
    input.placeholder = opts.placeholder || t("dorks.addValuePlaceholder", "autre valeur…");
    const plus = el("button", "dorks-value-add", "+");
    plus.type = "button";
    plus.title = t("dorks.addValue", "Ajouter cette valeur");
    const normalize = opts.normalize || ((v) => v.trim());
    function commit() {
      const added = input.value.split(",").map(normalize).filter(Boolean);
      if (!added.length) { input.classList.toggle("invalid", input.value.trim() !== ""); return; }
      const now = opts.get();
      const values = now.values.slice();
      const extra = now.extra.slice();
      added.forEach((v) => {
        if (options.indexOf(v) === -1 && extra.indexOf(v) === -1) extra.push(v);
        if (values.indexOf(v) === -1) values.push(v);
      });
      opts.set({ values, extra }, true, true);
    }
    plus.addEventListener("click", commit);
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === ",") { ev.preventDefault(); commit(); }
    });
    adder.appendChild(input);
    adder.appendChild(plus);
    box.appendChild(adder);
    return box;
  }

  // Re-focus the adder of the n-th checklist inside `scope` after a
  // re-render (so typing several values in a row stays smooth).
  function refocusAdder(scope, index) {
    const adders = scope.querySelectorAll(".dorks-value-input");
    if (adders[index]) adders[index].focus();
  }

  /* ---------------- Shared target ---------------- */

  function defaultTarget() {
    return { target: "", tld: { values: DEFAULT_TLDS.slice(), extra: [] }, wild: false };
  }

  function loadTarget() {
    try {
      let s = JSON.parse(localStorage.getItem(TARGET_KEY) || "null");
      if (!s) s = JSON.parse(localStorage.getItem(LEGACY_DORKS_KEY) || "null"); // one-time carry-over
      if (!s || typeof s !== "object") return defaultTarget();
      const tldIn = s.tld && typeof s.tld === "object" ? s.tld : {};
      const tld = { values: Array.isArray(tldIn.values) ? strs(tldIn.values) : DEFAULT_TLDS.slice(), extra: strs(tldIn.extra) };
      tld.values.forEach((v) => { if (PRESET_TLDS.indexOf(v) === -1 && tld.extra.indexOf(v) === -1) tld.extra.push(v); });
      return { target: typeof s.target === "string" ? s.target : "", tld, wild: s.wild === true };
    } catch (e) {
      return defaultTarget();
    }
  }

  const target = loadTarget();
  const listeners = [];

  function saveTarget() {
    try { localStorage.setItem(TARGET_KEY, JSON.stringify(target)); } catch (e) { /* stockage bloqué */ }
  }

  function targetChanged(origin) {
    saveTarget();
    listeners.forEach((fn) => fn(origin));
  }

  function onTargetChange(fn) { listeners.push(fn); }

  // "https://www.Example.com:443/path?x" -> "example.com"; "" if it
  // doesn't look like a domain name.
  function normalizeDomain(raw) {
    let d = String(raw || "").trim().toLowerCase();
    d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/[/?#].*$/, "").replace(/:\d+$/, "").replace(/^www\./, "").replace(/\.$/, "");
    return /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(d) ? d : "";
  }

  // ".CO.UK " -> "co.uk"; "" if not a plausible extension.
  function normalizeTld(raw) {
    const x = String(raw || "").trim().toLowerCase().replace(/^\.+/, "");
    return /^[a-z0-9-]{2,63}(\.[a-z0-9-]{2,63})?$/.test(x) ? x : "";
  }

  /* Reads the shared target:
       ""                 -> { mode: "empty" }
       abc.com (a domain) -> { mode: "domain", variants: ["abc.com"] }
       abc / abc* / abc.* -> { mode: "name", name: "abc", variants: one per
                             ticked extension, wild: ✱ ticked or * typed }
       anything else      -> { mode: "invalid" }
     `display` / `displayNoWild` stand in for <domain> in the chips. */
  function resolveTarget() {
    const none = (mode) => ({ mode, variants: [], wild: false, display: "", displayNoWild: "" });
    let raw = String(target.target || "").trim().toLowerCase();
    if (!raw) return none("empty");
    raw = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/[/?#].*$/, "").replace(/:\d+$/, "").replace(/^www\./, "");
    const typedWild = /\*$/.test(raw);
    const bare = raw.replace(/\.?\*+$/, "").replace(/\.$/, "");
    if (!typedWild) {
      const domain = normalizeDomain(bare);
      if (domain) return { mode: "domain", name: domain, variants: [domain], wild: false, display: domain, displayNoWild: domain };
    }
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(bare)) return none("invalid");
    const exts = target.tld.values.map(normalizeTld).filter(Boolean);
    const wild = typedWild || target.wild;
    const variants = exts.map((x) => bare + "." + x);
    const shown = exts.length === 0 ? "" : exts.length === 1 ? bare + "." + exts[0] : bare + ".{" + exts.join(",") + "}";
    return { mode: "name", name: bare, typedWild, variants, wild,
      display: [shown, wild ? bare + "✱" : ""].filter(Boolean).join(" + ") || bare,
      displayNoWild: shown || bare };
  }

  /* Target bar for one panel: input (+ `opts.extra` controls, e.g. the
     engine picker) and, for a bare name, the extensions row with the ✱
     box. `opts.wildNote(name)` says what ✱ becomes in THIS panel (or
     null when the panel ignores it). `opts.collapsed`: secondary panels
     show the extensions as a one-line summary that expands on click. */
  function renderTargetBar(container, opts) {
    opts = opts || {};
    const wrap = el("div", "osint-target");
    const bar = el("div", "dorks-bar");
    const input = el("input", "dorks-input");
    input.type = "text";
    input.spellcheck = false;
    input.autocomplete = "off";
    input.placeholder = t("dorks.targetPlaceholder", "Domaine (abc.com) ou nom (abc, abc*)");
    input.value = target.target;
    input.addEventListener("input", () => {
      target.target = input.value;
      targetChanged(input);
    });
    bar.appendChild(input);
    (opts.extra || []).forEach((n) => bar.appendChild(n));
    wrap.appendChild(bar);
    const tldRow = el("div", "dorks-tlds");
    wrap.appendChild(tldRow);
    container.appendChild(wrap);

    let expanded = !opts.collapsed;

    function render(origin) {
      const tg = resolveTarget();
      if (origin !== input && input.value !== target.target) input.value = target.target;
      input.classList.toggle("invalid", tg.mode === "invalid");
      tldRow.innerHTML = "";
      tldRow.hidden = tg.mode !== "name";
      if (tldRow.hidden) return;

      const note = opts.wildNote ? opts.wildNote(tg.name) : null;
      if (!expanded) {
        const exts = target.tld.values.map((x) => "." + x).join(" ") || "—";
        const sum = el("button", "dorks-tld-summary", t("dorks.tlds", "Extensions") + " : " + exts +
          (tg.wild ? "  ✱" + (note ? "" : " (" + t("dorks.wildIgnored", "ignoré ici") + ")") : "") + "  ✎");
        sum.type = "button";
        sum.addEventListener("click", () => { expanded = true; render(); });
        tldRow.appendChild(sum);
        return;
      }
      tldRow.appendChild(el("span", "dorks-tlds-label", t("dorks.tlds", "Extensions") + " :"));
      const list = checklist({
        presets: PRESET_TLDS,
        get: () => target.tld,
        set: (v, structural, refocus) => {
          target.tld = v;
          targetChanged(structural ? null : list);
          if (refocus) refocusAdder(tldRow, 0);
        },
        display: (x) => "." + x,
        normalize: normalizeTld,
        placeholder: t("dorks.addTldPlaceholder", "autre (co.uk)…"),
      });

      // ✱ -- forced on (and locked) when the name was typed with *.
      const wild = el("label", "dorks-opt dorks-wild");
      const wcb = el("input");
      wcb.type = "checkbox";
      wcb.checked = tg.wild;
      wcb.disabled = !!tg.typedWild;
      wild.classList.toggle("off", !tg.wild);
      wild.title = t("dorks.wildTitle", "Les moteurs n'ont pas de vrai joker de domaine : chaque panneau indique ce que ✱ devient.");
      wcb.addEventListener("change", () => {
        target.wild = wcb.checked;
        wild.classList.toggle("off", !wcb.checked);
        targetChanged(list);
      });
      wild.appendChild(wcb);
      wild.appendChild(el("span", null, "✱ " + t("dorks.wild", "joker") + " (" +
        (note || t("dorks.wildIgnored", "ignoré ici")) + ")"));
      list.appendChild(wild);
      tldRow.appendChild(list);
    }

    // Checkbox clicks inside this very row don't rebuild it (the box
    // already shows its new state); everything else does.
    onTargetChange((origin) => {
      if (origin && origin !== input && tldRow.contains(origin)) {
        input.classList.toggle("invalid", resolveTarget().mode === "invalid");
        return;
      }
      render(origin);
    });
    render();
    return wrap;
  }

  /* ---------------- Criteria builder ---------------- */

  /* opts:
       root, stateKey, logSource
       catalog   [{ id, title:{fr,en}, items:[{ id, label, op, values, mention? }] }]
       engines   { key: { name, url } }  (one engine = no picker)
       defaultClauses()        -> [clause]   (Reset)
       newClause               -> [catId, itemId] for "+ Ajouter un critère"
       implicitScope(state)    -> clause added in front when a target is set
                                  and no criterion uses <domain> (or null)
       dialect:
         wild(op, value, name) -> [{op, v}] what ✱ adds for one value
         group(op, [{op, v}])  -> string for one criterion ("" if empty)
       wildNote(name)          -> label for the ✱ box (null = ignored) */
  function createBuilder(opts) {
    const root = opts.root;
    const catalog = opts.catalog;
    const findCat = (id) => catalog.find((c) => c.id === id) || catalog[0];
    const findItem = (cat, id) => cat.items.find((i) => i.id === id) || cat.items[0];
    const engineKeys = Object.keys(opts.engines);

    function newClause(catId, itemId) {
      const cat = findCat(catId);
      const item = findItem(cat, itemId);
      return { cat: cat.id, item: item.id, values: item.values.slice(), extra: [] };
    }

    function defaultState() {
      return { engine: engineKeys[0], clauses: opts.defaultClauses().map((c) => newClause(c[0], c[1])) };
    }

    function loadState() {
      try {
        const s = JSON.parse(localStorage.getItem(opts.stateKey) || "null");
        if (!s || typeof s !== "object") return defaultState();
        const clauses = Array.isArray(s.clauses) ? s.clauses.filter((c) => c && typeof c === "object").map((c) => {
          const cat = findCat(c.cat);
          const item = findItem(cat, c.item);
          const values = strs(c.values);
          const extra = strs(c.extra);
          values.forEach((v) => { if (item.values.indexOf(v) === -1 && extra.indexOf(v) === -1) extra.push(v); });
          return { cat: cat.id, item: item.id, values, extra };
        }) : defaultState().clauses;
        return { engine: opts.engines[s.engine] ? s.engine : engineKeys[0], clauses };
      } catch (e) {
        return defaultState();
      }
    }

    const state = loadState();
    const save = () => {
      try { localStorage.setItem(opts.stateKey, JSON.stringify(state)); } catch (e) { /* stockage bloqué */ }
    };

    const hasTarget = (tg) => tg.variants.length > 0 || (tg.wild && opts.wildNote(tg.name) !== null);
    const opOf = (clause) => findItem(findCat(clause.cat), clause.item).op;
    const usesDomain = () => state.clauses.some((c) => c.values.some((v) => v.indexOf(PLACEHOLDER) !== -1));

    // One value holding <domain> becomes one value per extension variant,
    // plus whatever the dialect makes of the ✱ wildcard.
    function expand(clause, tg) {
      const op = opOf(clause);
      const items = [];
      const seen = new Set();
      const push = (it) => { const k = it.op + "\u0000" + it.v; if (!seen.has(k)) { seen.add(k); items.push(it); } };
      clause.values.map((v) => v.trim()).filter(Boolean).forEach((v) => {
        if (v.indexOf(PLACEHOLDER) === -1 || !hasTarget(tg)) { push({ op, v }); return; }
        tg.variants.forEach((d) => push({ op, v: v.split(PLACEHOLDER).join(d) }));
        if (tg.wild) opts.dialect.wild(op, v, tg.name).forEach(push);
      });
      return opts.dialect.group(op, items);
    }

    function effectiveClauses(tg) {
      if (!hasTarget(tg) || usesDomain()) return state.clauses;
      const scope = opts.implicitScope(state, (c) => findItem(findCat(c.cat), c.item));
      return scope ? [newClause(scope[0], scope[1])].concat(state.clauses) : state.clauses;
    }

    const buildQuery = (tg) => effectiveClauses(tg).map((c) => expand(c, tg)).filter(Boolean).join(" ");

    // --- Target bar (+ engine picker when there is more than one) ---
    const extra = [];
    let engineSelect = null;
    if (engineKeys.length > 1) {
      engineSelect = el("select", "dorks-select");
      engineKeys.forEach((k) => {
        const o = el("option", null, opts.engines[k].name);
        o.value = k;
        engineSelect.appendChild(o);
      });
      engineSelect.value = state.engine;
      engineSelect.addEventListener("change", () => {
        state.engine = engineSelect.value;
        save();
        refreshPreview();
      });
      extra.push(engineSelect);
    }
    renderTargetBar(root, { extra, wildNote: opts.wildNote, collapsed: opts.collapsedTarget });

    const list = el("div", "dorks-clauses");
    root.appendChild(list);

    const addBtn = button("dorks-add", "+ " + t("dorks.addClause", "Ajouter un critère"));
    addBtn.addEventListener("click", () => {
      state.clauses.push(newClause(opts.newClause[0], opts.newClause[1]));
      save();
      renderClauses();
    });
    const resetBtn = button("dorks-reset", t("dorks.reset", "Réinitialiser"));
    resetBtn.addEventListener("click", () => {
      state.clauses = defaultState().clauses;
      save();
      renderClauses();
    });
    const addRow = el("div", "dorks-add-row");
    addRow.appendChild(addBtn);
    addRow.appendChild(resetBtn);
    root.appendChild(addRow);

    const preview = el("div", "dorks-preview");
    const previewCode = el("code", "dorks-preview-query");
    const actions = el("div", "dorks-row-actions");
    const copyBtn = copyButton(() => buildQuery(resolveTarget()));
    const openLink = link("");
    actions.appendChild(copyBtn);
    actions.appendChild(openLink);
    preview.appendChild(previewCode);
    preview.appendChild(actions);
    root.appendChild(preview);
    const hint = el("div", "dorks-hint");
    root.appendChild(hint);

    openLink.addEventListener("click", (ev) => {
      if (openLink.classList.contains("disabled")) { ev.preventDefault(); return; }
      log(opts.logSource, opts.engines[state.engine].name + " · " + buildQuery(resolveTarget()));
    });

    function refreshPreview() {
      const tg = resolveTarget();
      const q = buildQuery(tg);
      const eff = effectiveClauses(tg);
      const implicit = eff !== state.clauses;
      hint.hidden = !implicit;
      hint.textContent = implicit
        ? t("dorks.implicitScope", "Cible ajoutée automatiquement (aucun critère n'utilise <domain>).") +
          " → " + expand(eff[0], tg)
        : "";
      previewCode.textContent = q || t("dorks.emptyQuery", "Ajoute un critère pour construire la requête");
      previewCode.classList.toggle("empty", !q);
      const missingDomain = usesDomain() && !hasTarget(tg);
      const ready = !!q && !missingDomain;
      openLink.textContent = "↗ " + opts.engines[state.engine].name;
      setLink(openLink, ready ? opts.engines[state.engine].url + encodeURIComponent(q) : "");
      openLink.title = missingDomain
        ? (tg.mode === "name" ? t("dorks.needTld", "Cocher au moins une extension ou le joker ✱") : t("dorks.needTarget", "Saisir d'abord un domaine cible"))
        : "";
      copyBtn.disabled = !q;
    }

    function renderClause(clause, index) {
      const row = el("div", "dorks-clause");
      const cat = findCat(clause.cat);
      const item = findItem(cat, clause.item);

      const catSelect = el("select", "dorks-select");
      catalog.forEach((c) => {
        const o = el("option", null, c.title[L]);
        o.value = c.id;
        catSelect.appendChild(o);
      });
      catSelect.value = cat.id;
      catSelect.addEventListener("change", () => {
        state.clauses[index] = newClause(catSelect.value);
        save();
        renderClauses();
      });

      const itemSelect = el("select", "dorks-select");
      cat.items.forEach((i) => {
        const o = el("option", null, i.label[L]);
        o.value = i.id;
        itemSelect.appendChild(o);
      });
      itemSelect.value = clause.item;
      itemSelect.addEventListener("change", () => {
        state.clauses[index] = newClause(cat.id, itemSelect.value);
        save();
        renderClauses();
      });

      const tg = resolveTarget();
      const wildShown = tg.wild && opts.dialect.wild(item.op, PLACEHOLDER, tg.name || "x").length > 0;
      const shown = wildShown ? tg.display : tg.displayNoWild;
      const values = checklist({
        presets: item.values,
        get: () => clause,
        set: (v, structural, refocus) => {
          clause.values = v.values;
          clause.extra = v.extra;
          save();
          if (structural) {
            renderClauses();
            if (refocus) refocusAdder(list, index);
          } else {
            refreshPreview();
          }
        },
        display: (v) => (shown ? v.split(PLACEHOLDER).join(shown) : v),
      });

      const remove = button("dorks-remove", "✕", t("dorks.removeClause", "Retirer ce critère"));
      remove.addEventListener("click", () => {
        state.clauses.splice(index, 1);
        save();
        renderClauses();
      });

      row.appendChild(catSelect);
      row.appendChild(itemSelect);
      row.appendChild(values);
      row.appendChild(remove);
      return row;
    }

    function renderClauses() {
      list.innerHTML = "";
      state.clauses.forEach((c, i) => list.appendChild(renderClause(c, i)));
      refreshPreview();
    }

    // The target changed (here or in another panel): chips show the
    // target, so rebuild them -- unless a checkbox of the extensions row
    // was clicked mid-typing elsewhere, then the preview is enough.
    onTargetChange(() => renderClauses());
    renderClauses();
  }

  // Shared formatting helpers.
  const needsQuotes = (v) => /[\s"():|,]/.test(v);
  const quoteIfNeeded = (v) => (needsQuotes(v) ? '"' + v.replace(/"/g, "") + '"' : v);

  window.OsintKit = {
    PLACEHOLDER, L, t, el, button, link, setLink, copyButton, log, checklist, refocusAdder,
    resolveTarget, onTargetChange, renderTargetBar, createBuilder, quoteIfNeeded,
  };
  return window.OsintKit;
};
