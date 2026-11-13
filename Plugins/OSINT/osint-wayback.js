/* Wayback Machine panel (OSINT dashboard) -- every URL the Internet
   Archive ever captured for the target: old pages, removed endpoints,
   forgotten files. Like crt.sh it isn't a query language, so: the shared
   target (osint-common.js) + options -> per domain variant
     • "↗ URL" = CDX API list of unique URLs (plain text, one per line)
     • "↗ Wayback" = the archive's own browsing UI
     • "⧉" = the same list as a curl command, for a shell.

   CDX parameters used: matchType=domain (with subdomains) or url=d/*
   (that host only), fl=original, collapse=urlkey (one line per URL),
   filter=statuscode:200, filter=original:.*\.(pdf|sql|…)$ (file types),
   from/to (years), limit. The archive has no domain wildcard: ✱ is
   ignored here. */

window.NeonFlareOsint = window.NeonFlareOsint || {};
window.NeonFlareOsint.wayback = function (root) {
  if (!root || !window.OsintKit) return;
  const K = window.OsintKit;
  const t = K.t;

  const PRESET_EXTS = ["pdf", "doc", "docx", "xls", "xlsx", "sql", "bak", "zip", "env", "conf", "log", "json", "xml", "txt", "js"];
  const STATE_KEY = "/dashboard.html/wayback";
  const state = (function () {
    const d = { subdomains: true, ok200: true, collapse: true, from: "", to: "", limit: "10000", exts: { values: [], extra: [] } };
    try {
      const s = JSON.parse(localStorage.getItem(STATE_KEY) || "null") || {};
      ["subdomains", "ok200", "collapse"].forEach((k) => { if (typeof s[k] === "boolean") d[k] = s[k]; });
      ["from", "to", "limit"].forEach((k) => { if (typeof s[k] === "string") d[k] = s[k]; });
      if (s.exts && Array.isArray(s.exts.values) && Array.isArray(s.exts.extra)) {
        d.exts = { values: s.exts.values.filter((v) => typeof v === "string"), extra: s.exts.extra.filter((v) => typeof v === "string") };
      }
    } catch (e) { /* défauts */ }
    return d;
  })();
  const save = () => { try { localStorage.setItem(STATE_KEY, JSON.stringify(state)); } catch (e) { /* bloqué */ } };

  K.renderTargetBar(root, { collapsed: true, wildNote: () => null });

  // --- Options ---
  const opts = K.el("div", "osint-options");
  function toggle(key, label) {
    const lab = K.el("label", "dorks-opt");
    const cb = K.el("input");
    cb.type = "checkbox";
    cb.checked = state[key];
    lab.classList.toggle("off", !cb.checked);
    cb.addEventListener("change", () => {
      state[key] = cb.checked;
      lab.classList.toggle("off", !cb.checked);
      save();
      render();
    });
    lab.appendChild(cb);
    lab.appendChild(K.el("span", null, label));
    opts.appendChild(lab);
  }
  toggle("subdomains", t("wayback.subdomains", "Sous-domaines inclus"));
  toggle("ok200", t("wayback.ok200", "Réponses 200 seulement"));
  toggle("collapse", t("wayback.collapse", "Une ligne par URL"));

  function numberInput(key, placeholder, width, pattern) {
    const i = K.el("input", "dorks-input osint-small-input");
    i.type = "text";
    i.inputMode = "numeric";
    i.placeholder = placeholder;
    i.value = state[key];
    i.style.width = width;
    i.addEventListener("input", () => {
      state[key] = i.value.trim();
      i.classList.toggle("invalid", state[key] !== "" && !pattern.test(state[key]));
      save();
      renderLinks();
    });
    i.classList.toggle("invalid", state[key] !== "" && !pattern.test(state[key]));
    return i;
  }
  const YEAR = /^(19|20)\d{2}$/;
  opts.appendChild(K.el("span", "dorks-tlds-label", t("wayback.years", "Années") + " :"));
  opts.appendChild(numberInput("from", t("wayback.from", "de"), "4.5rem", YEAR));
  opts.appendChild(numberInput("to", t("wayback.to", "à"), "4.5rem", YEAR));
  opts.appendChild(K.el("span", "dorks-tlds-label", t("wayback.limit", "Limite") + " :"));
  opts.appendChild(numberInput("limit", "10000", "5.5rem", /^\d{1,7}$/));
  root.appendChild(opts);

  // File types (none ticked = every URL).
  const extRow = K.el("div", "dorks-tlds");
  root.appendChild(extRow);
  function renderExts() {
    extRow.innerHTML = "";
    extRow.appendChild(K.el("span", "dorks-tlds-label", t("wayback.exts", "Types de fichiers (aucun = tout)") + " :"));
    extRow.appendChild(K.checklist({
      presets: PRESET_EXTS,
      get: () => state.exts,
      set: (v, structural, refocus) => {
        state.exts = v;
        save();
        if (structural) { renderExts(); if (refocus) K.refocusAdder(extRow, 0); }
        renderLinks();
      },
      display: (x) => "." + x,
      normalize: (v) => (/^[a-z0-9]{1,10}$/i.test(v.trim().replace(/^\./, "")) ? v.trim().replace(/^\./, "").toLowerCase() : ""),
      placeholder: t("wayback.addExt", "autre…"),
    }));
  }

  const rows = K.el("div", "osint-rows");
  root.appendChild(rows);
  const hint = K.el("div", "dorks-hint");
  root.appendChild(hint);

  function cdxUrl(d) {
    const p = [];
    if (state.subdomains) p.push("url=" + encodeURIComponent(d), "matchType=domain");
    else p.push("url=" + encodeURIComponent(d + "/*"));
    p.push("fl=original");
    if (state.collapse) p.push("collapse=urlkey");
    if (state.ok200) p.push("filter=statuscode:200");
    const exts = state.exts.values;
    if (exts.length) p.push("filter=" + encodeURIComponent("original:.*\\.(" + exts.join("|") + ")$"));
    if (YEAR.test(state.from)) p.push("from=" + state.from);
    if (YEAR.test(state.to)) p.push("to=" + state.to);
    if (/^\d{1,7}$/.test(state.limit)) p.push("limit=" + state.limit);
    return "https://web.archive.org/cdx/search/cdx?" + p.join("&");
  }

  // The browsing UI only takes a host prefix (no "*.host"): subdomains
  // are covered by the CDX list, not by this link.
  const uiUrl = (d) => "https://web.archive.org/web/*/" + d + "/*";

  function renderLinks() {
    rows.innerHTML = "";
    const variants = K.resolveTarget().variants;
    hint.hidden = variants.length > 0;
    hint.textContent = variants.length ? "" : t("osint.needTarget", "Saisis une cible (domaine ou nom + extensions) pour générer les recherches.");
    variants.forEach((d) => {
      const row = K.el("div", "osint-row");
      row.appendChild(K.el("code", "osint-row-query", (state.subdomains ? "*." : "") + d));
      const actions = K.el("div", "dorks-row-actions");
      actions.appendChild(K.copyButton(() => "curl -s '" + cdxUrl(d) + "'", t("wayback.copyCurl", "Copier la commande curl (liste d'URL)")));
      const list = K.link("↗ " + t("wayback.urls", "URL"), t("wayback.urlsTitle", "Liste brute des URL archivées (API CDX)"));
      K.setLink(list, cdxUrl(d));
      list.addEventListener("click", () => K.log("wayback", "CDX · " + d));
      const ui = K.link("↗ Wayback");
      K.setLink(ui, uiUrl(d));
      ui.addEventListener("click", () => K.log("wayback", "Wayback · " + d));
      actions.appendChild(list);
      actions.appendChild(ui);
      row.appendChild(actions);
      rows.appendChild(row);
    });
  }

  function render() { renderLinks(); }

  K.onTargetChange(renderLinks);
  renderExts();
  render();
};
