/* crt.sh panel (OSINT dashboard) -- certificate-transparency search,
   the best passive source of subdomains. Not a query language, so no
   criteria builder: the shared target (osint-common.js) + a few options
   give one crt.sh search per domain variant (abc.com, abc.ca, …), each
   with "open" and "copy a curl | jq command" (to run it from a shell).

   crt.sh syntax: % is its wildcard. "%.abc.com" = every subdomain; the
   ✱ box becomes "abc.%" (any extension) -- the only panel where ✱ is a
   real wildcard, but such searches are slow and may time out. */

window.NeonFlareOsint = window.NeonFlareOsint || {};
window.NeonFlareOsint.crtsh = function (root) {
  if (!root || !window.OsintKit) return;
  const K = window.OsintKit;
  const t = K.t;

  const STATE_KEY = "/dashboard.html/crtsh";
  const state = (function () {
    const d = { subdomains: true, excludeExpired: false, dedupe: true, format: "html" };
    try {
      const s = JSON.parse(localStorage.getItem(STATE_KEY) || "null") || {};
      Object.keys(d).forEach((k) => { if (typeof s[k] === typeof d[k]) d[k] = s[k]; });
    } catch (e) { /* défauts */ }
    return d;
  })();
  const save = () => { try { localStorage.setItem(STATE_KEY, JSON.stringify(state)); } catch (e) { /* bloqué */ } };

  K.renderTargetBar(root, { collapsed: true, wildNote: (name) => name + ".% — " + t("crtsh.slow", "lent") });

  // --- Options ---
  const opts = K.el("div", "osint-options");
  function toggle(key, label, title) {
    const lab = K.el("label", "dorks-opt");
    const cb = K.el("input");
    cb.type = "checkbox";
    cb.checked = state[key];
    lab.classList.toggle("off", !cb.checked);
    if (title) lab.title = title;
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
  toggle("subdomains", t("crtsh.subdomains", "Sous-domaines (%.)"));
  toggle("excludeExpired", t("crtsh.excludeExpired", "Exclure les expirés"));
  toggle("dedupe", t("crtsh.dedupe", "Dédupliquer (pré-certificats)"));
  const format = K.el("select", "dorks-select");
  [["html", "HTML"], ["json", "JSON"]].forEach(([v, n]) => {
    const o = K.el("option", null, n);
    o.value = v;
    format.appendChild(o);
  });
  format.value = state.format;
  format.addEventListener("change", () => { state.format = format.value; save(); render(); });
  opts.appendChild(format);
  root.appendChild(opts);

  const rows = K.el("div", "osint-rows");
  root.appendChild(rows);
  const hint = K.el("div", "dorks-hint");
  root.appendChild(hint);

  function queries() {
    const tg = K.resolveTarget();
    const sub = state.subdomains ? "%." : "";
    const list = tg.variants.map((d) => sub + d);
    if (tg.wild) list.push(sub + tg.name + ".%");
    return list;
  }

  function url(q, output) {
    let u = "https://crt.sh/?q=" + encodeURIComponent(q);
    if (state.excludeExpired) u += "&exclude=expired";
    if (state.dedupe) u += "&deduplicate=Y";
    if (output) u += "&output=" + output;
    return u;
  }

  // Shell one-liner: unique names, wildcard "*." prefixes stripped.
  function curlCmd(q) {
    return "curl -s '" + url(q, "json") + "' | jq -r '.[].name_value' | sed 's/^\\*\\.//' | sort -u";
  }

  function render() {
    rows.innerHTML = "";
    const qs = queries();
    hint.hidden = qs.length > 0;
    hint.textContent = qs.length ? "" : t("osint.needTarget", "Saisis une cible (domaine ou nom + extensions) pour générer les recherches.");
    qs.forEach((q) => {
      const row = K.el("div", "osint-row");
      row.appendChild(K.el("code", "osint-row-query", q));
      const actions = K.el("div", "dorks-row-actions");
      actions.appendChild(K.copyButton(() => curlCmd(q), t("crtsh.copyCurl", "Copier la commande curl | jq (liste des sous-domaines)")));
      const a = K.link("↗ crt.sh");
      K.setLink(a, url(q, state.format === "json" ? "json" : ""));
      a.addEventListener("click", () => K.log("crtsh", "crt.sh · " + q));
      actions.appendChild(a);
      row.appendChild(actions);
      rows.appendChild(row);
    });
  }

  K.onTargetChange(render);
  render();
};
