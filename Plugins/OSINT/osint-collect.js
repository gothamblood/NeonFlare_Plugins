/* OSINT -- collecte + inventaire « Actifs découverts » (2026-11-10,
   spec/osint-collecte/PLAN.md).

   Les autres panneaux OSINT GÉNÈRENT des requêtes ; celui-ci va CHERCHER
   les résultats et les range dans un inventaire unique, dédoublonné.

   Sources (PLAN.md §3), deux transports :
     fetch() direct -- API qui répondent avec CORS « * », y compris à
       l'origine « null » de file:// (mesuré le 2026-11-10) :
         crt.sh        sous-domaines (certificats)
         DNS           A, AAAA, MX, NS, TXT, CAA, _dmarc (DoH dns.google)
         RDAP          registraire, dates, statut, serveurs de noms (rdap.org
                       -> registre du TLD, CORS aussi après redirection)
         ASN           IP -> préfixe + ASN (RIPEstat)
         InternetDB    IP -> ports, CVE connues (Shodan, sans clé)
       + un LIEN ↗ Shodan (shodan.io/domain/<cible>) : comme Google Dorks,
         c'est l'utilisateur qui consulte Shodan avec son propre compte.
         Pas d'appel à l'API Shodan, donc aucune clé à stocker (choix du
         2026-11-10 : moins de risque juridique et de données conservées).
       + un LIEN ↗ Have I Been Pwned (haveibeenpwned.com/DomainSearch) : la
         recherche par domaine exige la connexion de l'utilisateur et la
         vérification du domaine chez HIBP ; aucune URL ne prend le domaine en
         paramètre, donc un seul lien. NeonFlare ne collecte aucun courriel.
     shell -- pas de CORS, ou outil local : la commande est tapée dans un
       shell Bash/Zsh ouvert et relue par ttyd-capture.js (captureLarge) :
         Wayback       URL archivées (API CDX)
         urlscan       scans publics existants
         subfinder / amass   s'ils sont installés

   Règles (PLAN.md §1) :
     1. Domaines : uniquement les variantes VALIDÉES de la cible partagée
        (OsintKit.resolveTarget) ; IP/hôtes revenus revalidés par regex
        avant toute réutilisation ; dans une commande shell, toujours shq().
     2. Tout ce qui revient est rendu en textContent, jamais en HTML ; un
        lien n'est créé que vers l'archive (web.archive.org), jamais vers la
        cible (ouvrir la cible = reconnaissance active).
     3. Rien ne part sans clic sur « ▶ », et seulement après la case
        « autorisé » cochée pour cette cible (V3).
     4. Pas de renseignement personnel : seuls noms d'hôte, IP, URL,
        enregistrements DNS, registraire (jamais le titulaire RDAP),
        ASN, ports, CVE sont gardés ; les courriels sont ignorés.
     5. Aucune clé d'API n'est demandée ni stockée.

   Stockage : /dashboard.html/osintInventory (protégé par le coffre,
   voir vault.js) = { items: [...], targets: { <cible>: dossier } }
     item    = { id, target, type, value, sources[], firstSeen, lastSeen,
                 status: "new"|"kept"|"dismissed", grcAssetId }
     dossier = { ok, scope, at, end: "AAAA-MM-JJ", notes: [{ at, text }] }
   Une date de fin dépassée fait PROPOSER la purge de la cible (V4). */

window.NeonFlareOsint = window.NeonFlareOsint || {};
window.NeonFlareOsint.collect = function (root, api) {
  "use strict";

  if (!root || !window.OsintKit || !api.shell || !api.vault) return;
  const K = window.OsintKit;
  const TC = api.shell;            // permission « shell »
  const GRC = api.grc || {};        // permission « grc »
  const S = (fr, en) => (K.L === "en" ? en : fr);

  const INV_KEY = "/dashboard.html/osintInventory";
  const UI_KEY = "/dashboard.html/osintCollectUi"; // confort local (filtres, limite), hors coffre
  const ROW_CAP = 300;
  const MAX_IPS = 30;       // IP interrogées par ASN / InternetDB, par collecte
  const MAX_RESOLVE = 50;   // sous-domaines résolus (A) par la collecte DNS
  const MAX_NOTES = 200;
  const HOST_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/;
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const IPV6_RE = /^[0-9a-f:]{2,39}$/;
  const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

  const TYPES = {
    subdomain: S("Sous-domaine", "Subdomain"),
    url: "URL",
    ip: "IP",
    dns: "DNS",
    whois: "RDAP",
    asn: "ASN",
    port: "Port",
    cve: "CVE",
    web: S("Fichier web", "Web file"),
  };
  const STATUSES = {
    new: S("Nouveau", "New"),
    kept: S("Retenu", "Kept"),
    dismissed: S("Écarté", "Dismissed"),
  };
  // Type d'actif GRC proposé par « → GRC » (GRC_ASSET_TYPES, grc-assets.js).
  const GRC_TYPE = { url: "logiciel", cve: "logiciel" };

  /* ---------------- Utilitaires ---------------- */

  const el = K.el;
  const errText = (e) => (e && e.message ? e.message : String(e));
  function now() { return new Date().toISOString(); }
  function newId() { return "osi-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }

  function normHost(h) {
    const x = String(h || "").trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    return HOST_RE.test(x) ? x : "";
  }
  function inScope(host, domain) {
    return host === domain || host.slice(-(domain.length + 1)) === "." + domain;
  }
  function normIp(v) {
    const x = String(v || "").trim().toLowerCase();
    if (IPV4_RE.test(x)) return x;
    if (IPV6_RE.test(x) && x.indexOf(":") !== -1) return x;
    return "";
  }
  function clip(s, n) {
    s = String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").trim();
    return s.length > n ? s.slice(0, n) + "…" : s;
  }

  async function getJson(url, opts) {
    const res = await fetch(url, Object.assign({ credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store" }, opts || {}));
    if (res.status === 404 && opts && opts.notFoundOk) return null;
    if (!res.ok) {
      const e = new Error("HTTP " + res.status + (res.status === 429 ? S(" (trop de requêtes, réessayez plus tard)", " (rate-limited, try again later)") : ""));
      e.status = res.status;
      throw e;
    }
    return res.json();
  }

  /* ---------------- Stockage ---------------- */

  function cleanTarget(v) {
    v = v && typeof v === "object" ? v : {};
    return {
      ok: v.ok === true,
      scope: typeof v.scope === "string" ? v.scope.slice(0, 300) : "",
      at: typeof v.at === "string" ? v.at : "",
      end: typeof v.end === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v.end) ? v.end : "",
      notes: Array.isArray(v.notes) ? v.notes.filter((n) => n && typeof n.text === "string")
        .map((n) => ({ at: String(n.at || ""), text: n.text.slice(0, 2000) })).slice(-MAX_NOTES) : [],
    };
  }

  function loadInv() {
    let s = null;
    try { s = JSON.parse(api.vault.getItem(INV_KEY) || "null"); } catch (e) { s = null; }
    const inv = { items: [], targets: {} };
    if (!s || typeof s !== "object") return inv;
    if (Array.isArray(s.items)) {
      inv.items = s.items.filter((it) => it && typeof it.value === "string" && TYPES[it.type] && typeof it.target === "string")
        .map((it) => ({
          id: String(it.id || newId()),
          target: it.target,
          type: it.type,
          value: it.value,
          sources: Array.isArray(it.sources) ? it.sources.filter((x) => typeof x === "string" && SOURCES[x]) : [],
          firstSeen: String(it.firstSeen || ""),
          lastSeen: String(it.lastSeen || ""),
          status: STATUSES[it.status] ? it.status : "new",
          grcAssetId: typeof it.grcAssetId === "string" ? it.grcAssetId : "",
        }));
    }
    if (s.targets && typeof s.targets === "object") {
      Object.keys(s.targets).forEach((k) => { inv.targets[k] = cleanTarget(s.targets[k]); });
    }
    return inv;
  }

  let inv = null;

  function saveInv() {
    try {
      api.vault.setItem(INV_KEY, JSON.stringify(inv));
    } catch (e) {
      setStatus("store", S("Enregistrement impossible : ", "Could not save: ") + errText(e), "fail");
    }
  }

  const ui = (function () {
    const d = { type: "", source: "", status: "", q: "", limit: "5000" };
    try {
      const s = JSON.parse(localStorage.getItem(UI_KEY) || "null") || {};
      Object.keys(d).forEach((k) => { if (typeof s[k] === "string") d[k] = s[k]; });
    } catch (e) { /* défauts */ }
    return d;
  })();
  function saveUi() {
    try { localStorage.setItem(UI_KEY, JSON.stringify(ui)); } catch (e) { /* stockage bloqué */ }
  }

  /* ---------------- Inventaire ---------------- */

  const index = new Map();
  function keyOf(target, type, value) { return target + "\u0000" + type + "\u0000" + value; }
  function reindex() {
    index.clear();
    inv.items.forEach((it) => index.set(keyOf(it.target, it.type, it.value), it));
  }

  // Ajoute ou fusionne (cible + type + valeur). Renvoie true si nouveau.
  function merge(target, type, value, source, at) {
    const k = keyOf(target, type, value);
    const cur = index.get(k);
    if (cur) {
      if (cur.sources.indexOf(source) === -1) cur.sources.push(source);
      cur.lastSeen = at;
      return false;
    }
    const it = { id: newId(), target, type, value, sources: [source], firstSeen: at, lastSeen: at, status: "new", grcAssetId: "" };
    inv.items.push(it);
    index.set(k, it);
    return true;
  }

  function targetItems(t, type) {
    return inv.items.filter((it) => it.target === t.key && (!type || it.type === type) && it.status !== "dismissed");
  }

  function targetIps(t) {
    const ips = [];
    targetItems(t, "ip").forEach((it) => { if (normIp(it.value) && ips.indexOf(it.value) === -1) ips.push(it.value); });
    return ips.slice(0, MAX_IPS);
  }

  /* ---------------- Sources ---------------- */

  // Commande curl pour le shell : code HTTP sur une dernière ligne balisée
  // (000 = aucune réponse). Barre oblique inverse + n LITTÉRALE : curl
  // l'interprète lui-même (un vrai saut de ligne couperait la commande).
  function curlCmd(url, maxTime) {
    return "curl -sS --max-time " + (maxTime || 110) + " -w " + TC.shq("\\nNFHTTP:%{http_code}\\n") + " " + TC.shq(url);
  }

  function httpBody(text) {
    const hm = /NFHTTP:(\d{3})\s*$/.exec(text);
    const code = hm ? hm[1] : "";
    if (code !== "200") {
      throw new Error(code === "000" || !code
        ? S("aucune réponse (réseau, ou délai dépassé : essayez une limite plus basse)", "no answer (network, or time limit hit: try a lower limit)")
        : "HTTP " + code + (code === "503" || code === "429" ? S(" -- service indisponible ou saturé, réessayez plus tard", " -- service unavailable or rate-limiting, try again later") : ""));
    }
    return text.slice(0, hm.index);
  }

  // Outil local : NFMISSING si absent (pas d'erreur bash dans le terminal).
  function toolCmd(bin, args) {
    return "command -v " + bin + " >/dev/null 2>&1 || { echo NFMISSING; exit 0; }; " + args;
  }

  function hostsFromText(text, domain) {
    const out = new Set();
    String(text || "").split(/[\s,;"'()<>[\]]+/).forEach((tok) => {
      const h = normHost(tok);
      if (h && inScope(h, domain)) out.add(h);
    });
    return Array.from(out).map((h) => ({ type: "subdomain", value: h }));
  }

  function urlItems(lines, domain) {
    const out = [];
    const hosts = new Set();
    lines.forEach((line) => {
      const v = String(line || "").trim();
      if (!v || v.length > 2048) return;
      let u;
      try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : "http://" + v); } catch (e) { return; }
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      const h = normHost(u.hostname);
      if (!h || !inScope(h, domain)) return;
      out.push({ type: "url", value: u.href });
      hosts.add(h);
    });
    hosts.forEach((h) => out.push({ type: "subdomain", value: h }));
    return out;
  }

  const DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA"];
  async function doh(name, type) {
    const d = await getJson("https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + type);
    return Array.isArray(d && d.Answer) ? d.Answer.filter((a) => a && typeof a.data === "string") : [];
  }

  /* Chaque source : { label, group, transport, scope, run(ctx) -> items[] }
     scope "domain" = une passe par variante de domaine ; "target" = une
     passe pour la cible (sources qui partent des IP déjà trouvées).
     ctx = { t, domain, port } ; un run peut poser ctx.note (résumé). */
  const SOURCES = {
    crtsh: {
      label: "crt.sh", group: "sub", transport: "fetch", scope: "domain",
      title: S("Sous-domaines depuis les certificats (requête directe à crt.sh)", "Subdomains from certificates (direct request to crt.sh)"),
      async run(ctx) {
        const data = await getJson("https://crt.sh/?q=" + encodeURIComponent("%." + ctx.domain) + "&output=json");
        if (!Array.isArray(data)) throw new Error(S("réponse inattendue", "unexpected response"));
        const hosts = new Set();
        data.forEach((row) => {
          String((row && row.name_value) || "").split("\n").forEach((n) => {
            const h = normHost(n);
            if (h && inScope(h, ctx.domain)) hosts.add(h);
          });
        });
        return Array.from(hosts).map((h) => ({ type: "subdomain", value: h }));
      },
    },
    wayback: {
      label: "Wayback", group: "sub", transport: "shell", scope: "domain",
      title: S("URL archivées (curl lancé dans le shell choisi)", "Archived URLs (curl run in the chosen shell)"),
      command(domain) {
        return curlCmd("https://web.archive.org/cdx/search/cdx?url=" + encodeURIComponent(domain) +
          "&matchType=domain&fl=original&collapse=urlkey&filter=statuscode:200&limit=" + ui.limit);
      },
      async run(ctx) {
        const text = httpBody(await shellRun(ctx, this.command(ctx.domain), "wayback"));
        return urlItems(text.split("\n"), ctx.domain);
      },
    },
    subfinder: {
      label: "subfinder", group: "sub", transport: "shell", scope: "domain",
      title: S("Sous-domaines passifs via subfinder, s'il est installé (shell choisi)", "Passive subdomains via subfinder, if installed (chosen shell)"),
      command(domain) { return toolCmd("subfinder", "timeout 110 subfinder -silent -d " + TC.shq(domain)); },
      async run(ctx) {
        const text = await shellRun(ctx, this.command(ctx.domain), "subfinder");
        if (/^NFMISSING\s*$/m.test(text)) throw new Error(S("subfinder n'est pas installé dans ce shell", "subfinder is not installed in this shell"));
        return hostsFromText(text, ctx.domain);
      },
    },
    amass: {
      label: "amass", group: "sub", transport: "shell", scope: "domain",
      title: S("Sous-domaines passifs via amass (enum -passive), s'il est installé (shell choisi)", "Passive subdomains via amass (enum -passive), if installed (chosen shell)"),
      command(domain) { return toolCmd("amass", "timeout 110 amass enum -passive -nocolor -d " + TC.shq(domain)); },
      async run(ctx) {
        const text = await shellRun(ctx, this.command(ctx.domain), "amass");
        if (/^NFMISSING\s*$/m.test(text)) throw new Error(S("amass n'est pas installé dans ce shell", "amass is not installed in this shell"));
        return hostsFromText(text, ctx.domain);
      },
    },
    dns: {
      label: "DNS", group: "infra", transport: "fetch", scope: "domain",
      title: S("Enregistrements DNS (A, AAAA, MX, NS, TXT, CAA, DMARC) + résolution des sous-domaines connus (DoH Google)", "DNS records (A, AAAA, MX, NS, TXT, CAA, DMARC) + resolution of known subdomains (Google DoH)"),
      async run(ctx) {
        const out = [];
        let spf = false;
        let dmarc = false;
        for (const type of DNS_TYPES) {
          (await doh(ctx.domain, type)).forEach((a) => {
            const data = clip(a.data, 500);
            out.push({ type: "dns", value: type + " " + data });
            if (type === "A" || type === "AAAA") { const ip = normIp(a.data); if (ip) out.push({ type: "ip", value: ip }); }
            if (type === "TXT" && /^"?v=spf1/i.test(a.data)) spf = true;
          });
        }
        (await doh("_dmarc." + ctx.domain, "TXT")).forEach((a) => {
          if (/v=DMARC1/i.test(a.data)) { dmarc = true; out.push({ type: "dns", value: "DMARC " + clip(a.data, 500) }); }
        });
        // Sous-domaines déjà inventoriés -> leurs IP (pour ASN / InternetDB).
        const subs = targetItems(ctx.t, "subdomain").map((it) => it.value)
          .filter((h) => h !== ctx.domain && inScope(h, ctx.domain)).slice(0, MAX_RESOLVE);
        for (const h of subs) {
          (await doh(h, "A")).forEach((a) => { const ip = normIp(a.data); if (ip) out.push({ type: "ip", value: ip }); });
        }
        ctx.note = "SPF " + (spf ? "✓" : "✗") + " · DMARC " + (dmarc ? "✓" : "✗") + (subs.length ? " · " + subs.length + S(" sous-domaine(s) résolu(s)", " subdomain(s) resolved") : "");
        return out;
      },
    },
    rdap: {
      label: "RDAP", group: "infra", transport: "fetch", scope: "domain",
      title: S("Registraire, dates, statut et serveurs de noms (RDAP, le WHOIS moderne) -- jamais le titulaire", "Registrar, dates, status and name servers (RDAP, modern WHOIS) -- never the registrant"),
      async run(ctx) {
        const d = await getJson("https://rdap.org/domain/" + encodeURIComponent(ctx.domain));
        const out = [];
        (Array.isArray(d.entities) ? d.entities : []).forEach((e) => {
          if (!e || !Array.isArray(e.roles) || e.roles.indexOf("registrar") === -1) return;
          const card = Array.isArray(e.vcardArray) && Array.isArray(e.vcardArray[1]) ? e.vcardArray[1] : [];
          const fn = card.find((f) => Array.isArray(f) && f[0] === "fn");
          if (fn && typeof fn[3] === "string") out.push({ type: "whois", value: "registrar: " + clip(fn[3], 200) });
        });
        (Array.isArray(d.events) ? d.events : []).forEach((ev) => {
          if (ev && /^(registration|expiration|last changed)$/.test(ev.eventAction) && typeof ev.eventDate === "string") {
            out.push({ type: "whois", value: ev.eventAction + ": " + ev.eventDate.slice(0, 10) });
          }
        });
        if (Array.isArray(d.status) && d.status.length) out.push({ type: "whois", value: "status: " + clip(d.status.filter((x) => typeof x === "string").join(", "), 300) });
        (Array.isArray(d.nameservers) ? d.nameservers : []).forEach((ns) => {
          const h = normHost(ns && ns.ldhName);
          if (h) out.push({ type: "dns", value: "NS " + h + "." });
        });
        return out;
      },
    },
    asn: {
      label: "ASN", group: "infra", transport: "fetch", scope: "target",
      title: S("Préfixe et ASN (hébergeur) de chaque IP trouvée, max " + MAX_IPS + " (RIPEstat) -- lancez DNS d'abord", "Prefix and ASN (hosting) of each IP found, max " + MAX_IPS + " (RIPEstat) -- run DNS first"),
      async run(ctx) {
        const ips = targetIps(ctx.t);
        if (!ips.length) throw new Error(S("aucune IP dans l'inventaire : lancez DNS d'abord", "no IP in the inventory: run DNS first"));
        const out = [];
        for (const ip of ips) {
          const d = await getJson("https://stat.ripe.net/data/prefix-overview/data.json?resource=" + encodeURIComponent(ip));
          const data = (d && d.data) || {};
          const prefix = typeof data.resource === "string" ? clip(data.resource, 60) : "";
          (Array.isArray(data.asns) ? data.asns : []).forEach((a) => {
            if (a && Number.isInteger(a.asn)) out.push({ type: "asn", value: "AS" + a.asn + " " + clip(a.holder || "", 120) + (prefix ? " · " + prefix : "") });
          });
        }
        ctx.note = ips.length + " IP";
        return out;
      },
    },
    internetdb: {
      label: "InternetDB", group: "expo", transport: "fetch", scope: "target",
      title: S("Ports ouverts et CVE connues de chaque IP trouvée, max " + MAX_IPS + " (Shodan InternetDB, sans clé) -- lancez DNS d'abord", "Open ports and known CVEs of each IP found, max " + MAX_IPS + " (Shodan InternetDB, no key) -- run DNS first"),
      async run(ctx) {
        const ips = targetIps(ctx.t);
        if (!ips.length) throw new Error(S("aucune IP dans l'inventaire : lancez DNS d'abord", "no IP in the inventory: run DNS first"));
        const out = [];
        for (const ip of ips) {
          const d = await getJson("https://internetdb.shodan.io/" + encodeURIComponent(ip), { notFoundOk: true });
          if (!d) continue;
          (Array.isArray(d.ports) ? d.ports : []).forEach((p) => { if (Number.isInteger(p) && p > 0 && p < 65536) out.push({ type: "port", value: ip + ":" + p }); });
          (Array.isArray(d.vulns) ? d.vulns : []).forEach((v) => { if (typeof v === "string" && CVE_RE.test(v)) out.push({ type: "cve", value: v + " · " + ip }); });
        }
        ctx.note = ips.length + " IP";
        return out;
      },
    },
    urlscan: {
      label: "urlscan", group: "expo", transport: "shell", scope: "domain",
      title: S("Scans publics existants sur urlscan.io (curl lancé dans le shell choisi)", "Existing public scans on urlscan.io (curl run in the chosen shell)"),
      command(domain) {
        return curlCmd("https://urlscan.io/api/v1/search/?size=100&q=" + encodeURIComponent("page.domain:" + domain + " OR page.apexDomain:" + domain), 60);
      },
      async run(ctx) {
        const body = httpBody(await shellRun(ctx, this.command(ctx.domain), "urlscan"));
        let d;
        try { d = JSON.parse(body); } catch (e) { throw new Error(S("réponse illisible", "unreadable response")); }
        const out = [];
        const urls = [];
        (Array.isArray(d && d.results) ? d.results : []).forEach((r) => {
          const p = (r && r.page) || {};
          const h = normHost(p.domain);
          if (!h || !inScope(h, ctx.domain)) return;
          if (typeof p.url === "string") urls.push(p.url);
          const ip = normIp(p.ip);
          if (ip) out.push({ type: "ip", value: ip });
        });
        return out.concat(urlItems(urls, ctx.domain));
      },
    },
    // ACTIF : seule source qui interroge le SITE de la cible (2 requêtes
    // HTTP par domaine). Hors « ▶ Tout ». Par le shell : ces fichiers
    // n'ont presque jamais d'en-tête CORS, le navigateur ne pourrait pas
    // les lire. Contenu lu comme du texte, jamais exécuté ni rendu.
    sitefiles: {
      label: "robots.txt + security.txt", group: "site", transport: "shell", scope: "domain",
      title: S("⚠ Actif : lit /robots.txt et /.well-known/security.txt sur le site de la cible (curl dans le shell choisi, 2 requêtes par domaine)",
        "⚠ Active: reads /robots.txt and /.well-known/security.txt on the target's site (curl in the chosen shell, 2 requests per domain)"),
      command(domain) {
        const get = (path) => "curl -sS -L --max-redirs 3 --max-time 15 --max-filesize 500000 -A NeonFlare-OSINT -w " +
          TC.shq("\\nNFHTTP:%{http_code}\\n") + " " + TC.shq("https://" + domain + path);
        return "printf 'NFFILE:robots\\n'; " + get("/robots.txt") + "; printf 'NFFILE:security\\n'; " + get("/.well-known/security.txt");
      },
      async run(ctx) {
        const text = await shellRun(ctx, this.command(ctx.domain), "sitefiles");
        const parts = {};
        text.split(/^NFFILE:(robots|security)\s*$/m).forEach((chunk, i, arr) => {
          if (i % 2 === 1) parts[chunk] = arr[i + 1] || "";
        });
        const out = [];
        const notes = [];
        const base = "https://" + ctx.domain;
        ["robots", "security"].forEach((name) => {
          const raw = parts[name] || "";
          const hm = /NFHTTP:(\d{3})\s*$/.exec(raw);
          const code = hm ? hm[1] : "000";
          const body = hm ? raw.slice(0, hm.index) : raw;
          const label = name === "robots" ? "robots.txt" : "security.txt";
          if (code !== "200") { notes.push(label + " " + (code === "000" ? S("injoignable", "unreachable") : code)); return; }
          let n = 0;
          body.split("\n").slice(0, 2000).forEach((line) => {
            const l = line.replace(/#.*$/, "").trim();
            const m = /^([A-Za-z-]+)\s*:\s*(.+)$/.exec(l);
            if (!m) return;
            const field = m[1].toLowerCase();
            const val = m[2].trim();
            if (name === "robots") {
              if (field === "disallow" || field === "allow") {
                if (!/^\//.test(val)) return;
                try { out.push.apply(out, urlItems([new URL(val, base).href], ctx.domain).filter((x) => x.type === "url")); n++; } catch (e) { /* chemin illisible */ }
              } else if (field === "sitemap") {
                const found = urlItems([val], ctx.domain).filter((x) => x.type === "url");
                out.push.apply(out, found);
                n += found.length;
              }
            } else if (/^(contact|expires|encryption|policy|acknowledgments|hiring|preferred-languages|canonical|csaf)$/.test(field)) {
              out.push({ type: "web", value: ctx.domain + " security.txt " + m[1] + ": " + clip(val, 300) });
              if (field === "expires" && !isNaN(Date.parse(val)) && Date.parse(val) < Date.now()) notes.push(S("security.txt expiré", "security.txt expired"));
              n++;
            }
          });
          notes.push(label + " ✓ (" + n + ")");
        });
        ctx.note = notes.join(" · ");
        return out;
      },
    },
  };
  const GROUPS = {
    sub: S("Sous-domaines & URL", "Subdomains & URLs"),
    infra: S("DNS & infrastructure", "DNS & infrastructure"),
    expo: S("Exposition", "Exposure"),
    site: S("Site de la cible ⚠ actif", "Target's site ⚠ active"),
  };
  // « ▶ Tout » : sources navigateur sans clé, dans l'ordre utile (DNS
  // avant ASN / InternetDB, qui partent des IP trouvées).
  const ALL_ORDER = ["crtsh", "dns", "rdap", "asn", "internetdb"];

  /* ---------------- Interface ---------------- */

  let statusWrap = null;
  const statusEls = {};
  let paneSelect = null;
  let listWrap = null;
  let countEl = null;
  let authBox = null;
  let scopeInput = null;
  let endInput = null;
  let endBanner = null;
  let notesList = null;
  let runButtons = [];
  let linksWrap = null;
  let busy = false;

  function currentTarget() {
    const tg = K.resolveTarget();
    if (tg.mode !== "domain" && tg.mode !== "name") return null;
    if (!tg.variants.length) return null;
    return { key: tg.mode === "domain" ? tg.name : tg.name + ".*", variants: tg.variants, display: tg.displayNoWild };
  }

  function setStatus(src, text, level) {
    let n = statusEls[src];
    if (!n) {
      n = statusEls[src] = el("div", "osint-inv-status-text");
      n.dataset.src = src;
      statusWrap.appendChild(n);
    }
    n.textContent = text;
    n.className = "osint-inv-status-text" + (level ? " " + level : "");
  }

  function dossier(t) {
    if (!t) return cleanTarget(null);
    if (!inv.targets[t.key]) inv.targets[t.key] = cleanTarget(null);
    return inv.targets[t.key];
  }

  function refreshAuth() {
    const t = currentTarget();
    const a = t ? (inv.targets[t.key] || cleanTarget(null)) : cleanTarget(null);
    authBox.checked = a.ok;
    authBox.disabled = !t;
    scopeInput.value = a.scope;
    scopeInput.disabled = !t;
    endInput.value = a.end;
    endInput.disabled = !t;
    runButtons.forEach((b) => { b.disabled = busy || !t || !a.ok; });
    renderLinks(t, a.ok);
    renderMailLinks();
    const today = new Date().toISOString().slice(0, 10);
    endBanner.hidden = !(t && a.end && a.end < today && inv.items.some((it) => it.target === t.key));
    if (!endBanner.hidden) {
      endBanner.firstChild.textContent = S("La date de fin du mandat (" + a.end + ") est passée : purger l'inventaire de cette cible ? ",
        "The engagement end date (" + a.end + ") has passed: purge this target's inventory? ");
    }
    renderNotes();
  }

  /* Liens ↗ (2026-11-10) : comme Google Dorks, c'est l'utilisateur qui
     consulte ces services avec son propre compte, dans un nouvel onglet ;
     NeonFlare n'en lit rien et ne garde rien. Actifs seulement une fois
     l'autorisation cochée (même règle que les ▶), chaque ouverture est
     notée dans le System log. Domaine = variante validée de la cible ;
     IP / ASN / CVE = valeurs revalidées par regex avant d'entrer dans une URL. */
  const enc = encodeURIComponent;
  const DOMAIN_LINKS = [
    { id: "shodan", label: "Shodan", url: (d) => "https://www.shodan.io/domain/" + enc(d),
      title: S("Hôtes et services indexés par Shodan pour ce domaine", "Hosts and services Shodan indexed for this domain") },
    { id: "virustotal", label: "VirusTotal", url: (d) => "https://www.virustotal.com/gui/domain/" + enc(d),
      title: S("Réputation, sous-domaines et résolutions connus de VirusTotal", "Reputation, subdomains and resolutions known to VirusTotal") },
    { id: "censys", label: "Censys", url: (d) => "https://platform.censys.io/search?q=" + enc(d),
      title: S("Hôtes et certificats indexés par Censys", "Hosts and certificates indexed by Censys") },
    { id: "securitytrails", label: "SecurityTrails", url: (d) => "https://securitytrails.com/domain/" + enc(d) + "/dns",
      title: S("DNS actuel et historique (SecurityTrails)", "Current and historical DNS (SecurityTrails)") },
    { id: "builtwith", label: "BuiltWith", url: (d) => "https://builtwith.com/" + enc(d),
      title: S("Technologies utilisées par le site (BuiltWith)", "Technologies used by the site (BuiltWith)") },
    { id: "archivetoday", label: "archive.today", url: (d) => "https://archive.ph/*." + d,
      title: S("Captures archive.today du domaine et de ses sous-domaines", "archive.today captures of the domain and its subdomains") },
    { id: "grepapp", label: "grep.app", url: (d) => "https://grep.app/search?q=" + enc(d),
      title: S("Mentions du domaine dans le code public (GitHub, GitLab…) : clés, URL internes", "Mentions of the domain in public code (GitHub, GitLab…): keys, internal URLs") },
    { id: "hunter", label: "Hunter.io", url: (d) => "https://hunter.io/search/" + enc(d),
      title: S("Adresses publiques connues et format des courriels du domaine (Hunter.io) -- mandat d'ingénierie sociale seulement", "Known public addresses and e-mail format of the domain (Hunter.io) -- social-engineering engagements only") },
    { id: "phonebook", label: "Phonebook.cz", generic: true, url: () => "https://phonebook.cz/",
      title: S("Courriels et sous-domaines vus dans les fuites et le web (saisissez le domaine sur la page) -- mandat d'ingénierie sociale seulement", "E-mails and subdomains seen in leaks and on the web (enter the domain on the page) -- social-engineering engagements only") },
    { id: "dnsdumpster", label: "DNSDumpster", generic: true, url: () => "https://dnsdumpster.com/",
      title: S("Cartographie DNS (saisissez le domaine sur la page)", "DNS mapping (enter the domain on the page)") },
    { id: "hibp", label: "Have I Been Pwned", generic: true, url: () => "https://haveibeenpwned.com/DomainSearch",
      title: S("Recherche de fuites par domaine sur haveibeenpwned.com (connexion et vérification du domaine chez HIBP ; NeonFlare ne transmet ni ne garde rien)",
        "Breach search by domain on haveibeenpwned.com (HIBP sign-in and domain verification; NeonFlare sends and keeps nothing)") },
  ];

  function extLink(id, label, url, title, ok) {
    const a = K.link("↗ " + label, title + S(" -- votre compte, nouvel onglet", " -- your account, new tab"));
    a.dataset.src = id + "-link";
    K.setLink(a, ok && url ? url : "");
    if (ok && url) a.addEventListener("click", () => K.log("osint", "↗ " + url.replace(/^https:\/\//, "")));
    return a;
  }

  function authOk(t) { return !!(t && inv.targets[t.key] && inv.targets[t.key].ok); }

  let linkVariant = "";
  function renderLinks(t, ok) {
    if (!linksWrap) return;
    linksWrap.textContent = "";
    const variants = t ? t.variants : [];
    if (variants.indexOf(linkVariant) === -1) linkVariant = variants[0] || "";
    if (variants.length > 1) {
      const sel = el("select", "dorks-select osint-inv-select osint-inv-variant");
      sel.title = S("Domaine visé par les liens", "Domain the links point to");
      variants.forEach((d) => { const o = el("option", null, d); o.value = d; sel.appendChild(o); });
      sel.value = linkVariant;
      sel.addEventListener("change", () => { linkVariant = sel.value; renderLinks(currentTarget(), authOk(currentTarget())); });
      linksWrap.appendChild(sel);
    }
    DOMAIN_LINKS.forEach((L) => {
      linksWrap.appendChild(extLink(L.id, L.label, L.generic ? L.url() : (linkVariant ? L.url(linkVariant) : ""), L.title, !!(t && ok)));
    });
  }

  /* « Vérifier une adresse » : l'adresse ne sert QU'À construire les deux
     liens. Jamais enregistrée (ni inventaire, ni localStorage, ni System log,
     ni attribut du champ), et limitée au domaine de la cible (minimisation,
     Loi 25). Ingénierie sociale : seulement si le mandat la couvre. */
  const EMAIL_RE = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@([a-z0-9.-]{1,253})$/i;
  let mailInput = null;
  let mailWrap = null;
  function renderMailLinks() {
    if (!mailWrap) return;
    const t = currentTarget();
    const ok = authOk(t);
    const raw = (mailInput.value || "").trim();
    const m = EMAIL_RE.exec(raw);
    const host = m ? normHost(m[1]) : "";
    const inTarget = !!(t && host && t.variants.some((d) => inScope(host, d)));
    const addr = inTarget ? raw.toLowerCase() : "";
    mailInput.classList.toggle("invalid", !!raw && !inTarget);
    mailInput.title = raw && !inTarget ? S("Adresse invalide ou hors du domaine de la cible", "Invalid address or outside the target's domain") : "";
    mailWrap.textContent = "";
    [["hibpmail", "Have I Been Pwned", (a) => "https://haveibeenpwned.com/account/" + enc(a), S("Cette adresse apparaît-elle dans des fuites ?", "Does this address appear in breaches?")],
     ["epieos", "Epieos", (a) => "https://epieos.com/?q=" + enc(a) + "&t=email", S("Comptes publics liés à cette adresse", "Public accounts linked to this address")]]
      .forEach((x) => {
        const a = K.link("↗ " + x[1], x[3] + S(" -- votre compte, nouvel onglet ; l'adresse n'est pas enregistrée", " -- your account, new tab; the address is not stored"));
        a.dataset.src = x[0] + "-link";
        K.setLink(a, ok && addr ? x[2](addr) : "");
        // Journal SANS l'adresse.
        if (ok && addr) a.addEventListener("click", () => K.log("osint", "↗ " + x[1] + S(" (vérification d'une adresse de ", " (address check for ") + t.key + ")"));
        mailWrap.appendChild(a);
      });
  }

  // Liens d'une ligne de l'inventaire, selon son type.
  function rowLinks(it, ok) {
    const out = [];
    const ipLinks = (ip) => [
      ["abuseipdb", "AbuseIPDB", "https://www.abuseipdb.com/check/" + enc(ip), S("Signalements d'abus pour cette IP", "Abuse reports for this IP")],
      ["greynoise", "GreyNoise", "https://viz.greynoise.io/ips/" + enc(ip), S("Cette IP balaie-t-elle Internet ? (GreyNoise)", "Is this IP scanning the Internet? (GreyNoise)")],
      ["shodanhost", "Shodan", "https://www.shodan.io/host/" + enc(ip), S("Services de cette IP sur Shodan", "This IP's services on Shodan")],
      ["bgp", "BGP", "https://bgp.he.net/ip/" + enc(ip), S("Préfixe et ASN (Hurricane Electric)", "Prefix and ASN (Hurricane Electric)")],
    ];
    if (it.type === "ip" && normIp(it.value)) {
      ipLinks(it.value).forEach((x) => out.push(x));
    } else if (it.type === "port") {
      const ip = normIp(it.value.slice(0, it.value.lastIndexOf(":")));
      if (ip) out.push(ipLinks(ip)[2]);
    } else if (it.type === "asn") {
      const m = /^AS(\d{1,10})\b/.exec(it.value);
      if (m) out.push(["bgpasn", "BGP", "https://bgp.he.net/AS" + m[1], S("Plages d'adresses et pairs de cet ASN", "This ASN's address ranges and peers")]);
    } else if (it.type === "cve") {
      const m = /^(CVE-\d{4}-\d{4,7})\b/.exec(it.value);
      if (m) out.push(["nvd", "NVD", "https://nvd.nist.gov/vuln/detail/" + m[1], S("Fiche de la vulnérabilité (NVD)", "Vulnerability record (NVD)")]);
    } else if (it.type === "subdomain" && normHost(it.value)) {
      out.push(["vtsub", "VirusTotal", "https://www.virustotal.com/gui/domain/" + enc(it.value), S("Ce sous-domaine sur VirusTotal", "This subdomain on VirusTotal")]);
    }
    return out.map((x) => extLink(x[0], x[1], x[2], x[3], ok));
  }

  async function refreshPanes() {
    const panes = (await TC.requestPaneList()).filter((p) => p.type === "bash" || p.type === "zsh");
    const prev = paneSelect.value;
    paneSelect.textContent = "";
    if (!panes.length) {
      const o = el("option", null, S("aucun shell Bash/Zsh ouvert", "no Bash/Zsh shell open"));
      o.value = "";
      paneSelect.appendChild(o);
      return;
    }
    panes.forEach((p) => {
      const o = el("option", null, TC.paneLabel(p));
      o.value = p.type + ":" + p.slot;
      paneSelect.appendChild(o);
    });
    if (Array.from(paneSelect.options).some((o) => o.value === prev)) paneSelect.value = prev;
  }

  function selectedPort() {
    const m = /^(bash|zsh):(\d+)$/.exec(paneSelect.value || "");
    return m ? TC.portFor({ type: m[1], slot: parseInt(m[2], 10) }) : null;
  }

  function shellRun(ctx, command, src) {
    if (!ctx.port) {
      throw new Error(S("ouvrez un shell Bash ou Zsh (« + SHELL ») et choisissez-le, ou copiez la commande (⧉)",
        "open a Bash or Zsh shell (\"+ SHELL\") and pick it, or copy the command (⧉)"));
    }
    return TC.captureLarge(ctx.port, command, {
      timeoutMs: 130000,
      onProgress: (r) => setStatus(src, SOURCES[src].label + " · " + ctx.domain + S(" : lecture ", ": reading ") + Math.round(r * 100) + " %", "pending"),
    });
  }

  function setBusy(on) {
    busy = on;
    refreshAuth();
  }

  async function runOne(src, t, at) {
    const def = SOURCES[src];
    const domains = def.scope === "target" ? [null] : t.variants;
    for (const domain of domains) {
      const where = domain ? " · " + domain : "";
      const ctx = { t, domain, port: def.transport === "shell" ? selectedPort() : null, note: "" };
      setStatus(src, def.label + where + " : " + (def.transport === "shell" ? S("commande en cours dans le shell…", "command running in the shell…") : S("interrogation…", "querying…")), "pending");
      try {
        const found = await def.run(ctx);
        let added = 0;
        found.forEach((f) => { if (merge(t.key, f.type, f.value, src, at)) added++; });
        saveInv();
        setStatus(src, def.label + where + " : " + found.length + S(" résultat(s), ", " result(s), ") + added + S(" nouveau(x)", " new") + (ctx.note ? " · " + ctx.note : ""), "ok");
        K.log("osint", def.label + (domain ? " " + domain : "") + " -> " + found.length + " (" + added + " new)");
      } catch (e) {
        setStatus(src, def.label + where + " : " + S("échec", "failed") + " (" + errText(e) + ")", "fail");
        K.log("osint", def.label + (domain ? " " + domain : "") + " failed: " + errText(e));
        if (def.transport === "shell" && !ctx.port) break;
      }
    }
  }

  async function run(list) {
    const t = currentTarget();
    if (!t || !(inv.targets[t.key] && inv.targets[t.key].ok) || busy) return;
    const at = now();
    setBusy(true);
    try {
      for (const src of list) await runOne(src, t, at);
    } finally {
      setBusy(false);
      renderList();
    }
  }

  /* ---------------- Actions sur un élément ---------------- */

  function srcLabels(it) { return it.sources.map((s) => (SOURCES[s] ? SOURCES[s].label : s)).join(", "); }

  function toGrc(it) {
    if (typeof GRC.addAsset !== "function") return;
    const base = {
      name: it.value,
      type: GRC_TYPE[it.type] || "reseau",
      notes: "OSINT " + TYPES[it.type] + " (" + srcLabels(it) + ") · " + S("découvert le ", "found on ") + it.firstSeen.slice(0, 10) +
        " · " + S("cible ", "target ") + it.target,
    };
    const asset = (typeof grkEnsure === "function" && typeof GRC_ASSET_FORM_SCHEMA === "object")
      ? Object.assign(grkEnsure(base, GRC_ASSET_FORM_SCHEMA), { name: base.name, notes: base.notes }) : base;
    try {
      it.grcAssetId = GRC.addAsset(asset);
      it.status = "kept";
      saveInv();
      K.log("osint", "→ GRC asset: " + it.value);
    } catch (e) {
      alert(S("Ajout au registre d'actifs impossible : ", "Could not add to the asset register: ") + errText(e));
    }
    renderList();
  }

  function toFinding(it) {
    if (typeof GRC.openQuickFinding !== "function") return;
    GRC.openQuickFinding();
    const title = document.getElementById("quickFindingTitle");
    const ev = document.getElementById("quickFindingEvidence");
    if (title && !title.value) {
      title.value = it.type === "cve" ? it.value : S("Exposition : ", "Exposure: ") + it.value;
    }
    if (ev && !ev.value) {
      ev.value = S("Découvert par OSINT passif (", "Found by passive OSINT (") + srcLabels(it) + ")\n" +
        TYPES[it.type] + " : " + it.value + "\n" + S("Première observation : ", "First seen: ") + it.firstSeen;
    }
  }

  function useAsTarget(it) {
    const input = root.querySelector(".osint-target .dorks-input");
    if (!input) return;
    input.value = it.value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.focus();
  }

  /* ---------------- Liste ---------------- */

  function visibleItems() {
    const t = currentTarget();
    const q = ui.q.trim().toLowerCase();
    return inv.items.filter((it) => (!t || it.target === t.key) &&
      (!ui.type || it.type === ui.type) &&
      (!ui.source || it.sources.indexOf(ui.source) !== -1) &&
      (!ui.status || it.status === ui.status) &&
      (!q || it.value.toLowerCase().indexOf(q) !== -1));
  }

  function renderList() {
    if (!listWrap) return;
    const t = currentTarget();
    const all = visibleItems();
    const forTarget = t ? inv.items.filter((it) => it.target === t.key).length : 0;
    countEl.textContent = t
      ? all.length + " / " + forTarget + S(" élément(s) pour ", " item(s) for ") + t.display
      : S("Saisissez une cible valide (domaine ou nom + extensions).", "Enter a valid target (domain or name + extensions).");
    listWrap.textContent = "";
    if (!t) return;
    if (!all.length) {
      listWrap.appendChild(el("p", "osint-inv-empty", forTarget
        ? S("Aucun élément ne correspond aux filtres.", "No item matches the filters.")
        : S("Rien encore : cochez l'autorisation puis lancez une collecte (▶).", "Nothing yet: tick the authorisation box, then run a collection (▶).")));
      return;
    }
    const table = el("table", "osint-inv-table");
    const thead = el("thead");
    const hr = el("tr");
    [S("Valeur", "Value"), S("Type", "Type"), S("Sources", "Sources"), S("Vu le", "Seen"), S("Statut", "Status"), ""].forEach((h) => hr.appendChild(el("th", null, h)));
    thead.appendChild(hr);
    table.appendChild(thead);
    const tbody = el("tbody");
    const rowOk = authOk(t);
    all.slice(0, ROW_CAP).forEach((it) => {
      const tr = el("tr", it.status === "dismissed" ? "dismissed" : "");
      const tdV = el("td", "osint-inv-value");
      tdV.appendChild(el("span", null, it.value));
      tr.appendChild(tdV);
      tr.appendChild(el("td", null, TYPES[it.type]));
      tr.appendChild(el("td", null, srcLabels(it)));
      tr.appendChild(el("td", "osint-inv-date", it.firstSeen.slice(0, 10)));

      const tdS = el("td");
      const sel = el("select", "dorks-select osint-inv-select");
      Object.keys(STATUSES).forEach((k) => {
        const o = el("option", null, STATUSES[k]);
        o.value = k;
        sel.appendChild(o);
      });
      sel.value = it.status;
      sel.addEventListener("change", () => { it.status = sel.value; saveInv(); tr.classList.toggle("dismissed", it.status === "dismissed"); });
      tdS.appendChild(sel);
      tr.appendChild(tdS);

      const tdA = el("td", "osint-inv-actions");
      const grc = K.button("", it.grcAssetId ? "✓ GRC" : "→ GRC",
        it.grcAssetId ? S("Déjà ajouté au registre d'actifs", "Already in the asset register") : S("Ajouter au registre d'actifs GRC", "Add to the GRC asset register"));
      grc.disabled = !!it.grcAssetId || typeof GRC.addAsset !== "function";
      grc.addEventListener("click", () => toGrc(it));
      const fnd = K.button("", "→ Finding", S("Créer un finding pentest pré-rempli", "Create a pre-filled pentest finding"));
      fnd.disabled = typeof GRC.openQuickFinding !== "function";
      fnd.addEventListener("click", () => toFinding(it));
      tdA.append(grc, fnd);
      rowLinks(it, rowOk).forEach((a) => tdA.appendChild(a));
      if (it.type === "subdomain") {
        const tg = K.button("", "◎", S("Utiliser comme cible des panneaux OSINT", "Use as the OSINT panels' target"));
        tg.addEventListener("click", () => useAsTarget(it));
        tdA.appendChild(tg);
      } else if (it.type === "url") {
        // Lien vers l'ARCHIVE uniquement (passif), jamais vers la cible.
        const a = K.link("↗", S("Voir dans la Wayback Machine", "View in the Wayback Machine"));
        a.href = "https://web.archive.org/web/*/" + encodeURI(it.value);
        tdA.appendChild(a);
      }
      tr.appendChild(tdA);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    listWrap.appendChild(table);
    if (all.length > ROW_CAP) {
      listWrap.appendChild(el("p", "osint-inv-empty", (all.length - ROW_CAP) + S(" autre(s) non affiché(s) : affinez les filtres ou exportez.", " more not shown: narrow the filters or export.")));
    }
  }

  /* ---------------- Dossier : notes, export, purge ---------------- */

  function renderNotes() {
    if (!notesList) return;
    const t = currentTarget();
    notesList.textContent = "";
    const notes = t && inv.targets[t.key] ? inv.targets[t.key].notes : [];
    if (!notes.length) {
      notesList.appendChild(el("li", "osint-inv-empty", S("Aucune note.", "No notes.")));
      return;
    }
    notes.slice().reverse().forEach((n) => {
      const li = el("li", "osint-note");
      li.append(el("span", "osint-note-at", n.at.slice(0, 16).replace("T", " ")), el("span", "osint-note-text", n.text));
      notesList.appendChild(li);
    });
  }

  function download(name, mime, text) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: mime }));
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  // Cellule CSV : guillemets doublés + neutralisation des formules
  // (=, +, -, @ en tête -> apostrophe), une URL archivée pouvant être n'importe quoi.
  function csvCell(v) {
    let s = String(v == null ? "" : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }

  function fileBase(t) {
    return "osint-" + t.key.replace(/[^a-z0-9.-]/g, "_") + "-" + new Date().toISOString().slice(0, 10);
  }

  function exportItems(fmt) {
    const t = currentTarget();
    if (!t) return;
    const items = visibleItems();
    if (fmt === "json") {
      download(fileBase(t) + ".json", "application/json", JSON.stringify({ target: t.key, exportedAt: now(), items }, null, 2));
    } else {
      const rows = [["target", "type", "value", "sources", "firstSeen", "lastSeen", "status"]]
        .concat(items.map((it) => [it.target, it.type, it.value, it.sources.join("|"), it.firstSeen, it.lastSeen, it.status]));
      download(fileBase(t) + ".csv", "text/csv", rows.map((r) => r.map(csvCell).join(",")).join("\r\n"));
    }
  }

  // Dossier complet (rapport pentest) : autorisation, périmètre, fin, notes, TOUT l'inventaire de la cible.
  function exportDossier() {
    const t = currentTarget();
    if (!t) return;
    download(fileBase(t) + "-dossier.json", "application/json", JSON.stringify({
      target: t.key,
      variants: t.variants,
      exportedAt: now(),
      dossier: inv.targets[t.key] || cleanTarget(null),
      items: inv.items.filter((it) => it.target === t.key),
    }, null, 2));
  }

  function purge() {
    const t = currentTarget();
    if (!t) return;
    const n = inv.items.filter((it) => it.target === t.key).length;
    if (!confirm(S("Supprimer les " + n + " élément(s), l'autorisation et les notes enregistrés pour « " + t.key + " » ?",
      "Delete the " + n + " item(s), the authorisation and the notes stored for \"" + t.key + "\"?"))) return;
    inv.items = inv.items.filter((it) => it.target !== t.key);
    delete inv.targets[t.key];
    reindex();
    saveInv();
    K.log("osint", "purge " + t.key + " (" + n + ")");
    refreshAuth();
    renderList();
  }

  /* ---------------- Construction ---------------- */

  function filterSelect(key, options, allLabel) {
    const s = el("select", "dorks-select osint-inv-select");
    const o0 = el("option", null, allLabel);
    o0.value = "";
    s.appendChild(o0);
    Object.keys(options).forEach((k) => {
      const o = el("option", null, options[k]);
      o.value = k;
      s.appendChild(o);
    });
    s.value = options[ui[key]] ? ui[key] : "";
    s.addEventListener("change", () => { ui[key] = s.value; saveUi(); renderList(); });
    return s;
  }

  function build() {
    root.textContent = "";
    inv = loadInv();
    reindex();

    K.renderTargetBar(root, { collapsed: true, wildNote: () => null });

    // Autorisation (V3) + périmètre + fin du mandat : par cible.
    const auth = el("div", "osint-options osint-inv-auth");
    const lab = el("label", "dorks-opt");
    authBox = el("input");
    authBox.type = "checkbox";
    lab.append(authBox, el("span", null, S("J'ai l'autorisation d'étudier cette cible", "I am authorised to study this target")));
    scopeInput = el("input", "dorks-input osint-small-input osint-inv-scope");
    scopeInput.type = "text";
    scopeInput.maxLength = 300;
    scopeInput.placeholder = S("Mandat / périmètre (facultatif)", "Engagement / scope (optional)");
    const endLab = el("label", "osint-inv-end");
    endInput = el("input", "dorks-input osint-small-input");
    endInput.type = "date";
    endInput.title = S("Fin du mandat : passé cette date, la purge de la cible est proposée", "Engagement end: after this date, purging the target is offered");
    endLab.append(el("span", null, S("Fin :", "End:")), endInput);
    function saveAuth() {
      const t = currentTarget();
      if (!t) return;
      const d = dossier(t);
      if (authBox.checked && !d.ok) d.at = now();
      d.ok = authBox.checked;
      if (!d.ok) d.at = "";
      d.scope = scopeInput.value.slice(0, 300);
      d.end = /^\d{4}-\d{2}-\d{2}$/.test(endInput.value) ? endInput.value : "";
      saveInv();
      refreshAuth();
      renderList();
    }
    authBox.addEventListener("change", saveAuth);
    scopeInput.addEventListener("change", saveAuth);
    endInput.addEventListener("change", saveAuth);
    auth.append(lab, scopeInput, endLab);
    root.appendChild(auth);

    endBanner = el("div", "osint-inv-banner");
    endBanner.hidden = true;
    endBanner.appendChild(document.createTextNode(""));
    const bPurgeNow = K.button("osint-inv-purge", "🗑 " + S("Purger", "Purge"));
    bPurgeNow.addEventListener("click", purge);
    endBanner.appendChild(bPurgeNow);
    root.appendChild(endBanner);

    // Collecte, par groupe.
    runButtons = [];
    Object.keys(GROUPS).forEach((g) => {
      const row = el("div", "osint-options osint-inv-run");
      row.appendChild(el("span", "osint-inv-group", GROUPS[g] + " :"));
      Object.keys(SOURCES).filter((s) => SOURCES[s].group === g).forEach((s) => {
        const def = SOURCES[s];
        const b = K.button("", "▶ " + def.label + (def.transport === "shell" ? " ⌨" : ""), def.title);
        b.dataset.src = s;
        b.addEventListener("click", () => run([s]));
        runButtons.push(b);
        row.appendChild(b);
      });
      if (g === "sub") {
        const bAll = K.button("osint-inv-all", "▶ " + S("Tout (navigateur)", "All (browser)"),
          S("crt.sh, DNS, RDAP, ASN puis InternetDB, dans cet ordre -- sans shell", "crt.sh, DNS, RDAP, ASN then InternetDB, in that order -- no shell"));
        bAll.dataset.src = "all";
        bAll.addEventListener("click", () => run(ALL_ORDER));
        runButtons.push(bAll);
        row.appendChild(bAll);
      }
      root.appendChild(row);
    });
    const linkRow = el("div", "osint-options osint-inv-run");
    linkRow.appendChild(el("span", "osint-inv-group", S("Liens ↗ (votre compte) :", "Links ↗ (your account):")));
    linksWrap = el("span", "osint-inv-links");
    linkRow.appendChild(linksWrap);
    root.appendChild(linkRow);
    const mailRow = el("div", "osint-options osint-inv-run");
    mailRow.appendChild(el("span", "osint-inv-group", S("Vérifier une adresse :", "Check an address:")));
    mailInput = el("input", "dorks-input osint-small-input osint-inv-mail");
    mailInput.type = "email";
    mailInput.autocomplete = "off";
    mailInput.spellcheck = false;
    mailInput.placeholder = S("prenom.nom@domaine-de-la-cible", "first.last@target-domain");
    mailInput.addEventListener("input", renderMailLinks);
    mailWrap = el("span", "osint-inv-links");
    mailRow.append(mailInput, mailWrap);
    root.appendChild(mailRow);

    // Réglages des sources ⌨ (shell).
    const shellRow = el("div", "osint-options osint-inv-shell");
    shellRow.appendChild(el("span", "osint-inv-group", "⌨ " + S("Shell :", "Shell:")));
    paneSelect = el("select", "dorks-select osint-inv-select");
    paneSelect.title = S("Shell où lancer les sources ⌨ (la commande s'y affiche brièvement, puis l'écran est nettoyé)", "Shell where ⌨ sources run (the command briefly shows there, then the screen is cleared)");
    const bPanes = K.button("", "⟳", S("Rafraîchir la liste des shells", "Refresh the shell list"));
    bPanes.addEventListener("click", refreshPanes);
    const limit = el("select", "dorks-select osint-inv-select");
    limit.title = S("Nombre maximal d'URL demandées à Wayback", "Maximum number of URLs asked from Wayback");
    ["1000", "5000", "20000"].forEach((n) => { const o = el("option", null, "Wayback ≤ " + n); o.value = n; limit.appendChild(o); });
    limit.value = ["1000", "5000", "20000"].indexOf(ui.limit) !== -1 ? ui.limit : "5000";
    limit.addEventListener("change", () => { ui.limit = limit.value; saveUi(); });
    const copyCmds = K.copyButton(() => {
      const t = currentTarget();
      if (!t) return "";
      return Object.keys(SOURCES).filter((s) => SOURCES[s].transport === "shell")
        .map((s) => t.variants.map((d) => "# " + SOURCES[s].label + "\n" + SOURCES[s].command(d)).join("\n")).join("\n");
    }, S("Copier les commandes ⌨ (à lancer vous-même)", "Copy the ⌨ commands (to run yourself)"));
    shellRow.append(paneSelect, bPanes, limit, copyCmds);
    root.appendChild(shellRow);

    statusWrap = el("div", "osint-inv-status");
    root.appendChild(statusWrap);

    // Filtres + export.
    const fl = el("div", "osint-options osint-inv-filters");
    const q = el("input", "dorks-input osint-small-input");
    q.type = "search";
    q.placeholder = S("Filtrer…", "Filter…");
    q.value = ui.q;
    q.addEventListener("input", () => { ui.q = q.value; saveUi(); renderList(); });
    const srcNames = {};
    Object.keys(SOURCES).forEach((s) => { srcNames[s] = SOURCES[s].label; });
    const bCsv = K.button("", "⤓ CSV", S("Exporter la liste filtrée en CSV", "Export the filtered list as CSV"));
    bCsv.addEventListener("click", () => exportItems("csv"));
    const bJson = K.button("", "⤓ JSON", S("Exporter la liste filtrée en JSON", "Export the filtered list as JSON"));
    bJson.addEventListener("click", () => exportItems("json"));
    const bPurge = K.button("osint-inv-purge", "🗑 " + S("Purger la cible", "Purge target"), S("Supprimer l'inventaire, l'autorisation et les notes de cette cible", "Delete this target's inventory, authorisation and notes"));
    bPurge.addEventListener("click", purge);
    fl.append(q,
      filterSelect("type", TYPES, S("Tous types", "All types")),
      filterSelect("source", srcNames, S("Toutes sources", "All sources")),
      filterSelect("status", STATUSES, S("Tous statuts", "All statuses")),
      bCsv, bJson, bPurge);
    root.appendChild(fl);

    countEl = el("div", "osint-inv-count");
    root.appendChild(countEl);
    listWrap = el("div", "osint-inv-list");
    root.appendChild(listWrap);

    // Dossier : notes horodatées + export complet.
    const det = el("details", "osint-inv-dossier");
    det.appendChild(el("summary", null, S("Dossier de la cible : notes et export", "Target file: notes and export")));
    const noteRow = el("div", "osint-options");
    const noteIn = el("textarea", "dorks-input osint-note-input");
    noteIn.rows = 2;
    noteIn.maxLength = 2000;
    noteIn.placeholder = S("Note horodatée (constat, preuve, échange avec le client…)", "Timestamped note (observation, evidence, client exchange…)");
    const bNote = K.button("", "+ " + S("Ajouter la note", "Add note"));
    bNote.addEventListener("click", () => {
      const t = currentTarget();
      const text = noteIn.value.trim();
      if (!t || !text) return;
      const d = dossier(t);
      d.notes.push({ at: now(), text: text.slice(0, 2000) });
      if (d.notes.length > MAX_NOTES) d.notes = d.notes.slice(-MAX_NOTES);
      saveInv();
      noteIn.value = "";
      renderNotes();
    });
    const bDossier = K.button("", "⤓ " + S("Dossier complet (JSON)", "Full file (JSON)"), S("Autorisation, périmètre, fin, notes et tout l'inventaire de la cible", "Authorisation, scope, end, notes and the target's whole inventory"));
    bDossier.addEventListener("click", exportDossier);
    noteRow.append(noteIn, bNote, bDossier);
    det.appendChild(noteRow);
    notesList = el("ul", "osint-notes");
    det.appendChild(notesList);
    root.appendChild(det);

    K.onTargetChange(() => { refreshAuth(); renderList(); });
    refreshAuth();
    renderList();
    refreshPanes();
  }

  function init() {
    if (api.vault.gate(root, init)) return;
    build();
  }

  init();
};
