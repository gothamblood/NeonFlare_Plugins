/* Plugin NeonRelay pour NeonFlare -- panneau du Dashboard
   (localrepo/spec/plugins/NEONRELAY.md).

   Le navigateur ne contacte JAMAIS le relais (permissions.network = []). Le
   panneau tape, dans un shell NeonFlare choisi, une ligne SANS Entrée et sans
   rien de sensible :
       bash '<NeonFlare>/plugins/neonrelay/tools/nf-open.sh' <outil> <nonce>
   L'utilisateur appuie sur Entrée. nf-open.sh coupe l'écho, affiche
   NFR-READY:<SHA-256 du nonce> ; le panneau (déjà à l'écoute,
   TtydCapture.deliverOnMarker) répond alors par UNE ligne masquée : adresse,
   identifiant et secrets ENREGISTRÉS de la boîte (base64). Ce qui manque est
   demandé dans le shell, en saisie masquée. Rien ne finit dans l'historique.

   Boîtes : coffre (/plugins/neonrelay/secure/boxes). Secrets enregistrés
   seulement si l'utilisateur coche la case ET que le coffre est activé
   (jamais en clair). Tout le texte est rendu avec textContent. */
(function () {
  "use strict";

  const BOXES_KEY = "/plugins/neonrelay/secure/boxes";
  const DEFAULT_BASE = "https://179.197.84.173:8000";
  // Empreinte du cert.pem livré dans ce plugin (vérifiée par le test NR.c).
  const CERT_SHA256 = "A1:36:49:2E:CA:CC:F8:67:96:27:C0:D7:55:58:E3:35:D8:97:F7:A0:1E:7A:10:EC:4D:AD:7E:BC:FC:AB:45:73";
  const BASE_RE = /^https:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?$/;
  const TOKEN_RE = /^[A-Za-z0-9_-]{1,128}$/;
  const TOOLS = {
    // outil : ce dont il a besoin (box = adresse + identifiant + mot de passe [+ clé, PIN])
    "secure-shell": "box", stream: "box", relay: "box", stash: "box", readstash: "box",
    delete: "box", count: "box", health: "base", token: "base", "make-key": "base",
    client: "none", "check-key": "none", "make-pin": "none", claviers: "none",
  };

  const STR = {
    fr: {
      box: "Boîte", shell: "Shell", add: "+ Ajouter", edit: "✎", del: "Supprimer",
      noBox: "Aucune boîte : ajoutez-en une (identifiant de la boîte, adresse du relais).",
      noShell: "Aucun shell ouvert", newBash: "Nouveau Bash", newZsh: "Nouveau Zsh",
      launch: "▶ Lancer le canal", tools: "Outils (boîte et shell choisis)", connect: "Connexion",
      operator: "Opérateur", cert: "Certificat épinglé (SHA-256) : ",
      ttydOff: "Les shells ne tournent pas : lancez scripts/ttyd-shells.sh start, puis ouvrez un shell.",
      pickShell: "Ouvrez un shell (Bash ou Zsh) ou choisissez « Nouveau Bash ».",
      pathHttp: "Dossier de NeonFlare sur ce poste (celui qui contient index.html) :",
      pathBad: "Indiquez le dossier de NeonFlare (chemin absolu).",
      typed: "Commande tapée dans « {shell} » : appuyez sur Entrée dans ce shell. Rien n'est lancé sans vous.",
      delivered: "Valeurs de la boîte remises au shell (saisie masquée, rien dans l'historique).",
      notDelivered: "Rien n'a été envoyé au shell : les valeurs vous y seront demandées.",
      typedNone: "Commande tapée dans « {shell} » : appuyez sur Entrée dans ce shell.",
      name: "Nom", base: "Adresse du relais", token: "Identifiant de la boîte (token)",
      pw: "Mot de passe de la boîte", key: "Clé de chiffrement E2E", pin: "PIN",
      once: "Pour ce lancement (facultatif, rien n'est enregistré) — sinon le shell les demande :",
      onceSaved: "enregistré", show: "Afficher / masquer",
      short: { pw: "Mot de passe", key: "Clé E2E", pin: "PIN" },
      save: "Enregistrer (à mes risques)", saved: "enregistré", clear: "oublier",
      saveBox: "Enregistrer la boîte", cancel: "Annuler",
      secretsWarn: "Par défaut, aucun secret n'est gardé : le shell vous les demande en saisie masquée. Cocher « Enregistrer » les garde chiffrés par le coffre ; ils sont remis au shell en saisie masquée, jamais tapés en clair.",
      vaultOff: "Pour enregistrer des secrets, activez le coffre : \"enabled\": true dans config/encryption.js, puis Paramètres › Chiffrement › Activer le chiffrement. Ils ne sont jamais gardés en clair. Sans coffre, utilisez les champs « Pour ce lancement ».",
      badBase: "Adresse invalide (https://hôte:port).", badToken: "Identifiant invalide (lettres, chiffres, _ et -).",
      confirmDel: "Supprimer la boîte « {name} » (et ses secrets enregistrés) ?",
      t: {
        "secure-shell": "Canal chiffré", stream: "Écouter", relay: "Relayer", stash: "Déposer",
        readstash: "Lire", delete: "Supprimer la boîte (serveur)", count: "Compter", health: "Santé du relais",
        token: "Nouveau token (admin)", client: "Client autonome (clé)", "check-key": "Vérifier une clé",
        "make-key": "Fabriquer une clé", "make-pin": "Tirer un PIN", claviers: "Claviers",
      },
    },
    en: {
      box: "Box", shell: "Shell", add: "+ Add", edit: "✎", del: "Delete",
      noBox: "No box yet: add one (box id, relay address).",
      noShell: "No shell open", newBash: "New Bash", newZsh: "New Zsh",
      launch: "▶ Open the channel", tools: "Tools (selected box and shell)", connect: "Connection",
      operator: "Operator", cert: "Pinned certificate (SHA-256): ",
      ttydOff: "The shells aren't running: run scripts/ttyd-shells.sh start, then open a shell.",
      pickShell: "Open a shell (Bash or Zsh) or pick \"New Bash\".",
      pathHttp: "NeonFlare folder on this machine (the one that holds index.html):",
      pathBad: "Enter the NeonFlare folder (absolute path).",
      typed: "Command typed into \"{shell}\": press Enter in that shell. Nothing runs without you.",
      delivered: "Box values handed to the shell (masked input, nothing in the history).",
      notDelivered: "Nothing was sent to the shell: it will ask you for the values.",
      typedNone: "Command typed into \"{shell}\": press Enter in that shell.",
      name: "Name", base: "Relay address", token: "Box id (token)",
      pw: "Box password", key: "E2E encryption key", pin: "PIN",
      once: "For this launch (optional, nothing is saved) — otherwise the shell asks for them:",
      onceSaved: "saved", show: "Show / hide",
      short: { pw: "Password", key: "E2E key", pin: "PIN" },
      save: "Save (at my own risk)", saved: "saved", clear: "forget",
      saveBox: "Save the box", cancel: "Cancel",
      secretsWarn: "By default no secret is kept: the shell asks for them as masked input. Ticking \"Save\" keeps them encrypted by the vault; they're handed to the shell as masked input, never typed in clear.",
      vaultOff: "To save secrets, turn the vault on: \"enabled\": true in config/encryption.js, then Settings › Encryption › Turn on encryption. They're never kept in clear. Without the vault, use the \"For this launch\" fields.",
      badBase: "Invalid address (https://host:port).", badToken: "Invalid id (letters, digits, _ and -).",
      confirmDel: "Delete the \"{name}\" box (and its saved secrets)?",
      t: {
        "secure-shell": "Encrypted channel", stream: "Listen", relay: "Relay", stash: "Stash",
        readstash: "Read stash", delete: "Delete the box (server)", count: "Count", health: "Relay health",
        token: "New token (admin)", client: "Standalone client (key)", "check-key": "Check a key",
        "make-key": "Make a key", "make-pin": "Draw a PIN", claviers: "Keyboards",
      },
    },
  };

  /* ---------- utilitaires ---------- */

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function fmt(s, v) { return String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] != null ? v[k] : m)); }
  function shq(v) { return "'" + String(v).replace(/'/g, "'\\''") + "'"; }
  function hex(bytes) { return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""); }
  function b64(s) {
    if (!s) return "-";
    const u = new TextEncoder().encode(String(s));
    let bin = "";
    u.forEach((c) => { bin += String.fromCharCode(c); });
    return btoa(bin);
  }

  // SHA-256 en JS pur : crypto.subtle n'existe pas hors contexte sécurisé
  // (NeonFlare servi en http sur une adresse du réseau local).
  function sha256hex(str) {
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const msg = new TextEncoder().encode(str);
    const len = msg.length;
    const total = ((len + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(total);
    buf.set(msg);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 4, (len * 8) >>> 0);
    dv.setUint32(total - 8, Math.floor(len / 0x20000000));
    const W = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
        const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    return H.map((x) => x.toString(16).padStart(8, "0")).join("");
  }

  // Dossier du plugin sur disque : déduit de l'adresse en file:// (comme le
  // Marketplace), sinon réglage saisi par l'utilisateur (http).
  function pluginDirFromLocation() {
    if (location.protocol !== "file:") return null;
    let path;
    try { path = decodeURIComponent(location.pathname); } catch (e) { return null; }
    const m = path.match(/^(.*)\/project\/[^/]+\.html$/);
    if (!m || !m[1]) return null;
    const win = m[1].match(/^\/([A-Za-z]):(\/.*)?$/); // Windows -> shells WSL2 (scripts/wsl/)
    const root = win ? "/mnt/" + win[1].toLowerCase() + (win[2] || "") : m[1];
    return root + "/plugins/neonrelay";
  }

  const HELP = {
    fr: {
      title: "NeonRelay",
      what: "Ouvre le canal chiffré d'une boîte NeonRelay dans un de vos shells NeonFlare, avec les outils NeonRelay. Le navigateur ne contacte jamais le relais : le TLS (certificat ML-DSA-87 épinglé, ML-KEM) est fait par les outils dans le shell.",
      how: [
        "Ajoutez une boîte (+ Ajouter) : nom, adresse du relais, identifiant (token).",
        "Choisissez la boîte et un shell (Bash ou Zsh), puis « Lancer le canal » ou un outil.",
        "La commande est tapée dans le shell sans être lancée : appuyez sur Entrée dans le shell.",
        "Les secrets non enregistrés vous sont demandés dans le shell, en saisie masquée.",
      ],
      notes: [
        "La ligne tapée ne contient ni secret ni identifiant : rien de sensible dans l'historique du shell, quelle que soit sa configuration.",
        "Secrets enregistrés (option, à vos risques) : chiffrés par le coffre, remis au shell en saisie masquée. Pendant que le canal est ouvert, les outils NeonRelay les ont dans leur environnement (lisible par votre propre compte).",
        "Le shell doit tourner : scripts/ttyd-shells.sh start.",
      ],
    },
    en: {
      title: "NeonRelay",
      what: "Opens a NeonRelay box's encrypted channel in one of your NeonFlare shells, with the NeonRelay tools. The browser never contacts the relay: TLS (pinned ML-DSA-87 certificate, ML-KEM) is done by the tools in the shell.",
      how: [
        "Add a box (+ Add): name, relay address, box id (token).",
        "Pick the box and a shell (Bash or Zsh), then \"Open the channel\" or a tool.",
        "The command is typed into the shell without running: press Enter in the shell.",
        "Secrets you didn't save are asked for in the shell, as masked input.",
      ],
      notes: [
        "The typed line holds no secret and no id: nothing sensitive in the shell history, whatever its settings.",
        "Saved secrets (optional, at your own risk): encrypted by the vault, handed to the shell as masked input. While the channel is open, the NeonRelay tools hold them in their environment (readable by your own account).",
        "The shell must be running: scripts/ttyd-shells.sh start.",
      ],
    },
  };

  /* ---------- panneau ---------- */

  function mount(root, api) {
    const L = api.lang() === "en" ? "en" : "fr";
    const T = STR[L];
    const vaultReady = () => typeof vaultIsSetUp === "function" && vaultIsSetUp();
    let boxes = [];
    let panes = [];
    let watcher = null;
    let paneSeq = 0; // rafraîchissements de la liste des shells (seul le dernier compte)
    let editing = null; // null | {} (nouvelle) | boîte

    root.classList.add("nr-root");

    function loadBoxes() {
      try {
        const raw = api.vault.getItem(BOXES_KEY);
        const v = raw ? JSON.parse(raw) : [];
        boxes = Array.isArray(v) ? v.filter((b) => b && typeof b.id === "string") : [];
      } catch (e) {
        boxes = [];
      }
    }
    function saveBoxes() {
      api.vault.setItem(BOXES_KEY, JSON.stringify(boxes));
    }
    function ui() {
      try { return JSON.parse(api.storage.get("ui") || "{}") || {}; } catch (e) { return {}; }
    }
    function setUi(patch) {
      api.storage.set("ui", JSON.stringify(Object.assign(ui(), patch)));
    }
    function pluginDir() {
      return pluginDirFromLocation() || (ui().dir ? String(ui().dir).replace(/\/+$/, "") + "/plugins/neonrelay" : null);
    }

    // Coffre activé mais verrouillé : formulaire de déverrouillage d'abord.
    if (api.vault.gate(root, () => { root.innerHTML = ""; start(); })) return;
    start();

    function start() {
      loadBoxes();
      render();
      refreshPanes();
    }

    function status(msg, kind) {
      const s = root.querySelector(".nr-status");
      if (!s) return;
      s.textContent = msg || "";
      s.className = "nr-status" + (kind ? " nr-status-" + kind : "");
      s.hidden = !msg;
    }

    function ttydUp() {
      return !!(window.shellSession && typeof window.shellSession.active === "function" && window.shellSession.active());
    }

    function refreshPanes(selectNew) {
      const before = panes.map((p) => p.type + ":" + p.slot);
      const seq = ++paneSeq;
      const done = (list) => {
        // Seule la réponse du DERNIER rafraîchissement compte : une demande plus
        // ancienne (sans réponse, résolue vide après son délai) n'écrase rien.
        if (seq !== paneSeq) return;
        panes = (list || []).filter((p) => p && (p.type === "bash" || p.type === "zsh"));
        let sel = ui().shell;
        if (selectNew) {
          const fresh = panes.find((p) => before.indexOf(p.type + ":" + p.slot) === -1);
          if (fresh) { sel = fresh.type + ":" + fresh.slot; setUi({ shell: sel }); }
        }
        renderShellSelect(sel);
        renderWarn();
      };
      const ask = () => api.shell.requestPaneList().then(done, () => done([]));
      if (typeof api.shell.refreshSession === "function") api.shell.refreshSession(ask);
      else ask();
    }

    function renderWarn() {
      const w = root.querySelector(".nr-warn");
      const go = root.querySelectorAll(".nr-go");
      let msg = "";
      if (!ttydUp()) msg = T.ttydOff;
      else if (!panes.length) msg = T.pickShell;
      if (w) { w.textContent = msg; w.hidden = !msg; }
      go.forEach((b) => { b.disabled = !!msg; });
    }

    function renderShellSelect(sel) {
      const s = root.querySelector(".nr-shell");
      if (!s) return;
      s.innerHTML = "";
      if (!panes.length) s.appendChild(new Option(T.noShell, ""));
      panes.forEach((p) => s.appendChild(new Option(paneName(p), p.type + ":" + p.slot)));
      s.appendChild(new Option(T.newBash, "new:bash"));
      s.appendChild(new Option(T.newZsh, "new:zsh"));
      if (sel && panes.some((p) => p.type + ":" + p.slot === sel)) s.value = sel;
      else if (panes.length) s.value = panes[0].type + ":" + panes[0].slot;
    }

    // Le titre d'un shell contient déjà « Zsh 1 (:7691) » : pas de doublon.
    function paneName(p) { return p.title || api.shell.paneLabel(p); }

    function selectedPane() {
      const v = (root.querySelector(".nr-shell") || {}).value || "";
      return panes.find((p) => p.type + ":" + p.slot === v) || null;
    }
    function selectedBox() {
      const v = (root.querySelector(".nr-box") || {}).value || "";
      return boxes.find((b) => b.id === v) || null;
    }

    function render() {
      root.innerHTML = "";
      const layout = el("div", "nr-layout");
      const left = el("section", "nr-block nr-block-connect");
      left.appendChild(el("h3", "nr-block-title", T.connect));
      const right = el("section", "nr-block nr-block-tools");
      right.appendChild(el("h3", "nr-block-title", T.tools));
      layout.append(left, right);
      root.appendChild(layout);
      const rowBox = el("div", "nr-row");
      rowBox.appendChild(el("label", "nr-label", T.box));
      const boxSel = el("select", "nr-box");
      if (!boxes.length) boxSel.appendChild(new Option("—", ""));
      boxes.forEach((b) => boxSel.appendChild(new Option(b.name + " (" + b.token.slice(0, 6) + "…)", b.id)));
      if (ui().box && boxes.some((b) => b.id === ui().box)) boxSel.value = ui().box;
      boxSel.addEventListener("change", () => setUi({ box: boxSel.value }));
      rowBox.appendChild(boxSel);
      rowBox.appendChild(btn(T.add, "nr-add", () => { editing = {}; renderForm(); }));
      rowBox.appendChild(btn(T.edit, "nr-edit", () => { const b = selectedBox(); if (b) { editing = b; renderForm(); } }));
      rowBox.appendChild(btn(T.del, "nr-del", () => {
        const b = selectedBox();
        if (!b || !confirm(fmt(T.confirmDel, { name: b.name }))) return;
        boxes = boxes.filter((x) => x.id !== b.id);
        saveBoxes();
        render();
        refreshPanes();
      }));
      left.appendChild(rowBox);
      if (!boxes.length) left.appendChild(el("p", "nr-hint", T.noBox));

      const rowShell = el("div", "nr-row");
      rowShell.appendChild(el("label", "nr-label", T.shell));
      const shellSel = el("select", "nr-shell");
      shellSel.addEventListener("change", () => {
        const v = shellSel.value;
        if (v.indexOf("new:") === 0) {
          window.top.postMessage({ type: "shell-request-add", shellType: v.slice(4) }, "*");
          setTimeout(() => refreshPanes(true), 1500);
          return;
        }
        setUi({ shell: v });
      });
      rowShell.appendChild(shellSel);
      rowShell.appendChild(btn("↻", "nr-refresh", () => refreshPanes()));
      left.appendChild(rowShell);

      // Secrets « pour ce lancement » : saisis ici (collage possible), remis au
      // shell par la même remise masquée que les secrets enregistrés, puis
      // effacés. Jamais stockés (ni coffre, ni localStorage).
      const once = el("div", "nr-once");
      once.appendChild(el("p", "nr-hint nr-once-hint", T.once));
      ["pw", "key", "pin"].forEach((k) => {
        const row = el("div", "nr-row");
        row.appendChild(el("label", "nr-label", T.short[k]));
        const i = el("input", "nr-once-" + k);
        i.setAttribute("aria-label", T[k]);
        i.type = "password";
        i.autocomplete = "new-password";
        i.spellcheck = false;
        i.setAttribute("data-lpignore", "true");
        i.setAttribute("data-1p-ignore", "true");
        i.setAttribute("data-bwignore", "true");
        row.appendChild(i);
        const eye = btn("👁", "nr-eye", () => { i.type = i.type === "password" ? "text" : "password"; });
        eye.title = T.show;
        eye.setAttribute("aria-label", T.show);
        row.appendChild(eye);
        once.appendChild(row);
      });
      left.appendChild(once);
      const markSaved = () => {
        const b = selectedBox();
        ["pw", "key", "pin"].forEach((k) => {
          const i = once.querySelector(".nr-once-" + k);
          if (i) i.placeholder = b && b[k] ? "(" + T.onceSaved + ")" : "";
        });
      };
      boxSel.addEventListener("change", markSaved);
      markSaved();

      if (!pluginDirFromLocation()) {
        const rowDir = el("div", "nr-row");
        rowDir.appendChild(el("label", "nr-label nr-label-wide", T.pathHttp));
        const dir = el("input", "nr-dir");
        dir.type = "text";
        dir.value = ui().dir || "";
        dir.placeholder = "/home/…/NeonFlare";
        dir.addEventListener("change", () => setUi({ dir: dir.value.trim() }));
        rowDir.appendChild(dir);
        left.appendChild(rowDir);
      }

      const warn = el("p", "nr-warn");
      warn.hidden = true;
      left.appendChild(warn);
      const go = btn(T.launch, "nr-go nr-launch", () => run("secure-shell"));
      left.appendChild(go);

      const tools = el("div", "nr-tools");
      ["stream", "relay", "stash", "readstash", "count", "delete", "health"].forEach((t) =>
        tools.appendChild(btn(T.t[t], "nr-go nr-tool", () => run(t), t)));
      right.appendChild(tools);
      const op = el("details", "nr-operator");
      op.appendChild(el("summary", null, T.operator));
      const opTools = el("div", "nr-tools");
      ["token", "client", "check-key", "make-key", "make-pin", "claviers"].forEach((t) =>
        opTools.appendChild(btn(T.t[t], "nr-go nr-tool", () => run(t), t)));
      op.appendChild(opTools);
      right.appendChild(op);

      const st = el("p", "nr-status");
      st.setAttribute("role", "status");
      st.hidden = true;
      root.appendChild(st);
      const form = el("div", "nr-form nr-block");
      form.hidden = true;
      root.appendChild(form);
      root.appendChild(el("p", "nr-cert", T.cert + CERT_SHA256));
      renderShellSelect(ui().shell);
      renderWarn();
    }

    function btn(label, cls, onClick, tool) {
      const b = el("button", "dash-btn " + cls, label);
      b.type = "button";
      if (tool) b.setAttribute("data-tool", tool);
      b.addEventListener("click", onClick);
      return b;
    }

    /* ---------- formulaire d'une boîte ---------- */

    function renderForm() {
      const f = root.querySelector(".nr-form");
      if (!f) return;
      f.innerHTML = "";
      f.hidden = false;
      const b = editing || {};
      const canSave = vaultReady();
      const field = (label, cls, value, type) => {
        const row = el("label", "nr-field");
        row.appendChild(el("span", null, label));
        const i = el("input", cls);
        i.type = type || "text";
        i.value = value || "";
        i.autocomplete = type === "password" ? "new-password" : "off";
        i.spellcheck = false;
        row.appendChild(i);
        f.appendChild(row);
        return i;
      };
      const iName = field(T.name, "nr-f-name", b.name);
      const iBase = field(T.base, "nr-f-base", b.base || DEFAULT_BASE);
      const iToken = field(T.token, "nr-f-token", b.token);
      f.appendChild(el("p", "nr-hint", T.secretsWarn));
      if (!canSave) f.appendChild(el("p", "nr-hint nr-hint-warn", T.vaultOff));
      const secrets = {};
      ["pw", "key", "pin"].forEach((k) => {
        const row = el("div", "nr-secret");
        const i = field(T[k], "nr-f-" + k, "", "password");
        row.appendChild(i.parentNode);
        const lab = el("label", "nr-save");
        const c = el("input", "nr-f-save-" + k);
        c.type = "checkbox";
        c.disabled = !canSave;
        c.checked = canSave && !!b[k];
        lab.append(c, document.createTextNode(" " + T.save));
        row.appendChild(lab);
        if (b[k]) {
          row.appendChild(el("span", "nr-saved", "(" + T.saved + ")"));
          i.placeholder = "••••••";
        }
        f.appendChild(row);
        secrets[k] = { input: i, check: c };
      });
      const err = el("p", "nr-status nr-status-error");
      err.hidden = true;
      f.appendChild(err);
      const actions = el("div", "nr-row");
      actions.appendChild(btn(T.saveBox, "nr-f-ok", () => {
        const name = iName.value.trim() || iToken.value.trim().slice(0, 8);
        const base = iBase.value.trim();
        const token = iToken.value.trim();
        if (!BASE_RE.test(base)) { err.textContent = T.badBase; err.hidden = false; return; }
        if (!TOKEN_RE.test(token)) { err.textContent = T.badToken; err.hidden = false; return; }
        const box = { id: b.id || "b" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), name: name.slice(0, 60), base, token };
        Object.keys(secrets).forEach((k) => {
          const s = secrets[k];
          if (!canSave || !s.check.checked) return;            // décoché = rien gardé
          const v = s.input.value;
          if (v) box[k] = v;
          else if (b[k]) box[k] = b[k];                         // champ vide = garder l'ancien
        });
        const i = boxes.findIndex((x) => x.id === box.id);
        if (i === -1) boxes.push(box);
        else boxes[i] = box;
        saveBoxes();
        setUi({ box: box.id });
        editing = null;
        render();
        refreshPanes();
      }));
      actions.appendChild(btn(T.cancel, "nr-f-cancel", () => { editing = null; f.hidden = true; f.innerHTML = ""; }));
      f.appendChild(actions);
    }

    /* ---------- lancer un outil ---------- */

    function run(tool) {
      const need = TOOLS[tool];
      if (!need) return;
      const pane = selectedPane();
      const dir = pluginDir();
      if (!ttydUp() || !pane) { renderWarn(); return; }
      if (!dir || !/^\/[^\x00-\x1f\x7f]*$/.test(dir)) { status(T.pathBad, "error"); return; }
      const box = selectedBox();
      if (need === "box" && !box) { status(T.noBox, "warn"); return; }
      const nonceBytes = new Uint8Array(16);
      crypto.getRandomValues(nonceBytes);
      const nonce = hex(nonceBytes);
      const command = " bash " + shq(dir + "/tools/nf-open.sh") + " " + tool + " " + nonce;
      const label = paneName(pane);
      if (watcher) { watcher.cancel(); watcher = null; }

      const type = () => window.top.postMessage(
        { type: "shell-copy-request", shellType: pane.type, slot: pane.slot, text: command, forceNew: false }, "*");

      if (need === "none") {
        type();
        status(fmt(T.typedNone, { shell: label }), "info");
        return;
      }
      // Valeurs remises seulement après le signal ; rien d'autre n'est jamais envoyé.
      const base = box ? box.base : DEFAULT_BASE;
      // Saisi « pour ce lancement » > enregistré > rien (le shell demandera).
      const typed = (k) => {
        const i = root.querySelector(".nr-once-" + k);
        return i && i.value ? i.value : "";
      };
      const fields = need === "box"
        ? [base, box.token, typed("pw") || box.pw || "", typed("key") || box.key || "", typed("pin") || box.pin || ""]
        : [base, "", "", "", ""];
      const line = "NFR1 " + fields.map(b64).join(" ");
      // Les valeurs vivent désormais dans `line` seulement : champs vidés et remasqués.
      root.querySelectorAll(".nr-once input").forEach((i) => { i.value = ""; i.type = "password"; });
      const w = api.shell.deliverOnMarker(api.shell.portFor(pane), "NFR-READY:" + sha256hex(nonce), line, { timeoutMs: 300000 });
      watcher = w;
      w.promise.then((r) => {
        if (watcher !== w) return;
        watcher = null;
        status(r && r.delivered ? T.delivered : T.notDelivered, r && r.delivered ? "ok" : "warn");
      }, () => {
        if (watcher !== w) return;
        watcher = null;
        status(T.notDelivered, "warn");
      });
      // À l'écoute AVANT que la ligne n'arrive dans le shell.
      setTimeout(() => {
        type();
        status(fmt(T.typed, { shell: label }), "info");
      }, 700);
    }
  }

  NeonFlarePlugins.register({
    id: "neonrelay",
    panels: [{ key: "panelNeonRelay", help: HELP, mount: mount }],
  });
  // Pour les tests (NR.c / NR.d) : fonctions pures seulement.
  window.NeonRelayPlugin = Object.freeze({ sha256hex: sha256hex, pluginDirFromLocation: pluginDirFromLocation, CERT_SHA256: CERT_SHA256 });
})();
