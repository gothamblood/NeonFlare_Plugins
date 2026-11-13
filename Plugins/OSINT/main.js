/* Plugin OSINT pour NeonFlare -- point d'entrée (spec/plugins/PLAN.md § 5).

   Au chargement : uniquement NeonFlarePlugins.register(). Les autres fichiers
   (osint-common, -dorks, -shodan, -crtsh, -wayback, -collect) ne font que
   définir des fonctions dans window.NeonFlareOsint ; tout est construit dans
   mount(), une fois le cœur chargé.

   Mêmes identifiants qu'avant le plugin (panneaux, clés de stockage, tableau
   « seed-osint ») : les données et réglages existants sont repris tels quels.
   Aucune requête réseau avant un clic de l'utilisateur (Loi 25). */
(function () {
  "use strict";
  const NS = window.NeonFlareOsint;

  // Crée le conteneur attendu par chaque panneau (ancien HTML en dur).
  function box(el, id) {
    const d = document.createElement("div");
    d.className = "dorks-panel";
    d.id = id;
    el.appendChild(d);
    return d;
  }

  function panel(key, id, run) {
    return {
      key: key,
      help: HELP[key],
      mount(el, api) {
        NS.kit();
        run(box(el, id), api);
      },
    };
  }

  const HELP = {
  panelDorks: {
    fr: {
      title: "Google Dorks",
      what: "Construit des recherches avancées (dorks) sur Google, Bing, DuckDuckGo ou le code GitHub, pour trouver ce qu'une cible expose publiquement.",
      how: [
        "Saisissez la cible : un domaine (abc.com) ou un nom (abc, abc*) avec les extensions à cocher.",
        "« + Ajouter un critère » : catégorie ▾, élément ▾, puis cochez les valeurs (ou ajoutez les vôtres).",
        "Vérifiez l'aperçu, puis Copier ou ↗ ouvrir dans le moteur choisi.",
      ],
      notes: [
        "La cible est partagée par tous les panneaux OSINT : la changer ici la change partout.",
        "Rien n'est envoyé avant votre clic ; chaque ouverture est notée dans le System log.",
        "N'utilisez l'OSINT que sur une cible que vous êtes autorisé à étudier.",
      ],
    },
    en: {
      title: "Google Dorks",
      what: "Builds advanced searches (dorks) for Google, Bing, DuckDuckGo or GitHub code, to find what a target exposes publicly.",
      how: [
        "Enter the target: a domain (abc.com) or a name (abc, abc*) with the extensions to tick.",
        "\"+ Add a criterion\": category ▾, element ▾, then tick values (or add your own).",
        "Check the preview, then Copy or ↗ open in the chosen engine.",
      ],
      notes: [
        "The target is shared by every OSINT panel: changing it here changes it everywhere.",
        "Nothing is sent before you click; each opening is logged in the System log.",
        "Only run OSINT against a target you are authorised to study.",
      ],
    },
  },
  panelShodan: {
    fr: {
      title: "Shodan",
      what: "Construit des recherches Shodan : les machines et services exposés sur Internet (ports, bannières, logiciels, certificats).",
      how: [
        "La cible partagée remplit hostname: (sous-domaines inclus).",
        "Ajoutez des critères (port, produit, pays, titre HTTP…) ; plusieurs valeurs d'un critère = OU, critères entre eux = ET.",
        "Copier, ou ↗ Shodan pour lancer la recherche.",
      ],
      notes: [
        "La plupart des filtres demandent un compte Shodan gratuit ; vuln: demande une offre payante.",
        "Shodan n'a pas de joker de domaine : la case ✱ est ignorée ici.",
      ],
    },
    en: {
      title: "Shodan",
      what: "Builds Shodan searches: machines and services exposed on the Internet (ports, banners, software, certificates).",
      how: [
        "The shared target fills hostname: (subdomains included).",
        "Add criteria (port, product, country, HTTP title…); several values of one criterion = OR, criteria together = AND.",
        "Copy, or ↗ Shodan to run the search.",
      ],
      notes: [
        "Most filters need a free Shodan account; vuln: needs a paid plan.",
        "Shodan has no domain wildcard: the ✱ box is ignored here.",
      ],
    },
  },
  panelCrtsh: {
    fr: {
      title: "Certificats (crt.sh)",
      what: "Interroge les journaux de transparence des certificats : la meilleure source passive de sous-domaines.",
      how: [
        "La cible partagée donne une recherche par variante de domaine (abc.com, abc.ca…).",
        "Options : inclure les sous-domaines, exclure les expirés, dédoublonner, format HTML ou JSON.",
        "↗ ouvre crt.sh ; ⧉ copie une commande curl | jq à lancer dans un shell.",
      ],
      notes: [
        "Seul panneau où ✱ est un vrai joker (abc.%) : ces recherches sont lentes et peuvent expirer.",
      ],
    },
    en: {
      title: "Certificates (crt.sh)",
      what: "Queries Certificate Transparency logs: the best passive source of subdomains.",
      how: [
        "The shared target gives one search per domain variant (abc.com, abc.ca…).",
        "Options: include subdomains, exclude expired, deduplicate, HTML or JSON output.",
        "↗ opens crt.sh; ⧉ copies a curl | jq command to run in a shell.",
      ],
      notes: [
        "The only panel where ✱ is a real wildcard (abc.%): such searches are slow and may time out.",
      ],
    },
  },
  panelWayback: {
    fr: {
      title: "Wayback Machine",
      what: "Toutes les URL que l'Internet Archive a capturées pour la cible : anciennes pages, points d'accès retirés, fichiers oubliés.",
      how: [
        "Choisissez les options : sous-domaines, réponses 200 seulement, une ligne par URL, années, limite.",
        "Cochez des types de fichiers (.sql, .env, .bak…) pour ne garder que ceux-là.",
        "↗ URL : la liste brute ; ↗ Wayback : l'interface de l'archive ; ⧉ : la même liste en commande curl.",
      ],
      notes: ["L'archive n'a pas de joker de domaine : la case ✱ est ignorée ici."],
    },
    en: {
      title: "Wayback Machine",
      what: "Every URL the Internet Archive captured for the target: old pages, removed endpoints, forgotten files.",
      how: [
        "Pick options: subdomains, 200 responses only, one line per URL, years, limit.",
        "Tick file types (.sql, .env, .bak…) to keep only those.",
        "↗ URL: the raw list; ↗ Wayback: the archive's own UI; ⧉: the same list as a curl command.",
      ],
      notes: ["The archive has no domain wildcard: the ✱ box is ignored here."],
    },
  },
  panelOsintAssets: {
    fr: {
      title: "Actifs découverts",
      what: "Va chercher les résultats OSINT pour la cible partagée et les range dans un inventaire unique, sans doublons : sous-domaines, URL archivées, IP, enregistrements DNS, registraire (RDAP), ASN, ports ouverts et CVE connues.",
      how: [
        "Saisissez la cible (ici ou dans un autre panneau OSINT), cochez « J'ai l'autorisation d'étudier cette cible » ; mandat et date de fin sont facultatifs.",
        "Lancez une source (▶) ou « ▶ Tout (navigateur) » : crt.sh, DNS, RDAP, ASN puis InternetDB. ASN et InternetDB partent des IP trouvées : lancez DNS avant.",
        "« Site de la cible ⚠ actif » : robots.txt + security.txt lit ces deux fichiers sur le site lui-même (chemins cachés, plans de site, contact sécurité) -- c'est la seule source qui touche la cible, à réserver aux mandats qui le permettent.",
        "Les sources ⌨ (Wayback, urlscan, subfinder, amass, robots.txt + security.txt) passent par le shell Bash/Zsh choisi : ouvrez-en un avec « + SHELL », ⟳ rafraîchit la liste, ⧉ copie les commandes pour les lancer vous-même.",
        "« Liens ↗ » : Shodan, VirusTotal, Censys, SecurityTrails, BuiltWith, archive.today, grep.app, DNSDumpster et Have I Been Pwned s'ouvrent dans un nouvel onglet, avec votre propre compte (choisissez le domaine si la cible en a plusieurs). Chaque ligne de l'inventaire a aussi ses liens : AbuseIPDB, GreyNoise, Shodan et BGP pour une IP, BGP pour un ASN, NVD pour une CVE, VirusTotal pour un sous-domaine. NeonFlare n'en lit rien et ne garde rien.",
        "Courriels (Hunter.io, Phonebook.cz, « Vérifier une adresse » → Have I Been Pwned, Epieos) : seulement si le mandat couvre l'ingénierie sociale. L'adresse doit appartenir au domaine de la cible ; elle sert à construire le lien et n'est enregistrée nulle part.",
        "Triez avec les filtres et le statut (Nouveau / Retenu / Écarté) ; → GRC ajoute au registre d'actifs, → Finding ouvre un finding pré-rempli, ◎ fait d'un sous-domaine la nouvelle cible.",
        "« Dossier de la cible » : notes horodatées et export complet (autorisation, périmètre, notes, inventaire) ; 🗑 purge la cible.",
      ],
      notes: [
        "Rien ne part sans votre clic. Une commande ⌨ s'affiche brièvement dans le terminal choisi, puis l'écran est nettoyé.",
        "Collecte passive sauf « Site de la cible ⚠ actif » : aucun lien n'ouvre la cible elle-même (↗ mène à l'archive). Pas de renseignement personnel : ni courriels, ni titulaire du domaine.",
        "Passé la date de fin du mandat, la purge de la cible est proposée.",
        "L'inventaire est chiffré par le coffre s'il est configuré.",
      ],
    },
    en: {
      title: "Discovered assets",
      what: "Fetches OSINT results for the shared target into a single, deduplicated inventory: subdomains, archived URLs, IPs, DNS records, registrar (RDAP), ASNs, open ports and known CVEs.",
      how: [
        "Enter the target (here or in another OSINT panel), tick \"I am authorised to study this target\"; engagement and end date are optional.",
        "Run a source (▶) or \"▶ All (browser)\": crt.sh, DNS, RDAP, ASN then InternetDB. ASN and InternetDB start from the IPs found: run DNS first.",
        "\"Target's site ⚠ active\": robots.txt + security.txt reads these two files on the site itself (hidden paths, sitemaps, security contact) -- the only source that touches the target, keep it for engagements that allow it.",
        "⌨ sources (Wayback, urlscan, subfinder, amass, robots.txt + security.txt) go through the chosen Bash/Zsh shell: open one with \"+ SHELL\", ⟳ refreshes the list, ⧉ copies the commands to run them yourself.",
        "\"Links ↗\": Shodan, VirusTotal, Censys, SecurityTrails, BuiltWith, archive.today, grep.app, DNSDumpster and Have I Been Pwned open in a new tab, with your own account (pick the domain when the target has several). Each inventory row has its own links too: AbuseIPDB, GreyNoise, Shodan and BGP for an IP, BGP for an ASN, NVD for a CVE, VirusTotal for a subdomain. NeonFlare reads and keeps nothing from them.",
        "E-mail (Hunter.io, Phonebook.cz, \"Check an address\" → Have I Been Pwned, Epieos): only when the engagement covers social engineering. The address must belong to the target's domain; it only builds the link and is stored nowhere.",
        "Sort with the filters and the status (New / Kept / Dismissed); → GRC adds to the asset register, → Finding opens a pre-filled finding, ◎ makes a subdomain the new target.",
        "\"Target file\": timestamped notes and full export (authorisation, scope, notes, inventory); 🗑 purges the target.",
      ],
      notes: [
        "Nothing is sent before you click. A ⌨ command briefly shows in the chosen terminal, then the screen is cleared.",
        "Passive collection except \"Target's site ⚠ active\": no link opens the target itself (↗ goes to the archive). No personal data: no e-mail addresses, no domain registrant.",
        "Once the engagement end date has passed, purging the target is offered.",
        "The inventory is encrypted by the vault when it is set up.",
      ],
    },
  },
  };

  NeonFlarePlugins.register({
    id: "osint",
    i18n: {
      "osint.needTarget": {
        fr: "Saisis une cible (domaine ou nom + extensions) pour générer les recherches.",
        en: "Enter a target (domain, or name + extensions) to build the searches."
      },
      "dorks.wildIgnored": { fr: "ignoré ici", en: "ignored here" },
      "crtsh.slow": { fr: "lent", en: "slow" },
      "crtsh.subdomains": { fr: "Sous-domaines (%.)", en: "Subdomains (%.)" },
      "crtsh.excludeExpired": { fr: "Exclure les expirés", en: "Exclude expired" },
      "crtsh.dedupe": { fr: "Dédupliquer (pré-certificats)", en: "Deduplicate (precertificates)" },
      "crtsh.copyCurl": { fr: "Copier la commande curl | jq (liste des sous-domaines)", en: "Copy the curl | jq command (subdomain list)" },
      "wayback.subdomains": { fr: "Sous-domaines inclus", en: "Include subdomains" },
      "wayback.ok200": { fr: "Réponses 200 seulement", en: "200 responses only" },
      "wayback.collapse": { fr: "Une ligne par URL", en: "One line per URL" },
      "wayback.years": { fr: "Années", en: "Years" },
      "wayback.from": { fr: "de", en: "from" },
      "wayback.to": { fr: "à", en: "to" },
      "wayback.limit": { fr: "Limite", en: "Limit" },
      "wayback.exts": { fr: "Types de fichiers (aucun = tout)", en: "File types (none = all)" },
      "wayback.addExt": { fr: "autre…", en: "other…" },
      "wayback.copyCurl": { fr: "Copier la commande curl (liste d'URL)", en: "Copy the curl command (URL list)" },
      "wayback.urls": { fr: "URL", en: "URLs" },
      "wayback.urlsTitle": { fr: "Liste brute des URL archivées (API CDX)", en: "Raw list of archived URLs (CDX API)" },
      "dorks.copy": { fr: "Copier la requête", en: "Copy query" },
      "dorks.needTarget": { fr: "Saisir d'abord un domaine cible", en: "Enter a target domain first" },
      "dorks.targetPlaceholder": { fr: "Domaine (abc.com) ou nom (abc, abc*)", en: "Domain (abc.com) or name (abc, abc*)" },
      "dorks.copyShort": { fr: "Copier", en: "Copy" },
      "dorks.copied": { fr: "Copié", en: "Copied" },
      "dorks.addClause": { fr: "Ajouter un critère", en: "Add a criterion" },
      "dorks.removeClause": { fr: "Retirer ce critère", en: "Remove this criterion" },
      "dorks.reset": { fr: "Réinitialiser", en: "Reset" },
      "dorks.addValue": { fr: "Ajouter cette valeur", en: "Add this value" },
      "dorks.addValuePlaceholder": { fr: "autre valeur…", en: "other value…" },
      "dorks.removeValue": { fr: "Retirer cette valeur", en: "Remove this value" },
      "dorks.tlds": { fr: "Extensions", en: "Extensions" },
      "dorks.addTldPlaceholder": { fr: "autre (co.uk)…", en: "other (co.uk)…" },
      "dorks.wild": { fr: "joker", en: "wildcard" },
      "dorks.wildTitle": {
        fr: "Les moteurs n'ont pas de vrai joker de domaine : chaque panneau indique ce que ✱ devient.",
        en: "Engines have no real domain wildcard: each panel says what ✱ turns into."
      },
      "dorks.needTld": { fr: "Cocher au moins une extension ou le joker ✱", en: "Tick at least one extension or the ✱ wildcard" },
      "dorks.implicitScope": {
        fr: "Cible ajoutée automatiquement (aucun critère n'utilise <domain>).",
        en: "Target added automatically (no criterion uses <domain>)."
      },
      "dorks.emptyQuery": { fr: "Ajoute un critère pour construire la requête", en: "Add a criterion to build the query" },
    },
    panels: [
      panel("panelDorks", "dorksPanel", (root) => NS.dorks(root)),
      panel("panelShodan", "shodanPanel", (root) => NS.shodan(root)),
      panel("panelCrtsh", "crtshPanel", (root) => NS.crtsh(root)),
      panel("panelWayback", "waybackPanel", (root) => NS.wayback(root)),
      panel("panelOsintAssets", "osintAssetsPanel", (root, api) => NS.collect(root, api)),
    ],
  });
})();
