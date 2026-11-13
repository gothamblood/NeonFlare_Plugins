/* Shodan panel (OSINT dashboard) -- same criteria builder as Google Dorks
   (osint-common.js), with Shodan's own filter syntax:

     filter:value                  hostname:abc.com
     several values = comma list   port:22,3389   (Shodan reads a comma
                                   as OR inside one filter)
     "…" around a value with spaces  http.title:"Dashboard [Jenkins]"
     -filter:value = exclusion     -port:80
     criteria are AND'ed (space)

   The shared target fills hostname: (Shodan's hostname filter already
   matches subdomains). Shodan has no domain wildcard, so the ✱ box is
   ignored here (and says so). Most filters need a (free) Shodan login,
   vuln: needs a paid plan. */

window.NeonFlareOsint = window.NeonFlareOsint || {};
window.NeonFlareOsint.shodan = function (root) {
  if (!root || !window.OsintKit) return;
  const K = window.OsintKit;

  const ENGINES = { shodan: { name: "Shodan", url: "https://www.shodan.io/search?query=" } };

  const CATALOG = [
    { id: "target", title: { fr: "Cible", en: "Target" }, items: [
      { id: "hostname", label: { fr: "Nom d'hôte (hostname:)", en: "Hostname (hostname:)" }, op: "hostname", values: ["<domain>"] },
      { id: "certcn", label: { fr: "Certificat — CN", en: "Certificate — CN" }, op: "ssl.cert.subject.cn", values: ["<domain>"] },
      { id: "ssl", label: { fr: "Certificat — tout champ (ssl:)", en: "Certificate — any field (ssl:)" }, op: "ssl", values: ["<domain>"] },
      { id: "org", label: { fr: "Organisation (org:)", en: "Organization (org:)" }, op: "org", values: [] },
      { id: "net", label: { fr: "Plage IP (net:)", en: "IP range (net:)" }, op: "net", values: [] },
      { id: "asn", label: { fr: "ASN (asn:)", en: "ASN (asn:)" }, op: "asn", values: [] },
    ] },
    { id: "ports", title: { fr: "Ports / services", en: "Ports / services" }, items: [
      { id: "remote", label: { fr: "Accès distant", en: "Remote access" }, op: "port", values: ["22", "23", "3389", "5900"] },
      { id: "db", label: { fr: "Bases de données", en: "Databases" }, op: "port", values: ["3306", "5432", "1433", "1521", "6379", "9200", "27017"] },
      { id: "web", label: { fr: "Web", en: "Web" }, op: "port", values: ["80", "443", "8080", "8443", "8000"] },
      { id: "files", label: { fr: "Partage de fichiers", en: "File sharing" }, op: "port", values: ["21", "445", "2049", "873"] },
      { id: "ics", label: { fr: "Industriel (ICS)", en: "Industrial (ICS)" }, op: "port", values: ["502", "102", "20000", "47808"] },
    ] },
    { id: "software", title: { fr: "Logiciels", en: "Software" }, items: [
      { id: "product", label: { fr: "Produit (product:)", en: "Product (product:)" }, op: "product", values: ["Apache httpd", "nginx", "Microsoft IIS httpd", "OpenSSH"] },
      { id: "component", label: { fr: "Composant web (http.component:)", en: "Web component (http.component:)" }, op: "http.component", values: ["WordPress", "Drupal", "Joomla"] },
      { id: "version", label: { fr: "Version (version:)", en: "Version (version:)" }, op: "version", values: [] },
    ] },
    { id: "exposure", title: { fr: "Exposition", en: "Exposure" }, items: [
      { id: "panels", label: { fr: "Panneaux d'admin", en: "Admin panels" }, op: "http.title", values: ["Grafana", "Kibana", "Dashboard [Jenkins]", "phpMyAdmin", "Outlook"] },
      { id: "dirlist", label: { fr: "Répertoires ouverts", en: "Open directories" }, op: "http.title", values: ["Index of /"] },
      { id: "screenshot", label: { fr: "Avec capture d'écran", en: "Has a screenshot" }, op: "has_screenshot", values: ["true"] },
      { id: "vuln", label: { fr: "CVE (vuln:, plan payant)", en: "CVE (vuln:, paid plan)" }, op: "vuln", values: [] },
    ] },
    { id: "geo", title: { fr: "Géographie", en: "Geography" }, items: [
      { id: "country", label: { fr: "Pays (country:)", en: "Country (country:)" }, op: "country", values: ["CA", "US"] },
      { id: "city", label: { fr: "Ville (city:)", en: "City (city:)" }, op: "city", values: [] },
    ] },
    { id: "fingerprint", title: { fr: "Empreinte", en: "Fingerprint" }, items: [
      { id: "favicon", label: { fr: "Hash du favicon", en: "Favicon hash" }, op: "http.favicon.hash", values: [] },
      { id: "html", label: { fr: "Contenu HTML (http.html:)", en: "HTML content (http.html:)" }, op: "http.html", values: [] },
      { id: "jarm", label: { fr: "JARM TLS (ssl.jarm:)", en: "TLS JARM (ssl.jarm:)" }, op: "ssl.jarm", values: [] },
    ] },
    { id: "exclude", title: { fr: "Exclusions", en: "Exclusions" }, items: [
      { id: "port", label: { fr: "Exclure des ports", en: "Exclude ports" }, op: "-port", values: [] },
      { id: "product", label: { fr: "Exclure des produits", en: "Exclude products" }, op: "-product", values: [] },
      { id: "hostname", label: { fr: "Exclure des hôtes", en: "Exclude hosts" }, op: "-hostname", values: [] },
    ] },
    { id: "free", title: { fr: "Libre", en: "Free" }, items: [
      { id: "word", label: { fr: "Mot-clé (bannière)", en: "Keyword (banner)" }, op: "word", values: [] },
    ] },
  ];

  const dialect = {
    wild: () => [], // no domain wildcard on Shodan
    group(op, items) {
      const vals = items.map((it) => it.v);
      if (vals.length === 0) return "";
      if (op === "word") return vals.map(K.quoteIfNeeded).join(" ");
      // An exclusion is written once per value: -port:22 -port:80.
      if (op.charAt(0) === "-") return vals.map((v) => op + ":" + K.quoteIfNeeded(v)).join(" ");
      return op + ":" + vals.map(K.quoteIfNeeded).join(",");
    },
  };

  K.createBuilder({
    root,
    stateKey: "/dashboard.html/shodan",
    logSource: "shodan",
    catalog: CATALOG,
    engines: ENGINES,
    defaultClauses: () => [["target", "hostname"]],
    newClause: ["ports", "remote"],
    implicitScope: () => ["target", "hostname"],
    dialect,
    wildNote: () => null,
    collapsedTarget: true,
  });
};
