/* Google Dorks panel (OSINT dashboard) -- criteria builder for Google /
   Bing / DuckDuckGo / GitHub code search. The builder, the shared target
   and the checkbox UI live in osint-common.js; this file is the Google
   catalogue and its syntax ("dialect"):

     values of one criterion are OR'ed, criteria AND'ed (space):
       site:x.com (filetype:env OR filetype:ini) inurl:admin
     " OR " rather than "|" (Bing and DuckDuckGo don't read "|").
     ✱ wildcard: engines have no wildcard inside site:, so it becomes
     inurl:<name> for site: values, nothing for -site:, and the bare name
     elsewhere ("abc" for a mention).

   Items flagged `mention: true` search OTHER sites (paste sites, Postman,
   LinkedIn…): when the target is added automatically, it is then added
   as a mention ("abc.com") rather than site:abc.com, which would
   contradict site:pastebin.com. Same with the GitHub engine. */

window.NeonFlareOsint = window.NeonFlareOsint || {};
window.NeonFlareOsint.dorks = function (root) {
  if (!root || !window.OsintKit) return;
  const K = window.OsintKit;

  const ENGINES = {
    google: { name: "Google", url: "https://www.google.com/search?q=" },
    bing: { name: "Bing", url: "https://www.bing.com/search?q=" },
    duckduckgo: { name: "DuckDuckGo", url: "https://duckduckgo.com/?q=" },
    github: { name: "GitHub (code)", url: "https://github.com/search?type=code&q=" },
  };

  /* op = how each value is written:
       site / filetype / path / after / before -> op:value
       inurl / intitle / intext                -> op:value ("…" if needed)
       exact    -> "value"
       exclude  -> -value          (-"two words" when needed)
       nosite   -> -site:value
       word     -> value as typed (may hold several operators) */
  const CATALOG = [
    { id: "target", title: { fr: "Cible", en: "Target" }, items: [
      { id: "site", label: { fr: "Sur le domaine (site:)", en: "On the domain (site:)" }, op: "site", values: ["<domain>"] },
      { id: "subdomains", label: { fr: "Sous-domaines", en: "Subdomains" }, op: "site", values: ["*.<domain>"] },
      { id: "nosite", label: { fr: "Exclure un hôte (-site:)", en: "Exclude a host (-site:)" }, op: "nosite", values: ["www.<domain>"] },
      { id: "mention", label: { fr: "Mention du domaine", en: "Domain mention" }, op: "exact", values: ["<domain>"] },
      { id: "email", label: { fr: "Adresses courriel", en: "Email addresses" }, op: "exact", values: ["@<domain>"] },
    ] },
    { id: "files", title: { fr: "Fichiers sensibles", en: "Sensitive files" }, items: [
      { id: "config", label: { fr: "Configuration / secrets", en: "Config / secrets" }, op: "filetype", values: ["env", "ini", "conf", "cfg", "yml"] },
      { id: "db", label: { fr: "Bases de données", en: "Databases" }, op: "filetype", values: ["sql", "db", "sqlite", "mdb"] },
      { id: "backup", label: { fr: "Sauvegardes", en: "Backups" }, op: "filetype", values: ["bak", "old", "backup", "zip", "tar"] },
      { id: "logs", label: { fr: "Journaux", en: "Logs" }, op: "filetype", values: ["log"] },
      { id: "keys", label: { fr: "Clés / certificats", en: "Keys / certificates" }, op: "filetype", values: ["pem", "key", "ppk", "p12"] },
      { id: "access", label: { fr: "Accès / captures", en: "Access / captures" }, op: "filetype", values: ["ovpn", "rdp", "kdbx", "pcap"] },
    ] },
    { id: "secrets", title: { fr: "Secrets dans les fichiers", en: "Secrets inside files" }, items: [
      { id: "passwords", label: { fr: "Mots de passe", en: "Passwords" }, op: "word",
        values: ["filetype:env \"DB_PASSWORD\"", "filetype:sql \"INSERT INTO\" \"password\"", "filetype:log \"password\"", "filetype:xml \"password\""] },
      { id: "apikeys", label: { fr: "Clés d'API", en: "API keys" }, op: "intext", values: ["api_key", "apikey", "client_secret", "AKIA"] },
      { id: "privkeys", label: { fr: "Clés privées", en: "Private keys" }, op: "intext", values: ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"] },
    ] },
    { id: "docs", title: { fr: "Documents", en: "Documents" }, items: [
      { id: "office", label: { fr: "Bureautique", en: "Office files" }, op: "filetype", values: ["pdf", "docx", "xlsx", "pptx", "doc", "xls"] },
      { id: "confidential", label: { fr: "Mentions confidentielles", en: "Confidential markings" }, op: "intext", values: ["confidentiel", "confidential", "internal use only"] },
    ] },
    { id: "surface", title: { fr: "Surface exposée", en: "Exposed surface" }, items: [
      { id: "dirlist", label: { fr: "Répertoires ouverts", en: "Open directories" }, op: "intitle", values: ["index of"] },
      { id: "login", label: { fr: "Connexion / admin", en: "Login / admin" }, op: "inurl", values: ["login", "signin", "admin", "portal"] },
      { id: "errors", label: { fr: "Messages d'erreur", en: "Error messages" }, op: "intext", values: ["sql syntax", "Warning: mysql", "Fatal error", "stack trace"] },
      { id: "phpinfo", label: { fr: "phpinfo()", en: "phpinfo()" }, op: "intitle", values: ["phpinfo"] },
      { id: "params", label: { fr: "Paramètres d'URL", en: "URL parameters" }, op: "inurl", values: ["?id=", "?page=", "?redirect=", "?url="] },
    ] },
    { id: "services", title: { fr: "Services exposés", en: "Exposed services" }, items: [
      { id: "monitoring", label: { fr: "Supervision", en: "Monitoring" }, op: "intitle", values: ["Grafana", "Kibana", "Prometheus Time Series", "Zabbix"] },
      { id: "ci", label: { fr: "CI / dev", en: "CI / dev" }, op: "intitle", values: ["Dashboard [Jenkins]", "Sign in · GitLab", "SonarQube", "Swagger UI"] },
      { id: "dbadmin", label: { fr: "Admin de BD / serveur", en: "DB / server admin" }, op: "intitle", values: ["phpMyAdmin", "Adminer", "Webmin"] },
      { id: "remote", label: { fr: "Accès distant", en: "Remote access" }, op: "intitle", values: ["Outlook Web App", "RD Web Access", "SSL VPN", "Citrix Gateway"] },
    ] },
    { id: "devfiles", title: { fr: "Fichiers de dev", en: "Dev files" }, items: [
      { id: "vcs", label: { fr: "Gestion de versions", en: "Version control" }, op: "inurl", values: ["/.git", "/.svn", "/.hg", ".DS_Store"] },
      { id: "manifests", label: { fr: "Manifestes / config web", en: "Manifests / web config" }, op: "inurl", values: ["composer.json", "package.json", "docker-compose.yml", "web.config", ".htaccess"] },
      { id: "robots", label: { fr: "robots.txt / sitemap", en: "robots.txt / sitemap" }, op: "inurl", values: ["robots.txt", "sitemap.xml"] },
    ] },
    { id: "infra", title: { fr: "Infrastructure", en: "Infrastructure" }, items: [
      { id: "envs", label: { fr: "Environnements dev / test", en: "Dev / test environments" }, op: "inurl", values: ["dev", "staging", "test", "uat", "preprod"] },
      { id: "api", label: { fr: "API / documentation", en: "API / documentation" }, op: "inurl", values: ["api", "swagger", "graphql", "openapi"] },
      { id: "wordpress", label: { fr: "WordPress", en: "WordPress" }, op: "inurl", values: ["wp-content", "wp-admin", "wp-json"] },
      { id: "securitytxt", label: { fr: "security.txt", en: "security.txt" }, op: "inurl", values: ["/.well-known/security.txt"] },
    ] },
    { id: "thirdparty", title: { fr: "Sites tiers (fuites)", en: "Third-party sites (leaks)" }, items: [
      { id: "paste", label: { fr: "Sites de paste", en: "Paste sites" }, op: "site", mention: true, values: ["pastebin.com", "justpaste.it", "paste.ee", "rentry.co"] },
      { id: "collab", label: { fr: "Outils collaboratifs", en: "Collaboration tools" }, op: "site", mention: true, values: ["trello.com", "atlassian.net", "notion.site"] },
      { id: "cloud", label: { fr: "Stockage cloud", en: "Cloud storage" }, op: "site", mention: true, values: ["s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com", "digitaloceanspaces.com"] },
      { id: "code", label: { fr: "Dépôts de code", en: "Code hosting" }, op: "site", mention: true, values: ["github.com", "gitlab.com", "bitbucket.org"] },
    ] },
    { id: "sharing", title: { fr: "Liens de partage", en: "Sharing links" }, items: [
      { id: "postman", label: { fr: "Postman (clés d'API)", en: "Postman (API keys)" }, op: "site", mention: true, values: ["postman.com"] },
      { id: "drives", label: { fr: "Documents partagés", en: "Shared documents" }, op: "site", mention: true, values: ["docs.google.com", "drive.google.com", "dropbox.com/s", "sharepoint.com", "1drv.ms"] },
      { id: "chat", label: { fr: "Messagerie / réunions", en: "Chat / meetings" }, op: "site", mention: true, values: ["join.slack.com", "discord.gg", "zoom.us/j", "teams.microsoft.com/l"] },
      { id: "snippets", label: { fr: "Extraits de code", en: "Code snippets" }, op: "site", mention: true, values: ["gist.github.com", "stackoverflow.com", "replit.com", "codepen.io", "jsfiddle.net"] },
    ] },
    { id: "people", title: { fr: "Personnes / organisation", en: "People / organization" }, items: [
      { id: "linkedin", label: { fr: "LinkedIn", en: "LinkedIn" }, op: "site", mention: true, values: ["linkedin.com/in", "linkedin.com/company"] },
      { id: "jobs", label: { fr: "Offres d'emploi (pile techno)", en: "Job postings (tech stack)" }, op: "site", mention: true, values: ["linkedin.com/jobs", "indeed.com", "glassdoor.com"] },
      { id: "cv", label: { fr: "CV", en: "Resumes" }, op: "intitle", mention: true, values: ["cv", "resume", "curriculum vitae"] },
      { id: "bugbounty", label: { fr: "Bug bounty / divulgation", en: "Bug bounty / disclosure" }, op: "site", mention: true, values: ["hackerone.com", "bugcrowd.com", "openbugbounty.org"] },
    ] },
    { id: "github", title: { fr: "GitHub (code)", en: "GitHub (code)" }, items: [
      { id: "secrets", label: { fr: "Mots-clés secrets", en: "Secret keywords" }, op: "word", values: ["password", "api_key", "secret", "token"] },
      { id: "aws", label: { fr: "Clés AWS", en: "AWS keys" }, op: "word", values: ["AWS_SECRET_ACCESS_KEY", "AKIA"] },
      { id: "path", label: { fr: "Chemin de fichier (path:)", en: "File path (path:)" }, op: "path", values: [".env", "config.yml", "id_rsa", ".npmrc"] },
    ] },
    { id: "ops", title: { fr: "Opérateurs libres", en: "Free operators" }, items: [
      { id: "word", label: { fr: "Mot-clé", en: "Keyword" }, op: "word", values: [] },
      { id: "exact", label: { fr: "Expression exacte \"…\"", en: "Exact phrase \"…\"" }, op: "exact", values: [] },
      { id: "site", label: { fr: "site:", en: "site:" }, op: "site", values: [] },
      { id: "filetype", label: { fr: "filetype:", en: "filetype:" }, op: "filetype", values: [] },
      { id: "inurl", label: { fr: "inurl:", en: "inurl:" }, op: "inurl", values: [] },
      { id: "intitle", label: { fr: "intitle:", en: "intitle:" }, op: "intitle", values: [] },
      { id: "intext", label: { fr: "intext:", en: "intext:" }, op: "intext", values: [] },
      { id: "after", label: { fr: "Après (after:AAAA-MM-JJ)", en: "After (after:YYYY-MM-DD)" }, op: "after", values: [] },
      { id: "before", label: { fr: "Avant (before:AAAA-MM-JJ)", en: "Before (before:YYYY-MM-DD)" }, op: "before", values: [] },
      { id: "exclude", label: { fr: "Exclure (-)", en: "Exclude (-)" }, op: "exclude", values: [] },
    ] },
  ];

  function formatValue(op, v) {
    switch (op) {
      case "site": case "filetype": case "path": case "after": case "before": return op + ":" + v.replace(/\s+/g, "");
      case "inurl": case "intitle": case "intext": return op + ":" + K.quoteIfNeeded(v);
      case "exact": return '"' + v.replace(/"/g, "") + '"';
      case "exclude": return "-" + K.quoteIfNeeded(v);
      case "nosite": return "-site:" + v.replace(/\s+/g, "");
      default: return v;
    }
  }

  const dialect = {
    wild(op, v, name) {
      if (op === "site") return [{ op: "inurl", v: name }];
      if (op === "nosite") return [];
      return [{ op, v: v.split(K.PLACEHOLDER).join(name) }];
    },
    // Negations are AND'ed even with several values ("(-a OR -b)" would
    // mean almost nothing); a multi-operator "word" value is wrapped in
    // its own parentheses so OR doesn't bind to its last term only.
    group(op, items) {
      const parts = items.map((it) => formatValue(it.op, it.v));
      if (parts.length === 0) return "";
      if (parts.length === 1 || op === "exclude" || op === "nosite") return parts.join(" ");
      return "(" + parts.map((p, i) => (items[i].op === "word" && /\s/.test(p) ? "(" + p + ")" : p)).join(" OR ") + ")";
    },
  };

  K.createBuilder({
    root,
    stateKey: "/dashboard.html/dorks",
    logSource: "dorks",
    catalog: CATALOG,
    engines: ENGINES,
    defaultClauses: () => [["target", "site"]],
    newClause: ["files", "config"],
    implicitScope: (state, itemOf) =>
      state.engine === "github" || state.clauses.some((c) => itemOf(c).mention) ? ["target", "mention"] : ["target", "site"],
    dialect,
    wildNote: (name) => name + "* → inurl:" + name,
  });
};
