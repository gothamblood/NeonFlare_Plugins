# OSINT — plugin NeonFlare

Passive reconnaissance of a target you are **authorised** to study, as five
Dashboard panels:

| Panel | What it does |
|---|---|
| Google Dorks | Builds advanced searches (Google, Bing, DuckDuckGo, GitHub code). Opens them only when you click. |
| Shodan | Builds Shodan searches; opens shodan.io with your own account (no API key). |
| Certificats (crt.sh) | Certificate-transparency links and `curl` commands. |
| Wayback Machine | Archived URLs (CDX links and `curl` commands). |
| Actifs découverts | Collects subdomains, DNS, RDAP, ASN and known ports into one de-duplicated inventory, after you tick "authorised" for the target. |

## Permissions

- **Shell**: Wayback / urlscan / subfinder / amass commands run in one of your
  open Bash/Zsh shells (NeonFlare's ttyd shells), never on their own.
- **Network**, only when you click ▶: `crt.sh`, `dns.google`, `rdap.org`,
  `stat.ripe.net`, `internetdb.shodan.io`; through the shell:
  `web.archive.org`, `urlscan.io`.
- **Vault**: the inventory (`/dashboard.html/osintInventory`) is encrypted
  when the vault is on.
- **GRC**: "→ GRC" adds a discovered host to the asset register; "+ Finding"
  opens NeonFlare's quick-finding form.

Nothing is sent before you click. No API key is asked for or stored. No
personal data is kept: emails and RDAP registrant details are ignored.

## Data

The plugin keeps the same storage keys NeonFlare used before OSINT became a
plugin (`/dashboard.html/osintTarget`, `…/dorks`, `…/shodan`, `…/crtsh`,
`…/wayback`, `…/osintCollectUi`, `…/osintInventory`), so an existing target,
settings and inventory come back as they were. Disabling the plugin keeps
them; **Marketplace → Delete data** removes them.

Enabling the plugin offers to create the **OSINT** dashboard (all five panels).
On your other dashboards the panels stay hidden until you show them with
☰ Panels.
