# NeonFlare Plugins

Optional plugins for [NeonFlare](https://github.com/gothamblood/NeonFlare),
installed from **More → Marketplace** inside NeonFlare.

## Plugins

| Plugin | What it does | Needs |
|---|---|---|
| [OSINT](Plugins/OSINT/README.md) | Passive recon panels: Google Dorks, Shodan, crt.sh, Wayback Machine, discovered assets | NeonFlare ≥ 2.0.0 |
| [NeonRelay](Plugins/NeonRelay/README.md) | Opens a NeonRelay box's encrypted channel in a NeonFlare shell, with the NeonRelay tools; the browser never contacts the relay | NeonFlare ≥ 2.1.0, a NeonFlare shell, OpenSSL ≥ 3.5, PyNaCl |

## How it works

- `index.json` lists every plugin with its version, the minimum NeonFlare
  version it needs, its permissions and the SHA-256 fingerprint of every file.
- `index.json.sig` is the author's ECDSA P-256 signature of `index.json`.
  NeonFlare ships the matching **public** key and checks the signature, then
  each file's fingerprint, before writing anything. If anything doesn't
  match, nothing is installed.
- An installed plugin arrives **disabled**. A disabled plugin has none of its
  files loaded, and an enabled one makes no network request until you act.
  Turning a plugin off never deletes its data.
- A plugin with the **shell** permission may also ship shell tools
  (`.sh`, `.py`, `.cnf`, `.pem`, only under `client/`, `scripts/`, `tools/`
  plus `cert.pem`). The browser never loads them; they run in your shells,
  only when you press Enter.

## Installing

Marketplace → *Install* shows the command to paste into a terminal, with the
path of your NeonFlare folder already filled in:

```bash
bash '/path/to/NeonFlare/scripts/plugins.sh' install <id>
```

The script downloads this signed catalog, checks the signature and every file's
SHA-256, then writes `plugins/<id>/` and `config/plugins.js`. The plugin arrives
disabled: reload the Marketplace and click *Enable*. Offline: *⬇ .zip*, then
`scripts/plugins.sh install neonflare-plugin-<id>-<version>.zip`.

## Layout

```
index.json, index.json.sig   signed catalog
Plugins/<Name>/manifest.json id, version, permissions, panels, files to load
Plugins/<Name>/…             the plugin's code, styles, icon, README
```

## License

MIT -- see [LICENSE](LICENSE). Same license as NeonFlare.
