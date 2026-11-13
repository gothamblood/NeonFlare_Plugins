# NeonFlare Plugins

Optional plugins for [NeonFlare](https://github.com/gothamblood/NeonFlare),
installed from **More → Marketplace** inside NeonFlare.

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

## Installing

- **Chrome / Edge / Brave**: Marketplace → *Install* (pick the NeonFlare
  folder once).
- **Other browsers**: Marketplace → *⬇ .zip*, then from the NeonFlare folder:

  ```bash
  scripts/plugins.sh install neonflare-plugin-<id>-<version>.zip
  ```

## Layout

```
index.json, index.json.sig   signed catalog
Plugins/<Name>/manifest.json id, version, permissions, panels, files to load
Plugins/<Name>/…             the plugin's code, styles, icon, README
```
