# NeonRelay (plugin NeonFlare)

Opens a NeonRelay box's end-to-end encrypted channel **in one of your NeonFlare
shells**, with the NeonRelay tools (listen, relay, stash, read, count, health…).

**The browser never contacts the relay** (`network: []`). TLS — the relay's
pinned ML-DSA-87 certificate (`cert.pem`), ML-KEM key exchange — is done by the
NeonRelay tools inside the shell, exactly as on the command line.

## Use

1. Start the shells: `scripts/ttyd-shells.sh start`, open a Bash or Zsh shell.
2. Dashboard → NeonRelay panel → **+ Add** a box: name, relay address, box id.
3. Pick the box and the shell → **Open the channel** (or a tool).
4. The command is **typed, not run**: press Enter in the shell yourself.

## Security model

- **Nothing runs by itself**: every command waits for your Enter.
- **Nothing sensitive on the command line**: the typed line holds only the
  plugin path, the tool name and a random nonce, so the shell history never
  sees an id or a secret, whatever `HISTCONTROL` / `HIST_IGNORE_SPACE` say.
- After your Enter, `tools/nf-open.sh` turns echo off and prints the nonce's
  SHA-256; only then does the panel hand over the box values on one masked
  line. Anything missing is asked for in the shell, masked.
- **Saved secrets are optional** (box password, E2E key, PIN — one checkbox
  each, off by default, at your own risk) and only possible with the NeonFlare
  vault on: stored encrypted, never in clear. While a channel is open, the
  NeonRelay tools hold them in their environment (`NEONRELAY_PW`,
  `NEONRELAY_KEY`), readable by your own account.
- `token.sh` (operator) writes the new box's credentials to
  `$XDG_RUNTIME_DIR/neonrelay-last-token.env` (RAM), never into the plugin
  folder.

## Requirements

OpenSSL ≥ 3.5 (ML-DSA-87 + ML-KEM), `python3`, PyNaCl
(`sudo apt install python3-nacl`), `curl`, a NeonFlare shell (ttyd).

## Contents

- `tools/nf-open.sh` — the launcher typed by the panel (written for NeonFlare).
- `client/`, `scripts/` — the public NeonRelay client, copied unchanged at a
  pinned commit (see `VENDOR.json`; MIT, `scripts/LICENSE-NeonRelay.txt`).
- `cert.pem` — the relay's **public** certificate (pinned).
