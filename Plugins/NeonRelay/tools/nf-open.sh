#!/usr/bin/env bash
# NeonFlare -- lanceur du plugin NeonRelay (localrepo/spec/plugins/NEONRELAY.md § 5).
#
#   bash nf-open.sh OUTIL NONCE
#
# Tapé par le panneau NeonRelay dans un shell NeonFlare, SANS Entrée : c'est
# toujours l'utilisateur qui lance. La ligne ne contient RIEN de sensible
# (chemin, outil en liste blanche, nonce aléatoire) : peu importe que le shell
# la garde dans son historique.
#
# Les valeurs de la boîte arrivent ensuite, jamais par la ligne de commande :
#   1. écho coupé (stty -echo), puis signal NFR-READY:<SHA-256 du nonce> ;
#   2. le panneau répond par UNE ligne « NFR1 base token mdp clé pin »
#      (chaque champ en base64, « - » si absent), lue en silence ;
#   3. ce qui manque est demandé ici, en saisie masquée.
# Ni l'écran, ni l'historique du shell, ni le défilement tmux ne voient les
# secrets. Les scripts NeonRelay les reçoivent ensuite par leur environnement
# (NEONRELAY_PW, NEONRELAY_KEY : leur interface habituelle).
set -u
umask 077
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUG="$(dirname "$HERE")"
NR="$PLUG/scripts"
DEFAULT_BASE="https://179.197.84.173:8000"
TOOL="${1:-}"
NONCE="${2:-}"

die() { printf '%s\n' "$*" >&2; exit 2; }

case "$TOOL" in
  secure-shell|stream|relay|stash|readstash|delete|count) NEED=box ;;
  health|make-key) NEED=base ;;
  token) NEED=admin ;;
  client|check-key|make-pin|claviers) NEED=none ;;
  *) die "nf-open.sh : outil inconnu « $TOOL »." ;;
esac
[[ "$NONCE" =~ ^[0-9a-f]{32}$ ]] || die "nf-open.sh : nonce invalide."
[ -t 0 ] || die "nf-open.sh : à lancer dans un terminal."

# Épinglage du certificat du relais + TLS 1.3 / ML-KEM (scripts/base/_tls.sh).
export NEONRELAY_CACERT="$PLUG/cert.pem"
export NEONRELAY_OPENSSL_CONF="$NR/base/openssl-tls.cnf"
# Jamais de fichier d'identifiants dans le dossier du plugin (il est dans le
# dépôt NeonFlare) : token.sh écrit, et _token.sh lirait, en mémoire vive.
export NEONRELAY_CREDS="${XDG_RUNTIME_DIR:-/tmp}/neonrelay-last-token.env"

BASE='' TOKEN='' PW='' KEY='' PIN=''

b64d() { [ "$1" = "-" ] && return 0; printf '%s' "$1" | base64 -d 2>/dev/null; }

# 1-2. Remise par le panneau (seulement s'il attend ce nonce précis).
if [ "$NEED" != none ]; then
  st="$(stty -g)"
  stty -echo
  printf 'NFR-READY:%s\n' "$(printf '%s' "$NONCE" | sha256sum | cut -c1-64)"
  line=''
  IFS= read -r -t 15 line || line=''
  stty "$st"
  if [ -n "$line" ]; then
    set -f
    IFS=' '
    # shellcheck disable=SC2086
    set -- $line
    IFS=$' \t\n'
    set +f
    if [ "$#" -eq 6 ] && [ "$1" = "NFR1" ]; then
      BASE="$(b64d "$2")"; TOKEN="$(b64d "$3")"; PW="$(b64d "$4")"; KEY="$(b64d "$5")"; PIN="$(b64d "$6")"
    else
      echo "Valeurs du panneau illisibles : saisie manuelle." >&2
    fi
    set --
    line=''
  fi
fi

# Valeurs remises : validées, sinon redemandées.
[[ "$BASE" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || BASE=''
[[ "$TOKEN" =~ ^[A-Za-z0-9_-]{1,128}$ ]] || TOKEN=''

ask() {   # ask VAR "invite" masqué(0|1)
  local v=''
  if [ "$3" = 1 ]; then
    IFS= read -r -s -p "$2" v
    printf '\n' >&2
  else
    IFS= read -r -p "$2" v
  fi
  printf -v "$1" '%s' "$v"
}

need_base() {
  while [ -z "$BASE" ]; do
    ask BASE "Adresse du relais [$DEFAULT_BASE] : " 0
    [ -z "$BASE" ] && BASE="$DEFAULT_BASE"
    [[ "$BASE" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || { echo "Adresse invalide (https://hôte:port)." >&2; BASE=''; }
  done
  export NEONRELAY_BASE="$BASE"
}

need_box() {
  need_base
  while [ -z "$TOKEN" ]; do
    ask TOKEN "Identifiant de la boîte (token) : " 1
    [[ "$TOKEN" =~ ^[A-Za-z0-9_-]{1,128}$ ]] || { echo "Identifiant invalide." >&2; TOKEN=''; }
  done
  while [ -z "$PW" ]; do ask PW "Mot de passe de la boîte : " 1; done
  export NEONRELAY_TOKEN="$TOKEN" NEONRELAY_PW="$PW"
}

need_key() {   # need_key obligatoire(0|1)
  if [ -z "$KEY" ]; then
    if [ "$1" = 1 ]; then
      while [ -z "$KEY" ]; do ask KEY "Clé de chiffrement E2E : " 1; done
    else
      ask KEY "Clé de chiffrement E2E (Entrée = aucune) : " 1
    fi
  fi
  [ -n "$KEY" ] && export NEONRELAY_KEY="$KEY"
  # PIN enregistré : clé dérivée ici (Argon2id, même calcul que scripts/base/_crypto.sh).
  # Tant que _crypto.sh ne saute pas sa propre invite quand NEONRELAY_E2E est déjà
  # défini (neonrelay/TODO.md), il demandera encore le PIN : Entrée suffit, la clé
  # dérivée ici est gardée.
  if [ -n "$PIN" ] && [ -n "$KEY" ]; then
    local e2e rc=0
    e2e="$(printf '%s\n' "$PIN" | NEONRELAY_TOKEN="$TOKEN" python3 "$NR/base/_crypto.py" derive)" || rc=$?
    PIN=''
    if [ "$rc" -eq 0 ] && [ -n "$e2e" ]; then
      export NEONRELAY_E2E="$e2e"
      echo "🔐 PIN enregistré appliqué." >&2
    else
      echo "PIN enregistré refusé : il sera demandé." >&2
    fi
  fi
  PIN=''
}

case "$TOOL" in
  secure-shell)
    need_box; need_key 1
    exec "$NR/secure-shell.sh" ;;
  stream|readstash|count)
    need_box; need_key 0
    exec "$NR/$TOOL.sh" ;;
  delete)
    need_box
    exec "$NR/delete.sh" ;;
  relay|stash)
    need_box; need_key 0
    MSG=''
    while [ -z "$MSG" ]; do IFS= read -r -p "Message : " MSG; done
    exec "$NR/$TOOL.sh" "$MSG" ;;
  health)
    need_base
    exec "$NR/health.sh" ;;
  token)
    need_base
    ask ADMIN_USER "Administrateur NeonRelay : " 0
    ask ADMIN_PW "Mot de passe administrateur : " 1
    export NEONRELAY_ADMIN_USER="$ADMIN_USER" NEONRELAY_ADMIN_PASSWORD="$ADMIN_PW"
    echo "Les identifiants de la nouvelle boîte iront dans $NEONRELAY_CREDS (mémoire vive)." >&2
    exec "$NR/token.sh" ;;
  make-key)
    need_base
    exec python3 "$PLUG/client/neonrelay.py" make-key --base "$BASE" --cert "$NEONRELAY_CACERT" ;;
  client)
    exec python3 "$PLUG/client/neonrelay.py" ;;
  check-key|make-pin|claviers)
    exec python3 "$PLUG/client/neonrelay.py" "$TOOL" ;;
esac
