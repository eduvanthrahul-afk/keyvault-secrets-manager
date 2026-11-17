#!/usr/bin/env bash
# KeyVault self-host installer.
#
#   curl -fsSL https://github.com/eduvanthrahul-afk/keyvault-secrets-manager/releases/latest/download/install.sh | bash
#
# Non-interactive (e.g. cloud-init):
#   curl -fsSL .../install.sh | KEYVAULT_DOMAIN=vault.example.com bash
#   curl -fsSL .../install.sh | KEYVAULT_DOMAIN=localhost bash        # local-only, no HTTPS
#
# Optional env: KEYVAULT_DIR (default ~/keyvault), KEYVAULT_VERSION (default: this release).
# Re-running the script upgrades an existing install and keeps its .env (your keys).
set -euo pipefail

REPO="eduvanthrahul-afk/keyvault-secrets-manager"
# The release workflow replaces this with the tag (e.g. v2.0.0).
RELEASE_VERSION="__KEYVAULT_VERSION__"

VERSION="${KEYVAULT_VERSION:-$RELEASE_VERSION}"
if [[ "$VERSION" == "__KEYVAULT_VERSION__" || -z "$VERSION" ]]; then VERSION="latest"; fi
if [[ "$VERSION" == "latest" ]]; then
  ASSETS="https://github.com/$REPO/releases/latest/download"
  IMAGE_TAG="latest"
else
  ASSETS="https://github.com/$REPO/releases/download/$VERSION"
  IMAGE_TAG="${VERSION#v}"
fi
DIR="${KEYVAULT_DIR:-$HOME/keyvault}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  \033[36m›\033[0m %s\n' "$*"; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Prompts read from the terminal even when the script itself is piped in via curl | bash.
ask() {
  local prompt="$1" default="${2:-}" reply=""
  if [[ -r /dev/tty ]]; then
    read -r -p "  $prompt${default:+ [$default]}: " reply </dev/tty || true
  fi
  printf '%s' "${reply:-$default}"
}

random_b64() { openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '\n'; }
random_hex() { openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

bold "KeyVault installer ($VERSION)"

# ---- 1. prerequisites ----------------------------------------------------------
command -v curl >/dev/null || fail "curl is required."
if ! command -v docker >/dev/null; then
  if [[ "$(uname -s)" == "Linux" ]]; then
    answer="$(ask "Docker is not installed. Install it now with get.docker.com? (y/N)" "N")"
    if [[ "$answer" =~ ^[Yy] ]]; then
      curl -fsSL https://get.docker.com | sh
    else
      fail "Install Docker first: https://docs.docker.com/engine/install/"
    fi
  else
    fail "Install Docker Desktop first: https://docs.docker.com/get-docker/"
  fi
fi

DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
  if command -v sudo >/dev/null && sudo docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
  else
    fail "Docker is installed but not running (or you lack permission). Start Docker and retry."
  fi
fi
"${DOCKER[@]}" compose version >/dev/null 2>&1 || fail "The Docker Compose plugin is required: https://docs.docker.com/compose/install/"

# ---- 2. files ------------------------------------------------------------------
mkdir -p "$DIR"
cd "$DIR"
info "Installing into $DIR"
curl -fsSL "$ASSETS/docker-compose.yml" -o docker-compose.yml
curl -fsSL "$ASSETS/Caddyfile" -o Caddyfile

# ---- 3. configuration (only on first install) -----------------------------------
if [[ -f .env ]]; then
  info "Keeping existing .env (your keys and settings)"
  # Move the pinned version forward on upgrade.
  if grep -q '^KEYVAULT_VERSION=' .env; then
    sed -i.bak "s/^KEYVAULT_VERSION=.*/KEYVAULT_VERSION=$IMAGE_TAG/" .env && rm -f .env.bak
  else
    echo "KEYVAULT_VERSION=$IMAGE_TAG" >> .env
  fi
else
  DOMAIN="${KEYVAULT_DOMAIN:-}"
  if [[ -z "$DOMAIN" ]]; then
    echo
    echo "  Enter the domain KeyVault will be served on (its DNS A record must point to this"
    echo "  server, with ports 80 and 443 open). Type 'localhost' to try it on this machine only."
    DOMAIN="$(ask "Domain" "localhost")"
  fi
  DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN%%/*}"

  umask 077
  if [[ "$DOMAIN" == "localhost" || "$DOMAIN" == "127.0.0.1" ]]; then
    MODE="local"
    {
      echo "KEYVAULT_MODE=local"
      echo "KEYVAULT_APP_ORIGIN=http://localhost:8080"
      echo "FORWARD_HEADERS_STRATEGY=none"
      # Browsers only keep Secure / __Host- cookies over HTTPS, so local mode uses a plain cookie.
      echo "KEYVAULT_SECURE_COOKIE=false"
      echo "KEYVAULT_SESSION_COOKIENAME=kv_session"
    } > .env
  else
    MODE="https"
    {
      echo "KEYVAULT_MODE=https"
      echo "COMPOSE_PROFILES=https"   # so a plain "docker compose up -d" also starts Caddy
      echo "KEYVAULT_DOMAIN=$DOMAIN"
      echo "KEYVAULT_APP_ORIGIN=https://$DOMAIN"
      echo "FORWARD_HEADERS_STRATEGY=framework"
    } > .env
  fi
  {
    echo "KEYVAULT_VERSION=$IMAGE_TAG"
    echo "DATABASE_PASSWORD=$(random_hex)"
    echo "# Encrypts TOTP seeds. Back this file up: losing it disables existing 2FA enrolments."
    echo "KEYVAULT_SERVER_KEY=$(random_b64)"
    echo "# Set to false after creating your accounts, then: docker compose up -d"
    echo "KEYVAULT_REGISTRATION_ENABLED=true"
  } >> .env
  info "Wrote .env with freshly generated secrets ($MODE mode)"
fi

# ---- 4. start -------------------------------------------------------------------
info "Pulling images"
"${DOCKER[@]}" compose pull --quiet
info "Starting KeyVault"
"${DOCKER[@]}" compose up -d --remove-orphans

info "Waiting for the server to become healthy"
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8080/actuator/health >/dev/null 2>&1; then
    URL="$(grep '^KEYVAULT_APP_ORIGIN=' .env | cut -d= -f2)"
    echo
    bold "KeyVault is running: $URL"
    echo "  Create your account there, then consider setting KEYVAULT_REGISTRATION_ENABLED=false"
    echo "  in $DIR/.env and running: cd $DIR && ${DOCKER[*]} compose up -d"
    echo
    echo "  Logs:     cd $DIR && ${DOCKER[*]} compose logs -f app"
    echo "  Upgrade:  re-run this installer"
    echo "  Backup:   $DIR/.env and: ${DOCKER[*]} compose exec db pg_dump -U keyvault keyvault > backup.sql"
    exit 0
  fi
  sleep 3
done
fail "The server did not become healthy in 3 minutes. Check: cd $DIR && ${DOCKER[*]} compose logs app"
