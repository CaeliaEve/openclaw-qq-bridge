#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not installed. Install Docker first."
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
else
  echo "ERROR: docker compose is not available."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon is not running."
  exit 1
fi

if [ ! -f ".env" ]; then
  if [ ! -f ".env.example" ]; then
    echo "ERROR: .env.example not found."
    exit 1
  fi
  cp .env.example .env
  echo ".env created from .env.example"
fi

required_keys=(
  "ONEBOT_ACCESS_TOKEN"
  "OPENCLAW_BASE_URL"
  "OPENCLAW_TOKEN"
  "PUBLIC_BASE_URL"
)

missing=()
for key in "${required_keys[@]}"; do
  value="$(grep -E "^${key}=" .env | head -n1 | cut -d= -f2- || true)"
  if [ -z "$value" ] || [[ "$value" == replace_with_* ]] || [[ "$value" == "http://your_server_ip_or_domain:8080" ]]; then
    missing+=("$key")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  if [ -t 0 ]; then
    echo "Fill required values in .env"
    for key in "${missing[@]}"; do
      if [ "$key" = "ONEBOT_ACCESS_TOKEN" ] || [ "$key" = "OPENCLAW_TOKEN" ]; then
        read -r -s -p "${key}: " input
        echo
      else
        read -r -p "${key}: " input
      fi
      if grep -q -E "^${key}=" .env; then
        sed -i "s|^${key}=.*|${key}=${input}|g" .env
      else
        echo "${key}=${input}" >> .env
      fi
    done
  else
    echo "ERROR: missing required .env values: ${missing[*]}"
    echo "Edit .env and rerun."
    exit 1
  fi
fi

echo "Starting nonebot-openclaw bridge..."
$COMPOSE_CMD up -d --build
$COMPOSE_CMD ps

echo
echo "Done."
echo "Quick check:"
echo "  - Container should be Up"
echo "  - NapCat WS should connect to bridge URL"
echo "  - QQ test: oc 你好"
