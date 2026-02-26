# OpenClaw QQ Bridge (NapCat + NoneBot2)

This repository packages a production-ready bridge that connects QQ (OneBot V11) to OpenClaw via gateway mode.

## Architecture

- QQ client (NapCat) -> OneBot V11 WebSocket
- NoneBot2 bridge (`bot.py`) handles:
  - `oc <message>` / `ai <message>` chat relay
  - group-shared sessions + private isolated sessions
  - optional file relay from server workspace to QQ
- OpenClaw gateway (`/v1/chat/completions`) executes agent/tools

## Included Files

- `bot.py`: NoneBot bridge logic
- `Dockerfile`: bridge image build
- `docker-compose.yml`: bridge runtime
- `requirements.txt`: Python dependencies
- `.env.example`: env template (no secrets)
- `openclaw.template.json`: OpenClaw config template (no secrets)

## Deploy

1. Install and configure OpenClaw on Linux host.
2. Copy `openclaw.template.json` to `~/.openclaw/openclaw.json` and fill your values.
3. Prepare bridge folder and copy this repo.
4. Create `.env` from `.env.example` and fill your tokens/URLs.
5. Start bridge:

```bash
docker compose up -d --build
```

## Required .env Values

- `ONEBOT_ACCESS_TOKEN`: token used by NapCat OneBot WS
- `OPENCLAW_BASE_URL`: OpenClaw gateway URL (example: `http://127.0.0.1:18789`)
- `OPENCLAW_TOKEN`: gateway bearer token
- `PUBLIC_BASE_URL`: public URL for temporary file links exposed by bridge

## QQ Usage

- `oc 你好`
- `ai 帮我查下香港天气`
- `ocfile somefile.zip`

## Notes

- Do not commit real secrets.
- If weather queries are slow in your region, OpenClaw may need tool/provider tuning.
- `docker-compose.yml` mounts OpenClaw workspace/session directories; adjust paths if needed.
