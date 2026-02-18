# Main Setup

This folder is the main composition layer where the applications are wired together for local run/deployment.

## What is here

- `docker-compose.yml`: launches the Kuma Management Console from `apps/kuma-management-console/`.
- `.env.example`: environment defaults you can copy into `.env`.

## Run

```bash
cd main
cp .env.example .env
# Set a secure secret key:
# python -c "import secrets; print(secrets.token_hex(32))"
docker compose up -d
```

Access the UI at `http://localhost:5080`.

## Notes

- The compose file uses `../apps/kuma-management-console` as build context.
- Add-ons (like mount monitor) are independent and documented under `addons/`.
