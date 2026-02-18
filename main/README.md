# Main Setup

This folder is the main composition layer where the applications are wired together for local run/deployment.

## What this starts

- `docker-compose.yml` starts the Kuma Management Console.
- Build source is `../apps/kuma-management-console`.
- App URL is `http://localhost:5080`.

## Prerequisites (required)

- Docker Desktop (or Docker Engine + Compose) installed and running.
- Port `5080` free on your machine.

Quick checks:

```bash
docker --version
docker compose version
```

## Stupid-proof quick start

Run these commands exactly:

```bash
cd main
cp -n .env.example .env
docker compose up -d --build
docker compose ps
```

Now open `http://localhost:5080`.

Success looks like this:

- `docker compose ps` shows the container as `Up` (or `healthy`)
- Browser opens login/setup page

## First run only: set your own secret key

Default `.env` contains a placeholder `SECRET_KEY`.
Replace it once:

```bash
cd main
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Copy that value into `.env` as `SECRET_KEY=...`, then restart:

```bash
cd main
docker compose up -d
```

## Common issues

- Port already in use:
  - Edit `main/docker-compose.yml` and change `5080:5000` to another host port, e.g. `5081:5000`.
- Container not starting:
  - Run `cd main && docker compose logs --tail=100`.
- Need to stop:
  - Run `cd main && docker compose down`.

## Related docs

- Web app details: `../apps/kuma-management-console/README.md`
- Add-ons are separate: `../addons/`
