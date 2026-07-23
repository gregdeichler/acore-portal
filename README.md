# Acore Portal

Acore Portal is a self-hosted web portal for private AzerothCore WotLK realms. It provides realm status, account login/registration, character views, admin workflows, launcher APIs, raid roster views, and optional raid loot tracking.

This project was extracted from a live private-server portal and sanitized for public reuse. It does not include private account data, character data, database dumps, passwords, DNS names, or server-specific artwork.

## Features

- Public realm status and launcher status APIs
- Portal account login backed by `acore_auth.portal_users`
- Optional account registration gate
- Account-owned character cards
- Character lookup, equipped gear, specs, and average item level
- Admin dashboard for curated SOAP actions
- Item search and grant workflow
- Raid roster and raid lockout tools
- Optional raid loot and world boss loot history when `mod-acore-portal-tools` is installed
- Generic fantasy artwork suitable for public repos

## Requirements

- AzerothCore WotLK
- MySQL/MariaDB access to `acore_auth`, `acore_characters`, and `acore_world`
- AzerothCore SOAP enabled for admin actions
- Node.js 20+ or Docker
- Optional: [`mod-acore-portal-tools`](https://github.com/gregdeichler/mod-acore-portal-tools)

## Quick Start

```bash
cp .env.example .env
```

Edit `.env` for your server:

```env
REALM_NAME=AzerothCore
PUBLIC_PORTAL_URL=http://localhost:8088
REALM_HOST=127.0.0.1
DB_HOST=host.docker.internal
DB_USER=acore
DB_PASSWORD=change-me
SOAP_USER=SOAP_ADMIN
SOAP_PASSWORD=change-me
SESSION_SECRET=change-me-long-random-secret
```

Then run with Docker:

```bash
docker compose up -d --build
```

Open:

```text
http://localhost:8088
```

## Database Notes

The portal creates its own support tables in `acore_auth` as needed, including `portal_users` and launcher token storage. It does not require or ship database dumps.

The optional tools module creates these `acore_characters` tables:

- `acore_portal_raid_loot_events`
- `acore_portal_world_boss_kills`

If those tables do not exist, loot views should degrade gracefully.

## Security Notes

- Do not commit `.env`.
- Do not expose SOAP or MySQL directly to the public internet.
- Use HTTPS before enabling remote account login.
- Use a long random `SESSION_SECRET`.
- Create a least-privileged MySQL user for the portal if possible.
- Keep admin actions behind portal admin accounts only.

## Optional Module

For repair bot summoning, summon-to-character, AV queue helper, and server-side loot tracking, install:

```text
mod-acore-portal-tools
```

The portal uses `.portaltools` SOAP commands when those admin actions are enabled.

## Public Assets

The included art is generic replacement art. Server owners can replace files in `public/portal-art/` with their own realm-specific assets.
