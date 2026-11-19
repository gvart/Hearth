# Telemetry collector

A Cloudflare Worker that receives the anonymous usage stats opted-in hubs send once a week
([docs/telemetry.md](../../docs/telemetry.md)). It:

- accepts only `POST` with a JSON body of at most 2 KiB;
- checks the payload strictly: exactly the keys `install_id`, `version`, `os`, `arch`, `devices` and
  `integrations`, each in its expected shape, the device range and integration names from fixed lists.
  Anything else is answered `400` and stored nowhere;
- keeps one row per install ID per ISO week in D1, so a hub that sends twice in a week counts once;
- stores no IP address: it reads no request header but `Content-Type`, and Workers observability
  (request logs) is off in `wrangler.toml`.

It is not deployed by CI. To run it:

```sh
cd deploy/telemetry-worker
npx wrangler login
npx wrangler d1 create hearth-telemetry        # put the database_id it prints into wrangler.toml
npx wrangler d1 execute hearth-telemetry --remote --command "
  CREATE TABLE IF NOT EXISTS pings (
    week         TEXT NOT NULL,   -- ISO week, such as 2026-W47
    install_id   TEXT NOT NULL,
    version      TEXT NOT NULL,
    os           TEXT NOT NULL,
    arch         TEXT NOT NULL,
    devices      TEXT NOT NULL,   -- 0, 1-5, 6-20, 21-50 or 51+
    integrations TEXT NOT NULL,   -- comma-separated, sorted
    PRIMARY KEY (week, install_id)
  )"
npx wrangler deploy
```

Then set the URL it prints (or a custom domain routed to it) as `defaultTelemetryEndpoint` in
`cmd/hearth/telemetry.go`. Until that constant is set, hubs store the admin's answer and send nothing.
The endpoint must be `https://`.

Weekly active installs, and the spread of versions:

```sh
npx wrangler d1 execute hearth-telemetry --remote --command \
  "SELECT week, COUNT(*) AS installs FROM pings GROUP BY week ORDER BY week DESC LIMIT 12"
npx wrangler d1 execute hearth-telemetry --remote --command \
  "SELECT version, COUNT(*) FROM pings WHERE week = (SELECT MAX(week) FROM pings) GROUP BY version"
```

Try it locally without deploying: `npx wrangler dev --local`, after running the `CREATE TABLE` above
with `--local` instead of `--remote`.
