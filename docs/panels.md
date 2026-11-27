---
title: Guest and kiosk panels
description: Share a few devices and the restarts allowed on them through a link with no login, or put them on a wall screen.
---

A panel is a page with a few chosen devices and, for each, the restarts a visitor may take. You
share it with a link that needs no login: a guest gets a page for the house's media box, or a
Raspberry Pi with a touch screen on the wall shows it full screen.

The link opens that one panel and nothing else. A guest cannot reach any other page, device, panel
or API route, and every action they take goes through the hub's [policy](guardrails.md) and into
the audit log.

## Build a panel

Sign in, open **Panels** and choose **New panel**.

1. Give it a name, such as `Living room`.
2. Add the devices it shows, in the order you want. Reorder them with the arrows.
3. For each device, tick the services a guest may restart. The list holds what the device's agent
   allows by name (**Restart services**, **Restrict to…** `docker:jellyfin` in the device's
   Capabilities card, see [guardrails.md](guardrails.md#device-capability-ceiling)); a glob such as
   `docker:*` names no one service. A device whose agent allows no restart by name is shown read-only.
4. **Save panel**.

A guest sees each device's name, whether it is online, and when it was last seen if not. Not its
addresses, labels, facts or anything else.

Only restarts (`device.restart`, class `safe`) can be offered. A panel can never allow a dangerous
action: the hub refuses to save one that lists one (`400 dangerous_action`), and policy admits the
`guest` actor to no dangerous action. A `policy.yaml` that sets `actors: {guest: {dangerous: ...}}`
to anything but `deny` fails to load.

Saving, deleting and sharing a panel are the policy actions `panel.save`, `panel.delete`,
`panel.link.create` and `panel.link.revoke` (class `safe`, signed-in admin only), each in the audit
log.

## Share it

Choose **Share** on the panel, pick how long the link lasts (24 hours, 7 days, 30 days or never) and
**Create link**. The link is shown **once**: copy it then. The hub keeps only its SHA-256 hash, and
the audit log only the link's ID.

You get two forms of it:

- `http://hub.lan:7080/p/<token>`: the guest page.
- `http://hub.lan:7080/p/<token>?kiosk=1`: the same page full screen, with no header, larger text
  and large touch targets, for a wall display.

A panel can have several links, for example one per screen and one for a visitor. Each lists its
status on the panel (active, expired or revoked). **Revoke** one when it is no longer needed: from
then on, as for an expired link or a deleted panel, the page and every guest request answer `404`,
and an open page stops updating at once. A restart still waiting for approval no longer runs, even
if you approve it; nor does one whose action you removed from the panel meanwhile.

Anyone who has the link can use it, so treat it like a key: share it only with whom should see the
panel, and prefer an expiry for visitors. Over plain HTTP the link crosses your LAN in the clear; use
the hub's [HTTPS address](https.md) where that matters.

## What a guest can do

- See the panel: it stays current on its own. The page listens to the hub's change stream and
  refetches the panel whenever a device on it changes, comes online or goes offline.
- Tap an allowed restart. The hub runs it as the actor `guest` with the ID `panel/<panel id>`, so
  the audit log shows which panel did what. The panel's list is a ceiling, not a grant on its own:
  - policy decides each one. With `actors: {guest: {safe: confirm}}` in `policy.yaml`, every guest
    restart is **held for approval** and runs only once you approve it (the button says it is
    waiting); `deny` refuses them all;
  - the device's capability ceiling is checked again, by the hub and by the agent;
  - a link takes at most 5 actions in a burst, then one every 10 seconds, counting requests for
    actions the panel does not have, with at most 2 running or waiting for approval at a time and
    at most 1 waiting for approval (`429` past any of them).

A link may also read its panel 30 times in a burst, then once a second, and keep at most 6 pages
open on the change stream; the hub keeps at most 64 open for all links (`429` past either).

A guest never names a device or a service: the page sends the IDs of the widget and the action the
hub gave them, and the hub takes the device and service from the saved panel.

## Kiosk on a Raspberry Pi screen

Any Pi with a screen and a desktop (Raspberry Pi OS with desktop) can show a panel. Create a link
for it, with no expiry if the screen stays up, and open its kiosk form in Chromium's kiosk mode:

```sh
chromium-browser --kiosk --noerrdialogs --disable-infobars --incognito \
  'http://hub.lan:7080/p/<token>?kiosk=1'
```

On recent Raspberry Pi OS the binary is `chromium` rather than `chromium-browser`. To start it with
the desktop, add that command to the desktop's autostart, as your OS version documents it (for
example an `[autostart]` entry in `~/.config/wayfire.ini` on Wayland, or a line in
`~/.config/lxsession/LXDE-pi/autostart` on X11). Hearth installs nothing on the Pi for this: the
screen is just a browser.

`--incognito` keeps no cookies, which a panel does not need. If the hub restarts or the network
drops, the page reconnects on its own. If the link is revoked, the screen says so; create a new link
and update the command.

## API

The admin's endpoints, behind the session cookie:

| Method and path                            | Does                                          |
| ------------------------------------------ | --------------------------------------------- |
| `GET /api/v1/panels`                       | Every panel, with its links (never a token)   |
| `POST /api/v1/panels`                      | Create a panel: `{"name", "widgets"}`         |
| `GET`, `PUT`, `DELETE /api/v1/panels/{id}` | Read, replace or delete one                   |
| `POST /api/v1/panels/{id}/links`           | Create a link, as JSON: `{"expires_in": "24h"}` or `{}`; the answer holds the token, once |
| `DELETE /api/v1/panels/{id}/links/{link}`  | Revoke a link                                 |

A widget is `{"kind": "device", "entity": "<device id>", "actions": [{"action": "device.restart",
"service": "docker:jellyfin"}]}`; the hub sets its `id`, and each action's `id` and `class`.

The guest's endpoints, where the token is the only credential:

| Method and path                         | Does                                                  |
| --------------------------------------- | ----------------------------------------------------- |
| `GET /p/{token}`                        | The page (404 for a link that opens nothing)          |
| `GET /api/v1/guest/{token}`             | The panel as the guest sees it                        |
| `GET /api/v1/guest/{token}/events`      | Server-sent `changed` events for the panel's devices  |
| `POST /api/v1/guest/{token}/actions`    | Take an action: `{"widget": "<id>", "action": "<id>"}` |

The token works nowhere else: not as a session cookie, not as a bearer token for MCP, not for
another panel.

