# Notifications

Hearth sends phone notifications through [ntfy](https://ntfy.sh) or a Telegram bot, so you need no
Hearth app. A **channel** is one ntfy topic or one Telegram chat, with its credentials. Channels are
configured in a file on the hub, and everything else — automations, the web UI, the audit log, run
history — names them only: no token or topic ever leaves that file. (A failed send may name the
server it could not reach, as `dial tcp ntfy.lan:443: ...`, like a webhook names its site.)

## The channels file

`<data-dir>/notify.yaml`, or `hearth hub --notify-config FILE` (env `HEARTH_NOTIFY_CONFIG`):

```yaml
channels:
  phone:                       # the channel's name: lowercase letters, digits, - and _
    type: ntfy
    url: https://ntfy.example.com   # the ntfy server only; https://ntfy.sh works too
    topic: hearth-alerts
    token: tk_AbCdEf...        # optional: an ntfy access token (ntfy token add)
  family:
    type: telegram
    bot_token: "123456789:AAE..."   # from @BotFather
    chat_id: "-1001234567890"       # the chat's id, or "@channelname"
```

Keep it readable by the hub's user only (`chmod 600`): the hub warns at start if it is not. The file
is read when the hub starts; restart the hub after changing it. A file that cannot be read or has
an error stops the hub from starting, naming the field but never quoting a value.

On ntfy.sh a topic without an access token is readable by anyone who guesses its name: pick a long
random topic, or run your own ntfy server.

For Telegram, create a bot with [@BotFather](https://t.me/BotFather), send it a message (or add it
to a group), and read the chat id from `https://api.telegram.org/bot<TOKEN>/getUpdates`.

In a cluster, notify actions run on the leader, which may be any voter: give every hub the same
file, as with the automations directory.

## Sending from an automation

```yaml
id: nas-down
triggers:
  - type: device
    device: nas
    to: offline
actions:
  - type: notify
    channel: phone
    title: "{{ .Trigger.Name }} is {{ .Trigger.State }}"   # optional
    message: "{{ .Trigger.Hostname }} stopped reporting at {{ .Trigger.At }}"
```

`title` and `message` are templates over the trigger's event: see
[Using the trigger's event in actions](automations.md#using-the-triggers-event-in-actions) for the
fields each trigger provides. `channel` is not a template, and must name a channel in the hub's
file, or the automation is rejected when it is loaded (`hearth automation plan`, which does not
know the hub's channels, accepts any name).

The `notify` action is in policy class `safe`, so any automation may take it; each one is in the
audit log as `automation.notify` with the channel's name as its target. A send that fails (the
server is down, the token is wrong) fails the run, with the provider's reason. A send gives up
after 10 s.

ntfy gets the title and message as they are. Telegram gets the title, a newline and the message, as
plain text.

## Test-send

The web UI's **Notifications** page lists the channels by name and type, with a **Send test**
button that sends "Test notification from Hearth" to the channel and shows whether the provider
accepted it. The test goes through policy as `notify.test` and is in the audit log.

The API behind it:

```
GET  /api/v1/notify/channels               {"channels": [{"name": "phone", "type": "ntfy"}]}
POST /api/v1/notify/channels/{name}/test   204, or 404 no such channel, or 502 with the reason
```
