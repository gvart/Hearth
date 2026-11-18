# Automations

An automation is a YAML file in the hub's automations directory: `<data-dir>/automations` by default,
or `hearth hub --automations-dir DIR`. Every `*.yaml` and `*.yml` file in it (not in subdirectories)
is one automation. Keep the directory in git.

```yaml
id: hello                  # lowercase letters, digits, - and _; unique across files
description: Say hello.    # optional
mode: single               # single (default), queued or restart
triggers:                  # any of these starts a run
  - id: by-hand            # step ids are optional: the default is <type>-<position>
    type: manual
conditions: []             # optional: all must hold, or the run is skipped
actions:                   # run in order; the first failure or policy denial ends the run
  - id: greet
    type: log
    description: write a line to the hub log
    message: hello from Hearth
```

`mode` says what happens when a trigger fires while a run is in progress: `single` ignores it,
`queued` runs it afterwards (at most 10 waiting), `restart` cancels the current run and starts again.

Built in so far: the `manual` trigger and the `log` action. More triggers and actions come with
their own issues.

## Checking a file

```sh
hearth automation plan automations/hello.yaml
```

validates the file and prints what the automation would do, without running anything. Problems are
reported with their line, as `file:line: message`.

## How the hub runs them

- The hub checks the directory every 2 s. A new or changed file is loaded; a changed automation
  is stopped (its run in progress cancelled) and started again; a removed one is stopped. If any
  file is invalid, the reload is refused as a whole and logged, and the automations already running
  carry on.
- In a cluster, automations run on the leader only, and move with leadership. Each hub reads its own
  directory, so keep it the same on every hub.
- Every action goes through policy with actor `automation/<id>`, and is in the audit log.
- Runs are kept in the run history (the newest 100 per automation):

  ```sh
  hearth automation runs [automation-id]
  ```

  After a rolling upgrade, runs are recorded once `hearth cluster migrate` brings the cluster to
  schema 7.
