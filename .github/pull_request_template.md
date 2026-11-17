<!-- Title: Conventional Commit, e.g. `feat: hub store (T4)`. -->

Implements `docs/tasks/TNN-<slug>.md`. <!-- or: Closes #<issue> -->

## What
<!-- The change in a few bullets: files/packages touched and what each does. -->
-

## Done when
<!-- Copy the task's "Done when" criteria and show how each one passes (test name, command, output). -->
- [ ]

## Decisions
<!-- Choices not covered by CLAUDE.md or the task spec: the option picked and a one-line why. Write "None" if there were none. -->
-

## Checklist
- [ ] `task test` (go test -race) passes
- [ ] `task lint` passes
- [ ] New action types declare their policy class (`read` / `safe` / `dangerous`)
- [ ] Commits are Conventional Commits and signed off (`git commit -s`)
