## Summary

<!-- What changed and why (user-visible behavior first). -->

## Test plan

- [ ] `npm test` passes (CI: Node 20/22/24)
- [ ] New/changed tool has a test covering the happy path and input rejection
- [ ] Docs updated (`docs/tools.md`, README tool table if headline)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## Safety checklist

- [ ] No tool gains network access, target execution, attach/injection, or command execution
- [ ] Authorized-target gates are intact and still reject blank declarations
- [ ] `brief` red lines are not weakened
- [ ] Artifact-writing tools are flagged in `WRITES_ARTIFACTS` (honest annotations)
- [ ] No secrets or real engagement data in the diff
