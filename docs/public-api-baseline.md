# Public API baseline

PolicySharp can treat a project's public/protected API as an explicit allowlist through `PolicySharp.PublicAPI.txt`.

When the baseline file is present:

- a new public/protected symbol that is not listed is denied with `PSHARP3001`;
- a listed symbol that disappears or changes signature is denied with `PSHARP3002`;
- no Git history is required at analyzer runtime.

## Approval workflow

The baseline is part of the policy trust boundary. It is not an agent-owned generated file.

To intentionally change the public API:

1. change the implementation;
2. review the resulting `PSHARP3001` / `PSHARP3002` diagnostics;
3. update `PolicySharp.PublicAPI.txt` in the same or a dedicated policy-change PR;
4. have a human review the API change and apply the `policy-approved` label;
5. require the Policy integrity status check before merge.

Coding agents should not update the baseline merely to make a build pass.
