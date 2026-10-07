# Policy trust boundary

PolicySharp treats policy and enforcement configuration as part of the repository trust boundary.

A coding agent should repair code so that it complies with the active policy. It must not silently broaden its own permissions by modifying the policy, analyzer wiring, public API baselines, or integrity checks.

## Protected paths

The canonical protected-path list lives in `.policysharp/protected-paths.txt`.

Typical protected inputs include:

- `policysharp.json`
- `Directory.Build.props`
- project files that install or configure PolicySharp
- `schema/policysharp.schema.json`
- public API baselines
- PolicySharp integrity workflows and scripts

## Approval model

Changes to protected paths are proposals, not automatically trusted policy changes.

For pull requests, `.github/workflows/policy-integrity.yml` fails when a protected path changes unless the pull request has the `policy-approved` label.

The label is deliberately outside the source diff. This means an agent cannot satisfy the gate merely by editing repository files in the same change.

Repository administrators should restrict who can apply the label and should make the Policy integrity check a required status check on protected branches.

## Agent behavior

Agents should:

1. treat protected paths as read-only unless a human explicitly asks for a policy change;
2. repair implementation code first;
3. surface a policy change as a separate proposal when the existing policy is genuinely insufficient;
4. never weaken policy merely to make a build pass.

PolicySharp diagnostics reinforce this by recommending compliant abstractions rather than policy broadening.
