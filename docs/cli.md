# PolicySharp CLI

PolicySharp ships a preflight command intended for local development, CI, and coding agents.

```bash
policysharp check MySolution.sln
policysharp check src/MyProject/MyProject.csproj
```

The command loads the target with Roslyn/MSBuild, discovers PolicySharp analyzers from the installed analyzer assembly, loads PolicySharp additional files, and executes the same analyzer logic used during compilation.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | All evaluated policy checks allowed |
| 1 | One or more policy decisions were denied |
| 2 | Policy/configuration/workspace loading error |
| 64 | Invalid CLI usage |

Unknown or ambiguous policy decisions are emitted as denied diagnostics by the analyzers and therefore produce exit code 1.

Missing or invalid `policysharp.json` produces exit code 2.

## Output

Diagnostics use a stable pipe-delimited form:

```text
DENY|Project|PSHARP2001|File.cs:12:9|message|policysharp.decision=DENIED;...
CONFIG|Project|PSHARP0001|<none>|message|
```

Backslashes, pipes, and newlines are escaped so coding agents can parse one diagnostic per line.

The CLI never edits or broadens policy.

## Transactional agent gate

Use the gate when an AI agent should not write directly into the trusted working tree:

```bash
policysharp gate apply proposed.patch MySolution.sln
```

The gate validates the patch in an isolated Git worktree, runs PolicySharp and `dotnet build`, rechecks the repository state, and only then applies the exact validated patch.

A protected policy/enforcement change requires approval supplied outside the patch:

```bash
POLICY_APPROVED=true policysharp gate apply proposed.patch MySolution.sln
```

The gate emits a JSON decision report. Exit code `0` means the validated patch was applied, `1` means DENY, and `2` means a configuration/repository precondition failed.

For v1, the trusted working tree must be clean before validation. The patch file itself may be an untracked file inside the repository.
