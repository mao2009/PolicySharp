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
