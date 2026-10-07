# PolicySharp

**Allow by policy. Deny by default.**

PolicySharp is a Roslyn-based policy engine for .NET codebases, designed to constrain both humans and AI coding agents at compile time.

The core rule is intentionally strict:

> Code may only depend on APIs, namespaces, packages, and capabilities that the active policy explicitly allows. Unknown or ambiguous access is denied.

This is the opposite of a traditional blacklist. PolicySharp is intended to make architectural escape routes fail closed.

## Why allowlists?

A denylist only blocks violations the policy author anticipated. New APIs, new packages, alternate call paths, or agent-generated workarounds may pass unnoticed.

PolicySharp instead uses a default-deny model:

```text
explicitly allowed      -> ALLOW
explicitly denied       -> DENY
unknown / ambiguous     -> DENY
```

Explicit deny rules may still be useful as narrow exceptions inside a broad allow rule, but they are not the primary security model.

## Example policy

The initial schema uses JSON so it can be consumed directly as a Roslyn AdditionalFile.

```json
{
  "version": 1,
  "mode": "default-deny",
  "scopes": [
    {
      "id": "domain",
      "match": {
        "namespace": "MyApp.Domain.**"
      },
      "allow": {
        "namespaces": [
          "System",
          "System.Collections.Generic",
          "System.Threading",
          "System.Threading.Tasks",
          "MyApp.Domain.**"
        ]
      },
      "deny": {
        "namespaces": [
          "System.Diagnostics",
          "System.Reflection.Emit"
        ]
      }
    }
  ]
}
```

With that policy, an unlisted dependency such as `System.Net.Http`, an Infrastructure namespace, or a newly added SDK is rejected even though nobody remembered to put it on a blacklist.

## AI-oriented diagnostics

Diagnostics should explain how to self-correct without suggesting that the policy itself be weakened.

```text
PSHARP2001: Dependency is not allowed by the active scope.

Scope: domain
Source: MyApp.Domain.Orders
Target: System.Net.Http
Decision: DENIED
Reason: target namespace is not present in the scope allowlist

Suggested action:
Use an already-approved abstraction from an allowed namespace.
Do not modify policysharp.json automatically.
```

## Direction

PolicySharp will evolve around three allowlist layers:

1. dependency allowlists — projects/namespaces a scope may reference
2. capability allowlists — effects such as network, file system, database writes, process execution
3. symbol allowlists — types/members that are explicitly approved

The long-term goal is that a coding agent can ask "is this change permitted?" and receive a deterministic compiler/CLI answer before the change is accepted.

## Policy protection

The policy is part of the trust boundary. An agent must not be able to bypass enforcement simply by broadening its own permissions.

PolicySharp therefore treats policy mutation as an explicit approval workflow. Repository-level tooling should protect files such as:

```text
policysharp.json
Directory.Build.props
*.csproj
```

The analyzer enforces code semantics; repository/agent tooling enforces who may change the policy. The transactional Agent Gate validates proposed patches in an isolated Git worktree. Host-native validation is the default, while Docker/Podman remain optional explicit isolation backends.

## Initial architecture

```text
PolicySharp
├─ PolicySharp.Analyzers   Roslyn enforcement and diagnostics
├─ PolicySharp.Core        policy model and decision engine
├─ PolicySharp.Tests       policy/analyzer tests
└─ samples                 policies and compliant/violating examples
```

## MVP

The first milestone targets:

1. default-deny policy evaluation
2. namespace dependency allowlists
3. explicit deny exceptions
4. deterministic fail-closed behavior
5. analyzer integration tests
6. AI-remediation-friendly diagnostics
7. policy schema validation
8. CLI preflight using the same decision engine

## License

MIT
