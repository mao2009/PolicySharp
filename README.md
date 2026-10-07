# PolicySharp

**Compile-time architectural guardrails for humans and AI coding agents.**

PolicySharp is a Roslyn-based policy engine for .NET codebases. Instead of merely reporting architectural drift after the fact, it aims to make forbidden code difficult—or impossible—to introduce.

The core idea is simple:

> Put the project's architectural rules in version control, then enforce them during editing, build, test, CI, and AI-assisted development.

## Goals

PolicySharp is intended to enforce policies such as:

- forbidden project or namespace dependencies
- forbidden API usage
- restricted type access
- public API growth restrictions
- architectural layer boundaries
- capability restrictions such as file system, network, process execution, or database writes
- AI-friendly diagnostics that explain both the violation and the allowed path

Example diagnostic:

```text
PSHARP1001: UI code may not access AppDbContext directly.

Allowed path:
OrderViewModel -> IOrderService -> IOrderRepository -> AppDbContext

Suggested fix:
Inject IOrderService instead.
```

## Proposed policy format

```yaml
version: 1

rules:
  - id: no-ui-dbcontext
    kind: forbid-type
    from: "MyApp.UI.**"
    target: "Microsoft.EntityFrameworkCore.DbContext"
    message: "UI code must access persistence through an application service."

  - id: no-domain-infrastructure
    kind: forbid-dependency
    from: "MyApp.Domain.**"
    target: "MyApp.Infrastructure.**"

  - id: no-process-start
    kind: forbid-api
    symbol: "System.Diagnostics.Process.Start"
```

The exact schema is intentionally not stable yet. The first milestone is to establish the Roslyn enforcement pipeline and then evolve the policy model from real use cases.

## Initial architecture

```text
PolicySharp
├─ PolicySharp.Analyzers   Roslyn analyzers and diagnostics
├─ PolicySharp.Core        policy model and rule evaluation
├─ PolicySharp.Tests       analyzer and policy tests
└─ samples                 example policies and violating/fixed code
```

## Status

Early development.

The first MVP targets:

1. forbidden API rules
2. forbidden namespace/type dependency rules
3. policy loading
4. deterministic compiler diagnostics
5. diagnostics written so coding agents can self-correct

## License

MIT
