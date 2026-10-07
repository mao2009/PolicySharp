; Unshipped analyzer release tracking
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|------
PSHARP0001 | Configuration | Error | Invalid policy file
PSHARP0002 | Configuration | Error | Missing policy file
PSHARP2001 | Architecture | Error | Dependency not explicitly allowed
PSHARP2002 | Architecture | Error | Source namespace not covered by a scope

PSHARP2101 | Architecture | Error | Symbol is not permitted by active symbol allowlist

PSHARP3001 | ApiSurface | Error | Public/protected API is not approved by baseline
PSHARP3002 | ApiSurface | Error | Approved public API is missing or changed

PSHARP2201 | Capabilities | Error | Required capability is not explicitly allowed
PSHARP2202 | Capabilities | Error | Sensitive API could not be classified safely
