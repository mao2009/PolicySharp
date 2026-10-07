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
