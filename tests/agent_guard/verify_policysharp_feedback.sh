#!/usr/bin/env bash
# End-to-end: actual PolicySharp NuGet analyzer + CLI + compiler.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/packages" "$work/consumer"

dotnet restore "$repo_root/PolicySharp.sln"
dotnet build "$repo_root/PolicySharp.sln" --no-restore
dotnet pack "$repo_root/src/PolicySharp.Analyzers/PolicySharp.Analyzers.csproj" --no-build \
  --output "$work/packages"
cli="$repo_root/src/PolicySharp.Cli/bin/Debug/net8.0/PolicySharp.Cli.dll"
[[ -f "$cli" ]] || { echo "Expected PolicySharp CLI DLL not found: $cli" >&2; exit 2; }
shopt -s nullglob
packages=("$work/packages"/loach.PolicySharp.Analyzers.*.nupkg)
shopt -u nullglob
[[ "${#packages[@]}" -eq 1 ]] || { echo "Expected exactly one analyzer package" >&2; exit 2; }
name="$(basename "${packages[0]}")"
version="${name#loach.PolicySharp.Analyzers.}"
version="${version%.nupkg}"

cat >"$work/consumer/Consumer.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
<ItemGroup><PackageReference Include="loach.PolicySharp.Analyzers" Version="$version" /></ItemGroup>
</Project>
EOF
cat >"$work/consumer/NuGet.Config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear/>
<add key="local" value="$work/packages"/>
<add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3"/>
</packageSources></configuration>
EOF
cp "$repo_root/samples/policysharp.json" "$work/consumer/policysharp.json"
cat >"$work/consumer/Example.cs" <<'EOF'
namespace Sample.Domain;
public static class Example
{
    public static System.Net.Http.HttpClient Make() => new();
}
EOF

dotnet restore "$work/consumer/Consumer.csproj" --configfile "$work/consumer/NuGet.Config"
run_feedback() {
  python "$repo_root/scripts/agent_diagnostic_feedback.py" \
    --root "$work/consumer" --project Consumer.csproj --backend policysharp \
    --policysharp-cli "$cli" --strict >"$work/result.json"
}
set +e
run_feedback
denied=$?
set -e
[[ $denied -eq 1 ]] || { cat "$work/result.json"; echo "Forbidden dependency must fail" >&2; exit 1; }
python - "$work/result.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["status"] == "DENY" and any(
    d["id"] == "PSHARP2001" for d in x["diagnostics"]), x
PY

cat >"$work/consumer/.editorconfig" <<'EOF'
root = true
[*.cs]
dotnet_diagnostic.PSHARP2001.severity = none
EOF
set +e
run_feedback
suppressed=$?
set -e
[[ $suppressed -eq 1 ]] || { cat "$work/result.json"; echo "Suppression must not succeed" >&2; exit 1; }
python - "$work/result.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["status"] == "DENY" and any(
    f["kind"] == "severity-override" for f in x.get("auditFindings", [])), x
PY
rm "$work/consumer/.editorconfig"

cat >"$work/consumer/Example.cs" <<'EOF'
namespace Sample.Domain;
public static class Example
{
    public static int Identity(int value) => value;
}
EOF
run_feedback
python - "$work/result.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["status"] == "ALLOW", x
PY

# A genuine compiler error cannot be accepted merely because policy JSON is clean.
cat >"$work/consumer/Example.cs" <<'EOF'
namespace Sample.Domain;
public static class Example
{
    public static int Identity(int value) => value
}
EOF
set +e
run_feedback
syntax=$?
set -e
[[ $syntax -eq 1 ]] || { cat "$work/result.json"; echo "C# syntax error must be denied" >&2; exit 1; }
python - "$work/result.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["status"] == "DENY" and any(
    d["id"] == "CS1002" for d in x["diagnostics"]), x
PY

# Restore source; deleting the analyzer reference must be rejected BEFORE build.
cat >"$work/consumer/Example.cs" <<'EOF'
namespace Sample.Domain;
public static class Example
{
    public static int Identity(int value) => value;
}
EOF
python - "$work/consumer/Consumer.csproj" <<'PY'
import pathlib,re,sys
p=pathlib.Path(sys.argv[1])
s,n=re.subn(r'<PackageReference\s+Include="loach\.PolicySharp\.Analyzers"[^>]*/>', "", p.read_text(), count=1)
assert n == 1
p.write_text(s)
PY
set +e
run_feedback
removed=$?
set -e
[[ $removed -eq 2 ]] || { cat "$work/result.json"; echo "Removed analyzer must fail closed" >&2; exit 1; }
python - "$work/result.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["status"] == "ERROR" and "reference not present" in x["error"], x
PY
echo "PolicySharp: real policy red, suppressed deny, fixed green, syntax red, missing analyzer error."
