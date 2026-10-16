#!/usr/bin/env bash
# A real SDK-generated-assembly-metadata consumer integration fixture.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/packages" "$work/consumer"
dotnet restore "$repo_root/PolicySharp.sln"
dotnet build "$repo_root/PolicySharp.sln" --configuration Release --no-restore
dotnet pack "$repo_root/src/PolicySharp.Analyzers/PolicySharp.Analyzers.csproj" \
  --configuration Release --no-build --output "$work/packages"
shopt -s nullglob
packages=("$work/packages"/loach.PolicySharp.Analyzers.*.nupkg)
shopt -u nullglob
[[ "${#packages[@]}" == 1 ]] || { echo "expected exactly one NuGet package" >&2; exit 2; }
pkg="$(basename "${packages[0]}")"
version="${pkg#loach.PolicySharp.Analyzers.}"
version="${version%.nupkg}"

cat > "$work/consumer/Consumer.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
<ItemGroup><PackageReference Include="loach.PolicySharp.Analyzers" Version="$version" /></ItemGroup>
</Project>
EOF
cat > "$work/consumer/NuGet.Config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear/>
<add key="local" value="$work/packages"/>
<add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3"/>
</packageSources></configuration>
EOF
cp "$repo_root/samples/policysharp.json" "$work/consumer/policysharp.json"
cat > "$work/consumer/Example.cs" <<'EOF'
namespace Sample.Domain;
public static class Example
{
    public static int Identity(int value) => value;
}
EOF
dotnet restore "$work/consumer/Consumer.csproj" --configfile "$work/consumer/NuGet.Config"
# The SDK's GenerateAssemblyInfo and GenerateTargetFrameworkAttribute remain at defaults.
dotnet build "$work/consumer/Consumer.csproj" --no-restore -v:m > "$work/green.log" 2>&1 ||
  { cat "$work/green.log"; echo "unexpected SDK-generated metadata policy violation" >&2; exit 1; }
if grep -q 'PSHARP2002' "$work/green.log"; then
  cat "$work/green.log"
  echo "SDK metadata still triggers PSHARP2002" >&2
  exit 1
fi

# Deliberately hand-written assembly metadata must not get a broad exemption.
cat > "$work/consumer/UserAssembly.cs" <<'EOF'
[assembly: System.Reflection.AssemblyDelaySignAttribute(true)]
EOF
set +e
dotnet build "$work/consumer/Consumer.csproj" --no-restore -v:m > "$work/red.log" 2>&1
exit_code=$?
set -e
if [[ "$exit_code" -eq 0 ]] || ! grep -q 'PSHARP2002' "$work/red.log"; then
  cat "$work/red.log"
  echo "handwritten assembly attribute bypassed policy" >&2
  exit 1
fi
echo "Verified SDK metadata success, handmade global assembly attribute denied."
