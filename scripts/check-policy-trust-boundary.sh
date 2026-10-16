#!/usr/bin/env bash
set -euo pipefail

base_ref="${1:-origin/main}"
head_ref="${2:-HEAD}"
protected_file=".policysharp/protected-paths.txt"

if [[ ! -f "$protected_file" ]]; then
  echo "PolicySharp trust-boundary manifest is missing: $protected_file" >&2
  exit 2
fi

mapfile -t patterns < <(grep -Ev '^[[:space:]]*(#|$)' "$protected_file")

changed_files="$(git diff --name-only "$base_ref...$head_ref")"
violations=()

while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  for pattern in "${patterns[@]}"; do
    if [[ "$file" == $pattern ]]; then
      violations+=("$file")
      break
    fi
  done
done <<< "$changed_files"

if (( ${#violations[@]} == 0 )); then
  echo "No protected PolicySharp trust-boundary files changed."
  exit 0
fi

printf 'Protected PolicySharp files changed:\n' >&2
printf ' - %s\n' "${violations[@]}" >&2

if [[ "${POLICY_APPROVED:-false}" == "true" &&
      "${POLICY_INDEPENDENT_APPROVED:-false}" == "true" ]]; then
  echo "Protected changes approved by an independent, authorized reviewer."
  exit 0
fi

echo "Protected changes require the 'policy-approved' label AND an independent" >&2
echo "authorized reviewer approval on the current PR head commit." >&2
echo "Owner self-approval or a label alone must not bypass this boundary." >&2
exit 1
