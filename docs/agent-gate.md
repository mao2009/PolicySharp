# Transactional Agent Gate

The Agent Gate is PolicySharp's write barrier for coding agents.

Instead of allowing an agent to modify trusted source code and checking afterward, the agent produces a Git patch and asks PolicySharp to validate it:

```text
untrusted agent
      |
      v
 proposed.patch
      |
      v
isolated Git worktree
      |
      +-- protected-path check
      +-- Docker/Podman sandbox
      |    +-- dotnet restore
      |    +-- PolicySharp check (--network none)
      |    +-- dotnet build --no-restore (--network none)
      |
      v
revalidate HEAD + working tree + patch + policy fingerprints
      |
 ALLOW +-----------------> git apply to trusted working tree
 DENY  +-----------------> discard isolated worktree
```

## Trust assumptions

The AI agent and its patch are untrusted. The active policy, PolicySharp enforcement implementation, and external human approval are trusted.

The repository's `.policysharp/protected-paths.txt` defines files that a patch cannot change without external approval. PolicySharp's own Core, Analyzer, and CLI implementation are protected in this repository so an agent cannot weaken the gate as part of the same patch.

## Fail closed

The gate returns DENY when any of the following occurs:

- the patch is invalid or does not apply to the current base;
- the trusted working tree is dirty;
- the policy/trust-boundary manifest is missing;
- a protected file changes without external approval;
- PolicySharp reports a policy violation or configuration error;
- the isolated patched solution does not compile;
- the repository HEAD, working-tree fingerprint, policy fingerprint, or patch hash changes after validation;
- the final patch check cannot be reproduced.

UNKNOWN policy decisions remain DENY through the normal PolicySharp decision engine.

## TOCTOU protection

The gate records:

- base commit SHA;
- clean working-tree fingerprint;
- patch SHA-256;
- base policy SHA-256;
- validated policy SHA-256;
- PolicySharp version;
- affected files;
- evaluated projects.

Immediately before applying the patch, the gate recomputes the trusted repository state and refuses to continue if it differs from the state that was validated.

## External approval

A patch cannot approve itself.

Protected changes require `POLICY_APPROVED=true` in the gate process environment. Agent integrations should only set this after an independent human approval step.

## Agent workflow

An agent integration should make the gate the only approved source-write path:

```text
1. Generate proposed.patch.
2. Run: policysharp gate apply proposed.patch MySolution.sln
3. If decision=ALLOW, continue with the now-applied change.
4. If decision=DENY, modify the proposed implementation and generate a new patch.
5. Do not modify policy to silence a denial unless a human explicitly requested a policy change.
```

## Validation sandbox

Default Agent Gate validation requires Docker or Podman. The patched temporary worktree is the only repository tree mounted into the validation container. The trusted working tree is never mounted.

Restore runs in the container with its normal container network so NuGet packages can be acquired. PolicySharp check and build then run in new containers with `--network none` and reuse the restored package cache from the isolated worktree.

The PolicySharp tool directory is mounted read-only at `/policysharp/tool`.

Environment controls:

- `POLICYSHARP_SANDBOX_BACKEND=docker|podman` forces a backend. If unavailable, validation fails closed.
- `POLICYSHARP_SANDBOX_IMAGE=<image>` overrides the default `mcr.microsoft.com/dotnet/sdk:8.0`.

There is intentionally no automatic host-execution fallback.

## Limits

The container sandbox prevents patched MSBuild from executing directly on the host, but it is not a general-purpose malware sandbox. Agent hosts should still restrict direct filesystem/process access so the Gate remains the approved source-write path.
