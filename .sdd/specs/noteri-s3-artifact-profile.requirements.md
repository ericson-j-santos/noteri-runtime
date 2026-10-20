# Noteri S3 artifact dependency profile

## Objective

Prove on the physical Noteri runner, without storage credentials, that the
minimal S3 artifact dependency profile from the Engineering Worker Pool can be
installed from binary wheels and imported in a temporary environment outside
the Git worktree.

## Requirements

1. The physical job runs only on `[self-hosted, Windows, X64, noteri, reqsys-dev]`.
2. Pull requests, including forks, run hosted contract tests only. Physical
   execution is limited to an owner push on the dedicated feature prefix or an
   explicit owner workflow dispatch.
3. Runtime, canonical rules and Worker Pool sources use full immutable commit
   identifiers. The hosted route builds a minimal transient Gateway artifact
   from the pinned rules checkout after checking the canonical manifest. The
   physical route binds that artifact to the same repository, runtime SHA, run
   and attempt and revalidates every file hash/size, avoiding a second rules
   checkout and any assumption about the host's persistent Gateway. All
   checkouts disable persisted credentials.
4. The physical entrypoint requires Session Launcher, runner-version preflight
   and Command Gateway. A blocked gate has no shell fallback.
5. The Worker Pool requirement is downloaded from the exact pinned commit and
   must equal `boto3==1.43.115` byte for byte.
6. Installation disables pip configuration files, uses only the explicit public
   PyPI index, and passes `--isolated`, `--only-binary=:all:`, `--no-input`,
   `--keyring-provider=disabled`, `--no-compile` and `--no-cache-dir`. A missing
   compatible wheel blocks instead of starting a native build, and the result
   does not depend on a machine-local or Codex artifact cache. The Python
   interpreter itself runs with `-I -B` and receives no inherited `PYTHON*`
   configuration.
7. The temporary environment lives under the governed
   `C:\dev\chatgpt-workers` namespace but outside every Git worktree, and is
   removed before success is recorded.
8. A separate isolated Python process imports `boto3` and `botocore` from that
   environment and rejects native extensions or fallback to global packages.
9. The probe never requests credentials, creates an S3 client, accesses storage,
   starts the Worker Pool or executes a task.
10. Evidence is bounded, atomic, redacted and bound to host, runtime SHA, rules
    SHA, Worker Pool SHA and correlation ID. It is read back through the Gateway.
11. Success qualifies only the dependency profile. It keeps
    `transport_ready=false` and does not prove a complete worker, credential
    delivery, S3 connectivity or task continuity.

## Acceptance

- Hosted positive and negative tests pass on the exact runtime SHA.
- The physical job is picked up by the Noteri runner and the governed
  qualification step succeeds on that same SHA.
- The uploaded receipt passed governed readback and contains no secret or
  absolute private path.
- If pickup or an external dependency is unavailable, the increment remains
  partially validated and no host is marked ready.
