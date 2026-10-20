# Noteri Worker S3 physical preflight

## Objective

Prove that the exact clean Noteri runtime and Engineering Worker Pool checkouts
can use the protected current-process credential through the shared durable S3
transport, while producing only redacted evidence outside Git.

## Requirements

1. Runtime and Worker Pool inputs use full expected commit and tree identifiers.
   Before the network effect and after it, each checkout must resolve to its
   physical top level, match both identifiers, have no tracked, untracked or
   ignored content, and have no assume-unchanged or skip-worktree index entries.
2. Git validation discards inherited `GIT_*` configuration, disables system and
   global configuration, prompts, fsmonitor and the untracked cache, and applies
   the deterministic Windows checkout conversion rule.
3. The S3 implementation is imported only from
   `app/s3_git_bundle_artifact.py` in the verified Worker Pool checkout. The
   Noteri wrapper must not duplicate the shared artifact protocol.
4. The protected credential wrapper supplies an explicit client exactly once.
   The shared transport's preflight performs the conditional create and exact
   readback contract. Missing, duplicate, wrong-route or failing callbacks block.
5. The complete `AWS_*` environment snapshot is unchanged. Any mutation is
   restored and causes a closed failure.
6. Evidence is bounded canonical JSON, written atomically to a create-only path
   outside both Git checkouts. It contains host, commit/tree identities,
   correlation ID and only a SHA-256 binding of the route; no credential or raw
   route value appears.
7. A separate readback operation reads an immutable single-link evidence file,
   requires canonical encoding and exact expected fields, revalidates both
   checkout identities before and after, and performs no credential or storage
   operation.
8. All errors collapse to a closed safe reason. A failed preflight never marks a
   worker ready and never executes a task.
9. The physical flow uses the canonical Session Launcher and Command Gateway
   bundle selected for the Noteri integration. This repository component does
   not embed or duplicate that evolving bundle.

## Acceptance

- Hosted positive and negative tests pass on the committed runtime tree without
  a real credential or network call.
- On the physical Noteri host, a governed process provisions the credential for
  the actual worker/Scheduled Task identity, then runs `run` and an independent
  `readback` process against pinned clean runtime and Worker Pool SHAs/trees.
- The redacted run evidence and readback receipt bind to the same correlation
  and identities; a deliberate dirty/index/evidence control is rejected.
- Until the physical identity, private endpoint and conditional write/readback
  succeed, this increment remains partially validated and no continuity claim
  is made.
