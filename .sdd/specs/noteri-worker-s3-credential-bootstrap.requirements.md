# Noteri Worker S3 credential bootstrap

## Objective

Provision one technical S3 credential for the physical Noteri Worker Pool
identity without placing plaintext in Git, command arguments, environment
variables, logs or evidence.

## Requirements

1. The bootstrap is valid only on Windows host `Noteri` and accepts credential
   material only from a non-interactive stdin pipe after an exact confirmation.
   It rejects TTY input, duplicate JSON keys, unknown fields and oversized or
   malformed input.
2. The credential envelope contains only the required schema and access/secret
   values, plus an optional session token. No credential value appears in a
   representation, result, reason, log or exception emitted by the component.
3. At rest the canonical envelope is protected by Windows DPAPI in CurrentUser
   scope with `CRYPTPROTECT_UI_FORBIDDEN`; machine scope and custom key files are
   forbidden.
4. The protected file lives below
   `%LOCALAPPDATA%\ReqSys\EngineeringWorkerPool\protected-credentials`, outside
   every Git checkout. Symlinks, reparse points and multiply linked files fail
   closed.
5. The protected directory, pending file and final file have a protected DACL
   containing exactly the current process-token identity and SYSTEM. The owner
   and DACL are read back through Windows APIs before any decryption is trusted.
6. Installation uses an exclusive pending file, flushes it, applies and checks
   its ACL, decrypts and compares a staged readback, and then performs a
   create-only atomic publication. It refuses to replace an existing target and
   independently decrypts and compares the committed file.
7. Runtime use constructs one boto3 S3 client with explicit credential keyword
   arguments, TLS verification, SigV4, path-style addressing, a single bounded
   attempt and configured endpoint overrides disabled. It never exports or
   mutates `AWS_*` variables and always closes the client.
8. Bucket, region, HTTPS endpoint and key prefix are strictly validated. User
   info, query strings, fragments, endpoint paths and traversal segments are
   rejected.
9. The component does not create a cloud credential, install a Scheduled Task,
   start a worker or claim that an S4U identity can decrypt the file.

## Acceptance

- Hosted tests prove strict stdin parsing, redaction, atomic no-overwrite
  behavior, protected readback, tamper rejection, ACL-before-decrypt ordering,
  explicit boto3 construction and unchanged `AWS_*` state without using a real
  credential.
- A later governed physical procedure provisions a least-privilege credential
  under the exact Noteri execution identity and proves `status` under that same
  identity.
- Until that physical proof succeeds, credential availability and S4U identity
  compatibility remain blocked and the host is not storage-ready.
