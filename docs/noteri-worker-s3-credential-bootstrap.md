# Noteri Worker S3 credential bootstrap

`scripts/noteri_worker_s3_credentials.py` is the host-local boundary between an
approved technical S3 credential and the shared Engineering Worker Pool. It
does not implement artifact transport and it does not create credentials.

## Security contract

- The only provisioning channel is a non-interactive stdin pipe. Credential
  values are forbidden in arguments, environment variables, temporary files,
  clipboard-driven UI and logs.
- The accepted JSON has schema version `1.0.0`, `aws_access_key_id`,
  `aws_secret_access_key` and an optional `aws_session_token`. Duplicate or
  unknown fields fail closed.
- The exact validated JSON is encrypted with CurrentUser DPAPI and UI disabled.
  The ciphertext envelope is stored at
  `%LOCALAPPDATA%\ReqSys\EngineeringWorkerPool\protected-credentials\s3-credential-v1.json`.
- The directory and file DACL contain only the current process-token SID and
  SYSTEM. ACL readback occurs before decryption.
- Publication is atomic and create-only. The command refuses an existing store;
  credential replacement requires a separately reviewed recovery/rotation
  procedure.
- Runtime callers receive an explicitly configured boto3 client. No `AWS_*`
  variable is created or changed.

## Governed use

Provisioning must be launched through the canonical Session Launcher and
Command Gateway on `Noteri`, under the exact Windows identity that will run the
worker. The approved secret broker must write the JSON directly to the child
process stdin; this document intentionally provides no command that embeds a
credential or stages plaintext.

The non-secret verification operation is:

```text
python -I -B scripts/noteri_worker_s3_credentials.py status
```

The install operation additionally requires the exact confirmation
`INSTALL-NOTERI-WORKER-S3-CREDENTIAL-V1`. Success proves decryption only for the
current process identity. It does not prove that a Scheduled Task using S4U
runs with the same usable DPAPI profile; that is a mandatory physical gate.

No credential was created or installed by the repository increment that added
this component.
