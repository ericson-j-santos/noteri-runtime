# Noteri DEV — SQL Server 2025 ERRORLOG administrative read

Status: **staged; not installed, not dispatched, and not a production-ready capability**. Tracks noteri-runtime issue #36 and report-builder-platform issue #7.

## Scope

The program scripts/noteri_sql_admin_errorlog_read.py classifies certificate startup messages from the already implemented scripts/noteri_sql_certificate_errorlog.py. It refuses other hosts, non-Windows systems, environments other than DEV, non-administrative identity, incorrect source SHA, incorrect confirmation, mismatched metadata, an unverified SQL startup -e parameter, and any extra/unsafe output fields. It has no custom path, SQL, command, registry key, or output destination input.

The existing reader restricts its registry reads to MSSQL17.MSSQLSERVER, verifies an actually running SQL Server 2025 service and NORMAL profile, bounds ERRORLOG reads to 8 MiB, rejects reparse points, and classifies messages without returning raw lines, credentials, identities, certificate thumbprints, or paths. This wrapper will NOT treat the setup-derived fallback as proof of the configured startup parameter.

## Critical security gate before use

The present elevated admin actuator installer writes code and a dispatcher under LOCALAPPDATA. Do not add this capability to that existing scheduled task, or execute newly downloaded code elevated, unless a reviewed update proves the binary/code bytes, SHA, administrative-only ACL of the installed path, and the allowed request contract. The entrypoint itself never elevates, changes permissions, creates scheduled tasks, or installs anything. Its fixed confirmation literal is not authorization by itself.

A governed one-shot actuator must bind Noteri DEV, the reviewed full SHA, a unique correlation ID and idempotency key, a protected installation path, confirmation of caller authorization, and a readback from a separate process. Require SESSION_LAUNCH_OK and Command Gateway readiness, fail closed if the administrative control-plane path is absent, and never substitute GUI, unrestricted shell, or weakening TLS.

## Evidence and limitations

CI tests use an injected collector; they test positive, negative, blocked, deterministic replay, strict output and no writes but are not a physical SQL test. Even a positive ERRORLOG message does NOT verify an active SQL certificate, correct TLS trust chain, live ODBC session, current service process generation, actual Report Builder read-only permissions, or Fabric delivery. These remain separate physical E2E gates.

After a verified administrative read, validate ODBC Driver 18 with Encrypt=Yes and TrustServerCertificate=No and approved DEV identity/DSN, then SQL preflight and independent gateway/Fabric render/export/readback. No changes to SQL Server, certificate, permissions, DSN, production or CU installation are authorized by this PR.
