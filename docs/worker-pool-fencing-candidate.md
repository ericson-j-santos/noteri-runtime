# Candidate-only: sink-side fencing before Noteri Worker Pool maintenance

Issue: [Noteri #42](https://github.com/ericson-j-santos/noteri-runtime/issues/42), related to [Rules #217](https://github.com/ericson-j-santos/chatgpt-operational-rules/issues/217).

Base source: `noteri-runtime@fd07d0742ad345efe934c7b800145765aaba6462` (historical, 67 commits behind `main` at inspection). This candidate **does not preserve the previously authorised code SHA**. It is not eligible for direct installation, release, merge, or maintenance.

## Exact destination contract

The unchanged **Risk2** target is `\\Automation\\NoteriWorkerPoolApi`; the existing confirmation and `NOTERI_POOL_MAINTENANCE_APPROVED_SHA` are still mandatory. The new `apply()` guard reads from the fixed Windows Known Folder `LocalAppData/ReqSys/CommandGateway/noteri-worker-pool-fencing` and confirms:

- `counter.json`: current positive, monotonic `sequence` with canonical SHA-256, task and exact host.
- `active.claim`: matching `sequence`, one-time `nonce`, `session_id`, `correlation_id`, `snapshot_sha256`, fixed target, Noteri host and PID of the **parent Gateway process**.
- Windows OS Known Folder `LocalAppData`; an injected environment path cannot redirect the reader.
- Regular files only, no symlink/junction or hardlink, bounded size, duplicated JSON keys rejected, stable descriptor/file identity on read.

The environment fields are merely *selectors*, never accepted as authority:
`NOTERI_POOL_MAINTENANCE_FENCE_SEQUENCE`, `..._NONCE`, `NOTERI_POOL_MAINTENANCE_SESSION_ID`, `..._CORRELATION_ID` and `..._SNAPSHOT_SHA256`.

All values must match the persistent state from the Gateway; missing, mismatched or corrupt state **blocks before backup/stop**. The guard rechecks immediately before stop, quarantine, runner replacement and task start. It does not mutate Gateway state or perform the maintenance on its own.

## Still blocked

1. The Gateway must **not** populate these environment fields until verified session and Gateway lock, real risk-specific approval, reliable zero-incremental-cost evidence, authorised provisioned counter, readback and destination-compatible SHA. Its current Risk2 branch remains fail-closed (no automatic token issuance/child activation).
2. The local counter is **not** a cross-host lease. Full failover requires a central authoritative owner/fencing enforcement in the destination, host identity, deterministic recovery of ambiguous claims, and proof that stale tokens are rejected by the actual service/task. A copied local state file and source hash alone do not satisfy that requirement.
3. A new exact code SHA requires renewed, explicit approval, upgrade/backup/rollback, verified installed Gateway version, independent Validator, tests/CI on that same SHA, and physical readback. No service, credential, task, policy or host change is implied by this candidate.

## Isolated verification

`python -m unittest -v tests.test_noteri_worker_pool_fence_sink` — 14 filesystem tests, including valid proof, missing selectors, wrong host/process, stale sequence, digest changes, forged nonce, duplicates, symlinks and oversized evidence. These can run on POSIX with OS identity mocked, but Windows native and whole-service E2E remain required.

The original maintenance tests use explicit synthetic fence fixtures; this never changes the deployed `require_fence()` gate. Noteri host must remain unchanged while CI/readback and authorisation are missing.

**Safety:** no automatic release of `active.claim`, reset of `counter.json`, deploy, dispatch, approval or task stop. Cost incremental authorised limit R$ 0.00.