# Noteri Worker S3 physical preflight

`scripts/noteri_worker_s3_preflight.py` connects the Noteri protected credential
boundary to the already shared Worker Pool S3 transport. It imports
`S3ArtifactConfig` and `S3GitBundleArtifactTransport` only from an exact clean
Worker Pool checkout; no S3 artifact protocol is copied into this runtime.

## Inputs and checks

The `run` operation requires exact runtime and Worker Pool commit and tree
identifiers, the physical Worker Pool checkout, a correlation ID, the
non-secret S3 route and an absolute evidence path outside both Git roots.

Both checkouts are verified before the request and after its result:

- physical repository top level;
- exact HEAD and `HEAD^{tree}`;
- no tracked, untracked or ignored files;
- no skip-worktree or assume-unchanged entries;
- no reparse point in either verified path.

The credential component creates one explicit boto3 client. The shared
transport performs its conditional write and exact readback preflight. The
wrapper checks that `AWS_*` state is byte-for-byte unchanged and emits only a
SHA-256 binding of bucket, region, endpoint and prefix.

## Independent readback

After `run` succeeds, invoke `readback` as a separate isolated Python process
with exactly the same arguments and evidence path. Readback makes no credential
or storage request. It requires canonical, exact evidence and rechecks both Git
identities before and after reading. Its stdout receipt contains the evidence
SHA-256 and no raw route value.

Both invocations must run through the canonical Noteri Session Launcher and
Command Gateway integration. This increment deliberately adds no competing
workflow or embedded rules bundle, so it can be wired to the transient
canonical bundle being established for the existing Noteri S3 profile work.

## Remaining physical gate

Repository tests use synthetic credentials, clients and transport doubles. A
host is not ready until a governed Noteri execution has all of the following on
the same committed runtime tree:

1. a least-privilege credential provisioned directly to stdin under the actual
   worker/S4U execution identity;
2. successful protected-store `status` under that identity;
3. successful shared transport preflight against the approved private route;
4. a separate successful evidence readback;
5. negative controls showing that dirty/index/evidence changes are rejected.

The preflight never starts the Worker Pool or executes a task.
