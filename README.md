# Agent-native Proxy Infrastructure Control Plane (P0 PoC)

This repository implements the first executable slice from `proxy-control-dev-plan-v0.1.md` without local GPU or local model dependencies. AI/BYOM is intentionally deferred to API-key backed P1 integrations.

![Proxy Control P0 Architecture](images/proxy-control-readme-architecture.png)

## What exists now

- Rust workspace with `domain`, `compiler-xray`, `runner`, `subscription`, and `control-plane` crates.
- Profile IR v0 structs and validation that rejects inline secret material.
- Content-addressed artifact metadata and blob storage using SHA-256.
- Xray compiler for VLESS + REALITY, Shadowsocks, and Trojan P0 profiles, including version-aware rejection for unsupported REALITY.
- Docker-backed real Xray smoke verifies compiled Shadowsocks output and LocalRunner apply with `xray run -test`.
- Signed runner command model with TTL, nonce replay, monotonic sequence, and node-scope validation; HTTP runner result submissions are signed by the runner and verified by the control-plane against the registered per-node public key before status is committed. Per-node runner result public keys can be rotated without re-registering the node.
- Control-plane queues signed `ApplyDeploymentPlan` commands through the storage layer after compile; runner has an outbound HTTP polling mode that can self-register with `NODE_REGISTRATION_TOKEN`, authenticates with `X-Runner-Token`, applies commands, signs deployment results, and submits them.
- Local runner apply flow: write temp config, run `xray run -test`, atomically switch `active`, optionally execute a reload/restart command and a process health command; invalid configs after a successful release return `RolledBack` and preserve the previous active release.
- Subscription artifact generation that hides revoked, expired, or quota-exceeded credentials, plus stored subscription token issue/rotate/verify and access logging.
- Minimal Axum control-plane API covering one-time-token node registration, authenticated runner heartbeat, VLESS/SS/Trojan profile and client creation, per-client quota/expiry decisions, subscription token issue/rotation, idempotent compile/deploy requests, runner command polling/result submission, deployment health sample reporting/query, multi-sample deployment readiness, rollout advance promotion/auto-rollback, raw usage sample reporting/query, hourly/daily/monthly usage rollups, audit/outbox counters, and subscription retrieval.
- Control-plane deployment evidence endpoints for rollback pointer and final deployment snapshot:
  `GET /deployments/{deployment_id}/rollback-pointer`, `GET /deployments/{deployment_id}/snapshot`,
  `GET /deployments/{deployment_id}/health`, and `GET /deployments/{deployment_id}/readiness`.
- Rollout advance via `POST /deployments/{deployment_id}/advance`, which promotes ready deployments
  and queues rollback automatically when the latest health sample is unhealthy.
- Operator-triggered rollback orchestration via `POST /deployments/{deployment_id}/rollback`,
  which queues a signed `RollbackDeployment` command for the runner.
- Runner result key rotation via `POST /nodes/{node_id}/runner-result-key/rotate`.
- `storage` crate with an async `ProxyStore` trait, in-memory repository, and Postgres/sqlx repository read/write paths for the P0 flow, including runner command queue, deployment result status updates, idempotency responses, rollback pointers, and deployment snapshots.
- Compiled config artifacts are persisted as bytes and can be retrieved with `GET /artifacts/{artifact_id}/bytes`.
- Raw usage sample storage via `usage_records`, hourly/daily/monthly aggregation into `usage_rollups`, optional `quota_bytes` and `expires_at` on `POST /clients`, quota/expiry decisions via `GET /clients/{client_id}/quota` and `GET /clients/{client_id}/expiry`, and subscription suppression for quota-exceeded or expired credentials.
- Usage endpoints: `POST /runner/nodes/{node_id}/usage`, `GET /usage/nodes/{node_id}/latest`, and `GET /usage/credentials/{credential_id}/rollups/latest?bucket=hour|day|month`.
- Next.js App Router console pages for `/dashboard`, `/nodes`, `/clients`, `/profiles`, `/deployments`, `/tasks`, `/logs`, and `/settings`; the console now uses a Vercel/Geist-style operational workbench with a React Flow topology canvas, Claude-style operator/artifact panels, and live browser actions for node registration, profile/client creation, deployment compile, evidence inspection, usage samples, and subscription retrieval.
- P0-shaped Postgres migration file plus a Docker-backed Postgres smoke test.
- One-command E2E smoke (`./scripts/e2e_smoke.sh`) starts disposable Postgres, runs the control-plane, lets the runner self-register and heartbeat, applies a VLESS REALITY deployment through the runner with Docker-backed real Xray validation, and verifies reload/restart hook, process health hook, deployment health, active config, and subscription output.

## Run

```bash
cargo test --workspace
cargo run -p control-plane
npm --prefix apps/web run lint
npm --prefix apps/web run build
./scripts/postgres_smoke.sh
./scripts/xray_smoke.sh
./scripts/runner_xray_smoke.sh
./scripts/e2e_smoke.sh

# Optional: switch control-plane to Postgres-backed storage when a DB is available.
DATABASE_URL=postgres://proxy:proxy@localhost:5432/proxy_control cargo run -p control-plane
```

Example control-plane flow:

```bash
curl -sS -X POST http://127.0.0.1:8080/nodes/register \
  -H 'content-type: application/json' \
  -d '{"registration_token":"dev-registration-token","node_id":"node-a","xray_version":"1.8.8"}'

# Registration tokens are consumed after the first successful registration.
# Alternative first registration: include runner_result_public_key_hex and run
# the runner with the matching RUNNER_RESULT_SIGNING_KEY_HEX to enforce per-node
# result signatures.
curl -sS -X POST http://127.0.0.1:8080/nodes/register \
  -H 'content-type: application/json' \
  -d '{"registration_token":"dev-registration-token","node_id":"node-b","xray_version":"1.8.8","runner_result_public_key_hex":"<ed25519-public-key-hex>"}'

curl -sS -X POST http://127.0.0.1:8080/nodes/node-b/runner-result-key/rotate \
  -H 'content-type: application/json' \
  -d '{"runner_result_public_key_hex":"<new-ed25519-public-key-hex>"}'

curl -sS -X POST http://127.0.0.1:8080/profiles/vless-reality \
  -H 'content-type: application/json' \
  -d '{"profile_id":"profile-a","server_name":"example.com"}'

# Optional P0 profile variants:
curl -sS -X POST http://127.0.0.1:8080/profiles/shadowsocks \
  -H 'content-type: application/json' \
  -d '{"profile_id":"profile-ss","port":8388}'

curl -sS -X POST http://127.0.0.1:8080/profiles/trojan \
  -H 'content-type: application/json' \
  -d '{"profile_id":"profile-trojan","server_name":"trojan.example.com"}'

curl -sS -X POST http://127.0.0.1:8080/clients \
  -H 'content-type: application/json' \
  -d '{"client_id":"client-a","profile_id":"profile-a","display_name":"Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111","quota_bytes":1000000000,"expires_at":"2026-12-31T00:00:00Z"}'

# For Shadowsocks/Trojan clients, pass kind-specific material:
curl -sS -X POST http://127.0.0.1:8080/clients \
  -H 'content-type: application/json' \
  -d '{"client_id":"client-ss","profile_id":"profile-ss","display_name":"SS Alice","kind":"shadowsocks","method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZg=="}'

curl -sS -X POST http://127.0.0.1:8080/clients \
  -H 'content-type: application/json' \
  -d '{"client_id":"client-trojan","profile_id":"profile-trojan","display_name":"Trojan Alice","kind":"trojan","password":"trojan-password"}'

curl -sS -X POST http://127.0.0.1:8080/deployments/compile \
  -H 'content-type: application/json' \
  -H 'idempotency-key: compile-profile-a-node-a-1' \
  -d '{"profile_id":"profile-a","node_id":"node-a"}'

# Replace artifact-id with the id returned by compile.
curl -sS http://127.0.0.1:8080/artifacts/artifact-id/bytes

# Replace dep-... with the deployment id returned by compile/result flow.
curl -sS http://127.0.0.1:8080/deployments/dep-.../rollback-pointer
curl -sS http://127.0.0.1:8080/deployments/dep-.../snapshot
curl -sS http://127.0.0.1:8080/deployments/dep-.../health
curl -sS http://127.0.0.1:8080/deployments/dep-.../readiness
curl -sS -X POST http://127.0.0.1:8080/deployments/dep-.../advance
curl -sS -X POST http://127.0.0.1:8080/runner/nodes/node-a/deployments/dep-.../health \
  -H 'content-type: application/json' \
  -H 'x-runner-token: dev-runner-token' \
  -d '{"status":"healthy","payload_json":{"probe":"subscription_fetch_ok"}}'
curl -sS -X POST http://127.0.0.1:8080/deployments/dep-.../rollback

curl -sS -X POST http://127.0.0.1:8080/runner/nodes/node-a/usage \
  -H 'content-type: application/json' \
  -H 'x-runner-token: dev-runner-token' \
  -d '{"credential_id":"client-a","uplink_bytes":1234,"downlink_bytes":5678}'

curl -sS http://127.0.0.1:8080/usage/nodes/node-a/latest
curl -sS 'http://127.0.0.1:8080/usage/credentials/client-a/rollups/latest?bucket=hour'
curl -sS 'http://127.0.0.1:8080/usage/credentials/client-a/rollups/latest?bucket=day'
curl -sS 'http://127.0.0.1:8080/usage/credentials/client-a/rollups/latest?bucket=month'
curl -sS http://127.0.0.1:8080/clients/client-a/quota
curl -sS http://127.0.0.1:8080/clients/client-a/expiry

# Issue a subscription token. Use the returned `token` query value for access.
curl -sS -X POST http://127.0.0.1:8080/subscriptions/profile-a/tokens
curl -sS 'http://127.0.0.1:8080/subscriptions/profile-a?token=<returned-token>'
curl -sS -X POST http://127.0.0.1:8080/subscriptions/profile-a/tokens/rotate

# Dev compatibility: before any token has been issued for a profile, the legacy
# tokenless subscription endpoint remains available.
curl -sS http://127.0.0.1:8080/subscriptions/profile-a
```

## Local machine note

The current implementation avoids GPU/model requirements and heavy Docker stacks. The Rust P0 core is the deployment path; the Next.js console is a verified local P0 control console, not a static runbook.


## Runner outbound polling

After creating a node/profile/client and compiling a deployment, run one polling iteration with:

```bash
CONTROL_PLANE_BASE_URL=http://127.0.0.1:8080 \
RUNNER_NODE_ID=node-a \
RUNNER_API_TOKEN=dev-runner-token \
NODE_REGISTRATION_TOKEN=dev-registration-token \
RUNNER_WORK_DIR=.data/runner \
RUNNER_XRAY_BIN=/path/to/xray \
RUNNER_XRAY_RELOAD_CMD=/path/to/reload-or-restart-xray \
RUNNER_XRAY_HEALTH_CMD=/path/to/check-xray-health \
RUNNER_RESULT_SIGNING_KEY_HEX=<optional-ed25519-private-key-seed-hex> \
RUNNER_ONCE=1 \
cargo run -p runner
```

When `NODE_REGISTRATION_TOKEN` is set, the runner first posts `/nodes/register` with its result public key. It then posts `/runner/nodes/{node_id}/heartbeat`, fetches `/runner/nodes/{node_id}/commands/next` with `X-Runner-Token`, verifies the signed command, validates the config with `xray run -test`, switches the active release, optionally runs `RUNNER_XRAY_RELOAD_CMD` and `RUNNER_XRAY_HEALTH_CMD` with `RUNNER_ACTIVE_DIR` / `RUNNER_ACTIVE_CONFIG` / `RUNNER_DEPLOYMENT_ID` environment variables, signs a `SignedDeploymentResult` with its node key, and posts it to `/runner/nodes/{node_id}/results`.
