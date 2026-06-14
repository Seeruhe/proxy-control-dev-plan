use axum::response::{IntoResponse, Response};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use compiler_xray::{compile_profile_to_xray, CompileContext};
use domain::{
    Artifact, ArtifactKind, ClientGroup, Credential, CredentialMaterial, DeploymentResult,
    DeploymentStatus, DnsConfig, Inbound, InboundProtocol, ProfileIr, RunnerCommand,
    RunnerCommandKind, Runtime, Security, SignedDeploymentResult, SignedRunnerCommand,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use storage::{
    CredentialExpiryDecision, CredentialQuotaDecision, DeploymentHealthCheckRecord,
    DeploymentPlanRecord, HeartbeatRecord, MemoryStore, NodeRecord, NodeRegistrationTokenRecord,
    PostgresStore, ProfileRecord, ProxyStore, StoreError, UsageRollupRecord, UsageSampleRecord,
};
use subscription::generate_subscription_artifact;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    default_registration_token: String,
    runner_api_token: String,
    tenant_id: String,
    store: Arc<dyn ProxyStore>,
    signing_key: Arc<SigningKey>,
    runner_result_verify_key: VerifyingKey,
    node_sequences: Arc<Mutex<HashMap<String, u64>>>,
    runner_results: Arc<Mutex<Vec<DeploymentResult>>>,
}

impl AppState {
    pub fn dev() -> Self {
        Self::with_store(
            "dev-registration-token",
            "tenant-dev",
            Arc::new(MemoryStore::new("tenant-dev")),
        )
    }

    pub fn dev_control_plane_verify_key() -> VerifyingKey {
        VerifyingKey::from(&dev_control_plane_signing_key())
    }

    pub async fn from_env() -> anyhow::Result<Self> {
        let registration_token = std::env::var("NODE_REGISTRATION_TOKEN")
            .unwrap_or_else(|_| "dev-registration-token".into());
        let tenant_id = std::env::var("TENANT_ID").unwrap_or_else(|_| "tenant-dev".into());
        let runner_api_token =
            std::env::var("RUNNER_API_TOKEN").unwrap_or_else(|_| "dev-runner-token".into());
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            let store = PostgresStore::connect_lazy(&database_url)?;
            Ok(Self::with_store_and_runner_token(
                registration_token,
                runner_api_token,
                tenant_id,
                Arc::new(store),
            ))
        } else {
            Ok(Self::with_store_and_runner_token(
                registration_token,
                runner_api_token,
                tenant_id.clone(),
                Arc::new(MemoryStore::new(&tenant_id)),
            ))
        }
    }

    pub fn with_store(
        registration_token: impl Into<String>,
        tenant_id: impl Into<String>,
        store: Arc<dyn ProxyStore>,
    ) -> Self {
        let registration_token = registration_token.into();
        Self {
            default_registration_token: registration_token,
            runner_api_token: "dev-runner-token".into(),
            tenant_id: tenant_id.into(),
            store,
            signing_key: Arc::new(dev_control_plane_signing_key()),
            runner_result_verify_key: dev_runner_result_verify_key(),
            node_sequences: Arc::new(Mutex::new(HashMap::new())),
            runner_results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_store_and_runner_token(
        registration_token: impl Into<String>,
        runner_api_token: impl Into<String>,
        tenant_id: impl Into<String>,
        store: Arc<dyn ProxyStore>,
    ) -> Self {
        let registration_token = registration_token.into();
        Self {
            default_registration_token: registration_token,
            runner_api_token: runner_api_token.into(),
            tenant_id: tenant_id.into(),
            store,
            signing_key: Arc::new(dev_control_plane_signing_key()),
            runner_result_verify_key: dev_runner_result_verify_key(),
            node_sequences: Arc::new(Mutex::new(HashMap::new())),
            runner_results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn store_kind(&self) -> &'static str {
        self.store.kind()
    }

    async fn next_sequence(&self, node_id: &str) -> u64 {
        let mut sequences = self.node_sequences.lock().await;
        let next = sequences.entry(node_id.to_owned()).or_insert(0);
        *next += 1;
        *next
    }
}

fn dev_control_plane_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn dev_runner_result_verify_key() -> VerifyingKey {
    VerifyingKey::from(&SigningKey::from_bytes(&[22u8; 32]))
}

const DEV_REALITY_PRIVATE_KEY: &str = "qKQ2RRX4uDMX5W-8JbyE8lcl3TVGeM5KAwkbTnEX1VM";

async fn ensure_default_registration_token(state: &AppState) -> Result<(), (StatusCode, String)> {
    let record = NodeRegistrationTokenRecord::new(
        &state.tenant_id,
        "regtok-dev",
        &state.default_registration_token,
    );
    state
        .store
        .create_node_registration_token(record)
        .await
        .map_err(to_http_error)
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/system/capabilities", get(system_capabilities))
        .route("/nodes", get(list_nodes))
        .route(
            "/nodes/registration-tokens",
            get(list_registration_tokens).post(issue_registration_token),
        )
        .route("/nodes/register", post(register_node))
        .route(
            "/nodes/{node_id}/runner-result-key/rotate",
            post(rotate_runner_result_key),
        )
        .route("/nodes/{node_id}/heartbeat", get(get_node_heartbeat))
        .route("/usage/nodes/{node_id}/latest", get(get_latest_usage))
        .route(
            "/usage/credentials/{credential_id}/rollups/latest",
            get(get_latest_usage_rollup),
        )
        .route("/artifacts/{artifact_id}/bytes", get(get_artifact_bytes))
        .route("/profiles", get(list_profiles))
        .route(
            "/profiles/vless-reality",
            post(create_vless_reality_profile),
        )
        .route("/profiles/shadowsocks", post(create_shadowsocks_profile))
        .route("/profiles/trojan", post(create_trojan_profile))
        .route("/clients", get(list_clients).post(create_client))
        .route("/clients/{client_id}/quota", get(get_client_quota))
        .route("/clients/{client_id}/expiry", get(get_client_expiry))
        .route("/deployments/compile", post(compile_deployment))
        .route("/deployments/{deployment_id}", get(get_deployment))
        .route(
            "/deployments/{deployment_id}/rollback",
            post(queue_rollback),
        )
        .route(
            "/deployments/{deployment_id}/rollback-pointer",
            get(get_rollback_pointer),
        )
        .route(
            "/deployments/{deployment_id}/snapshot",
            get(get_deployment_snapshot),
        )
        .route(
            "/deployments/{deployment_id}/health",
            get(get_deployment_health),
        )
        .route(
            "/deployments/{deployment_id}/readiness",
            get(get_deployment_readiness),
        )
        .route(
            "/deployments/{deployment_id}/advance",
            post(advance_deployment_rollout),
        )
        .route("/runner/nodes/{node_id}/heartbeat", post(runner_heartbeat))
        .route("/runner/nodes/{node_id}/usage", post(runner_usage))
        .route(
            "/runner/nodes/{node_id}/deployments/{deployment_id}/health",
            post(record_runner_deployment_health),
        )
        .route(
            "/runner/nodes/{node_id}/commands/next",
            get(next_runner_command),
        )
        .route(
            "/runner/nodes/{node_id}/results",
            post(submit_runner_result),
        )
        .route("/runner/results/count", get(runner_result_count))
        .route(
            "/subscriptions/{profile_id}/tokens",
            post(issue_subscription_token),
        )
        .route(
            "/subscriptions/{profile_id}/tokens/rotate",
            post(rotate_subscription_token),
        )
        .route("/subscriptions/{profile_id}", get(get_subscription))
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct SystemCapabilitiesResponse {
    product: &'static str,
    architecture: &'static str,
    p0_status: &'static str,
    core_path: Vec<CapabilityItem>,
    backend_wheels: Vec<CapabilityItem>,
    deferred_wheels: Vec<CapabilityItem>,
}

#[derive(Debug, Serialize)]
struct CapabilityItem {
    name: &'static str,
    status: &'static str,
    evidence: &'static str,
}

async fn system_capabilities() -> Json<SystemCapabilitiesResponse> {
    Json(SystemCapabilitiesResponse {
        product: "RelayX",
        architecture: "Agent-native proxy infrastructure control plane",
        p0_status: "executable",
        core_path: vec![
            CapabilityItem {
                name: "Next.js console -> Rust control-plane",
                status: "implemented",
                evidence: "same-origin /api/control-plane proxy, health check, browser operations",
            },
            CapabilityItem {
                name: "Rust control-plane -> storage",
                status: "implemented",
                evidence: "ProxyStore trait with MemoryStore and PostgresStore implementations",
            },
            CapabilityItem {
                name: "Rust runner -> xray-core",
                status: "implemented",
                evidence: "signed command polling, xray run -test, atomic active release switch",
            },
        ],
        backend_wheels: vec![
            CapabilityItem {
                name: "Profile IR",
                status: "implemented",
                evidence: "VLESS REALITY, Shadowsocks, and Trojan profile constructors plus validation",
            },
            CapabilityItem {
                name: "Xray compiler adapter",
                status: "implemented",
                evidence: "compiler-xray crate emits content-addressed xray JSON artifacts",
            },
            CapabilityItem {
                name: "Runner lifecycle",
                status: "implemented",
                evidence: "self-registration, heartbeat, command polling, apply, signed result submission",
            },
            CapabilityItem {
                name: "Node registration lease",
                status: "p0-implemented",
                evidence: "one-time registration tokens persisted in storage and atomically consumed",
            },
            CapabilityItem {
                name: "Deployment evidence",
                status: "implemented",
                evidence: "health samples, readiness, rollback pointer, snapshot, result count",
            },
            CapabilityItem {
                name: "Subscription and client guards",
                status: "implemented",
                evidence: "token issue/rotate/verify, quota, expiry, usage rollups",
            },
        ],
        deferred_wheels: vec![
            CapabilityItem {
                name: "Full Lease Protocol",
                status: "p1-deferred",
                evidence: "needs explicit node lease artifact, graceful drain, credential rotation workflow",
            },
            CapabilityItem {
                name: "sing-box compiler adapter",
                status: "p1-deferred",
                evidence: "compiler boundary exists; xray adapter is the P0 executable path",
            },
            CapabilityItem {
                name: "A2A boundary",
                status: "p1-deferred",
                evidence: "internal flow uses direct HTTP/Rust; A2A should wrap external agent capabilities later",
            },
            CapabilityItem {
                name: "BYOM integration",
                status: "p1-deferred",
                evidence: "no local model dependency in P0; future API-key-backed or customer connector mode",
            },
            CapabilityItem {
                name: "Node marketplace agent",
                status: "p2-deferred",
                evidence: "requires private registry, auth, rate limits, and lease artifact contract first",
            },
        ],
    })
}

#[derive(Debug, Deserialize)]
struct RegisterNodeRequest {
    registration_token: String,
    node_id: String,
    xray_version: String,
    runner_result_public_key_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterNodeResponse {
    node_id: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct ListNodesResponse {
    nodes: Vec<NodeRecord>,
}

#[derive(Debug, Serialize)]
struct ListRegistrationTokensResponse {
    tokens: Vec<NodeRegistrationTokenRecord>,
}

#[derive(Debug, Deserialize)]
struct IssueRegistrationTokenRequest {
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RotateRunnerResultKeyRequest {
    runner_result_public_key_hex: String,
}

#[derive(Debug, Serialize)]
struct RotateRunnerResultKeyResponse {
    node_id: String,
    status: String,
    runner_result_public_key_hex: String,
}

async fn register_node(
    State(state): State<AppState>,
    Json(req): Json<RegisterNodeRequest>,
) -> Result<(StatusCode, Json<RegisterNodeResponse>), (StatusCode, String)> {
    ensure_default_registration_token(&state).await?;
    let runner_result_public_key_hex = req
        .runner_result_public_key_hex
        .unwrap_or_else(|| hex::encode(state.runner_result_verify_key.to_bytes()));
    state
        .store
        .register_node_with_registration_token(
            NodeRecord::new(
                &state.tenant_id,
                &req.node_id,
                &format!("{}.example", req.node_id),
                &req.xray_version,
            )
            .with_runner_result_public_key_hex(runner_result_public_key_hex),
            &req.registration_token,
        )
        .await
        .map_err(|error| match error {
            StoreError::NotFound(_) => (
                StatusCode::UNAUTHORIZED,
                "invalid registration token".into(),
            ),
            other => to_http_error(other),
        })?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterNodeResponse {
            node_id: req.node_id,
            status: "registered".into(),
        }),
    ))
}

async fn list_nodes(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.list_nodes().await {
        Ok(nodes) => Json(ListNodesResponse { nodes }).into_response(),
        Err(error) => to_http_error(error).into_response(),
    }
}

async fn list_registration_tokens(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(error) = ensure_default_registration_token(&state).await {
        return error.into_response();
    }
    match state.store.list_node_registration_tokens().await {
        Ok(tokens) => Json(ListRegistrationTokensResponse { tokens }).into_response(),
        Err(error) => to_http_error(error).into_response(),
    }
}

async fn issue_registration_token(
    State(state): State<AppState>,
    Json(req): Json<IssueRegistrationTokenRequest>,
) -> impl IntoResponse {
    if let Err(error) = ensure_default_registration_token(&state).await {
        return error.into_response();
    }
    let token = req
        .token
        .unwrap_or_else(|| format!("node-reg-{}", Uuid::new_v4()));
    match state.store.node_registration_token(&token).await {
        Ok(_) => {
            return (StatusCode::CONFLICT, "registration token already exists").into_response()
        }
        Err(StoreError::NotFound(_)) => {}
        Err(error) => return to_http_error(error).into_response(),
    }
    let record = NodeRegistrationTokenRecord::new(
        &state.tenant_id,
        &format!("regtok-{}", Uuid::new_v4()),
        &token,
    );
    match state
        .store
        .create_node_registration_token(record.clone())
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(error) => to_http_error(error).into_response(),
    }
}

async fn rotate_runner_result_key(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(req): Json<RotateRunnerResultKeyRequest>,
) -> Result<(StatusCode, Json<RotateRunnerResultKeyResponse>), (StatusCode, String)> {
    parse_runner_result_public_key_hex(&req.runner_result_public_key_hex)
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let node = state
        .store
        .update_node_runner_result_public_key(&node_id, &req.runner_result_public_key_hex)
        .await
        .map_err(to_http_error)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(RotateRunnerResultKeyResponse {
            node_id,
            status: "rotated".into(),
            runner_result_public_key_hex: node.runner_result_public_key_hex,
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct RunnerHeartbeatRequest {
    capability_snapshot: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct RunnerHeartbeatResponse {
    node_id: String,
    accepted: bool,
}

async fn runner_heartbeat(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<RunnerHeartbeatRequest>,
) -> impl IntoResponse {
    if !runner_token_valid(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let heartbeat = HeartbeatRecord::new(&state.tenant_id, &node_id, req.capability_snapshot);
    match state.store.record_heartbeat(heartbeat).await {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(RunnerHeartbeatResponse {
                node_id,
                accepted: true,
            }),
        )
            .into_response(),
        Err(error) => to_http_error(error).into_response(),
    }
}

#[derive(Debug, Serialize)]
struct NodeHeartbeatResponse {
    node_id: String,
    capability_snapshot: serde_json::Value,
    observed_at: chrono::DateTime<Utc>,
}

async fn get_node_heartbeat(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<Json<NodeHeartbeatResponse>, (StatusCode, String)> {
    let heartbeat = state
        .store
        .latest_heartbeat(&node_id)
        .await
        .map_err(to_http_error)?;
    Ok(Json(NodeHeartbeatResponse {
        node_id: heartbeat.node_id,
        capability_snapshot: heartbeat.capability_snapshot,
        observed_at: heartbeat.created_at,
    }))
}

#[derive(Debug, Deserialize)]
struct RunnerUsageRequest {
    credential_id: Option<String>,
    uplink_bytes: i64,
    downlink_bytes: i64,
    sampled_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct RunnerUsageResponse {
    node_id: String,
    accepted: bool,
}

async fn runner_usage(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<RunnerUsageRequest>,
) -> impl IntoResponse {
    if !runner_token_valid(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let usage = UsageSampleRecord::new(
        &state.tenant_id,
        &node_id,
        req.credential_id,
        req.uplink_bytes,
        req.downlink_bytes,
        req.sampled_at.unwrap_or_else(Utc::now),
    );
    match state.store.record_usage_sample(usage).await {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(RunnerUsageResponse {
                node_id,
                accepted: true,
            }),
        )
            .into_response(),
        Err(error) => to_http_error(error).into_response(),
    }
}

async fn get_latest_usage(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<Json<UsageSampleRecord>, (StatusCode, String)> {
    let usage = state
        .store
        .latest_usage_sample(&node_id)
        .await
        .map_err(to_http_error)?;
    Ok(Json(usage))
}

#[derive(Debug, Deserialize)]
struct UsageRollupQuery {
    bucket: Option<String>,
}

async fn get_latest_usage_rollup(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    Query(query): Query<UsageRollupQuery>,
) -> Result<Json<UsageRollupRecord>, (StatusCode, String)> {
    let bucket = query.bucket.unwrap_or_else(|| "hour".into());
    let rollup = state
        .store
        .latest_usage_rollup_for_credential(&credential_id, &bucket)
        .await
        .map_err(to_http_error)?;
    Ok(Json(rollup))
}

#[derive(Debug, Deserialize)]
struct CreateProfileRequest {
    profile_id: String,
    server_name: String,
}

#[derive(Debug, Serialize)]
struct CreateProfileResponse {
    profile_id: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct ProfileInventoryResponse {
    profiles: Vec<ProfileInventoryItem>,
}

#[derive(Debug, Serialize)]
struct ProfileInventoryItem {
    profile_id: String,
    protocol: String,
    core: String,
    inbound_count: usize,
    credential_count: usize,
    created_at: chrono::DateTime<Utc>,
}

async fn list_profiles(State(state): State<AppState>) -> impl IntoResponse {
    let profiles = match state.store.list_profiles().await {
        Ok(profiles) => profiles,
        Err(error) => return to_http_error(error).into_response(),
    };
    let mut items = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let credential_count = match state
            .store
            .credentials_for_profile(&profile.profile_id)
            .await
        {
            Ok(credentials) => credentials.len(),
            Err(error) => return to_http_error(error).into_response(),
        };
        items.push(ProfileInventoryItem {
            protocol: profile_protocol_label(&profile.ir),
            core: profile.ir.runtime.core.clone(),
            inbound_count: profile.ir.inbounds.len(),
            credential_count,
            profile_id: profile.profile_id,
            created_at: profile.created_at,
        });
    }
    Json(ProfileInventoryResponse { profiles: items }).into_response()
}

async fn create_vless_reality_profile(
    State(state): State<AppState>,
    Json(req): Json<CreateProfileRequest>,
) -> Result<(StatusCode, Json<CreateProfileResponse>), (StatusCode, String)> {
    let mut ir = ProfileIr::vless_reality_example("group_default", "sec_reality_private");
    if let Security::Reality { server_name, .. } = &mut ir.inbounds[0].security {
        *server_name = req.server_name;
    }
    ir.validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .store
        .create_profile(ProfileRecord::new(&state.tenant_id, &req.profile_id, ir))
        .await
        .map_err(to_http_error)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateProfileResponse {
            profile_id: req.profile_id,
            status: "created".into(),
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct CreateShadowsocksProfileRequest {
    profile_id: String,
    port: Option<u16>,
}

async fn create_shadowsocks_profile(
    State(state): State<AppState>,
    Json(req): Json<CreateShadowsocksProfileRequest>,
) -> Result<(StatusCode, Json<CreateProfileResponse>), (StatusCode, String)> {
    let ir = ProfileIr {
        schema_version: "0.1".into(),
        runtime: Runtime {
            core: "xray".into(),
            core_version: "1.x".into(),
        },
        inbounds: vec![Inbound {
            id: "in_ss".into(),
            protocol: InboundProtocol::Shadowsocks,
            listen: "0.0.0.0".into(),
            port: req.port.unwrap_or(8388),
            security: Security::None,
            client_group_refs: vec!["group_default".into()],
        }],
        client_groups: vec![ClientGroup {
            id: "group_default".into(),
            credential_policy: "shadowsocks_password".into(),
            quota_policy_ref: None,
        }],
        routes: vec![],
        dns: DnsConfig {
            mode: "system".into(),
        },
    };
    state
        .store
        .create_profile(ProfileRecord::new(&state.tenant_id, &req.profile_id, ir))
        .await
        .map_err(to_http_error)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateProfileResponse {
            profile_id: req.profile_id,
            status: "created".into(),
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct CreateTrojanProfileRequest {
    profile_id: String,
    server_name: String,
    port: Option<u16>,
}

async fn create_trojan_profile(
    State(state): State<AppState>,
    Json(req): Json<CreateTrojanProfileRequest>,
) -> Result<(StatusCode, Json<CreateProfileResponse>), (StatusCode, String)> {
    let ir = ProfileIr {
        schema_version: "0.1".into(),
        runtime: Runtime {
            core: "xray".into(),
            core_version: "1.x".into(),
        },
        inbounds: vec![Inbound {
            id: "in_trojan".into(),
            protocol: InboundProtocol::Trojan,
            listen: "0.0.0.0".into(),
            port: req.port.unwrap_or(443),
            security: Security::Tls {
                server_name: req.server_name,
            },
            client_group_refs: vec!["group_default".into()],
        }],
        client_groups: vec![ClientGroup {
            id: "group_default".into(),
            credential_policy: "trojan_password".into(),
            quota_policy_ref: None,
        }],
        routes: vec![],
        dns: DnsConfig {
            mode: "system".into(),
        },
    };
    state
        .store
        .create_profile(ProfileRecord::new(&state.tenant_id, &req.profile_id, ir))
        .await
        .map_err(to_http_error)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateProfileResponse {
            profile_id: req.profile_id,
            status: "created".into(),
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct CreateClientRequest {
    client_id: String,
    profile_id: String,
    display_name: String,
    uuid: Option<String>,
    kind: Option<String>,
    method: Option<String>,
    password: Option<String>,
    quota_bytes: Option<i64>,
    expires_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct CreateClientResponse {
    client_id: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct ClientInventoryResponse {
    clients: Vec<ClientInventoryItem>,
}

#[derive(Debug, Serialize)]
struct ClientInventoryItem {
    client_id: String,
    profile_id: String,
    display_name: String,
    kind: String,
    status: String,
}

async fn list_clients(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.list_credentials().await {
        Ok(credentials) => {
            let clients = credentials
                .into_iter()
                .map(|record| ClientInventoryItem {
                    client_id: record.credential.id,
                    profile_id: record.profile_id,
                    display_name: record.credential.display_name,
                    kind: credential_kind_label(&record.credential.material),
                    status: credential_status_label(&record.credential.status),
                })
                .collect();
            Json(ClientInventoryResponse { clients }).into_response()
        }
        Err(error) => to_http_error(error).into_response(),
    }
}

async fn create_client(
    State(state): State<AppState>,
    Json(req): Json<CreateClientRequest>,
) -> Result<(StatusCode, Json<CreateClientResponse>), (StatusCode, String)> {
    let credential =
        match req.kind.as_deref().unwrap_or("vless") {
            "vless" => Credential::active_vless(
                &req.client_id,
                "group_default",
                req.uuid
                    .as_deref()
                    .ok_or_else(|| (StatusCode::BAD_REQUEST, "uuid is required".to_owned()))?,
                &req.display_name,
            ),
            "shadowsocks" => Credential {
                id: req.client_id.clone(),
                client_group_id: "group_default".into(),
                display_name: req.display_name.clone(),
                status: domain::CredentialStatus::Active,
                material: CredentialMaterial::ShadowsocksPassword {
                    method: req.method.clone().ok_or_else(|| {
                        (StatusCode::BAD_REQUEST, "method is required".to_owned())
                    })?,
                    password: req.password.clone().ok_or_else(|| {
                        (StatusCode::BAD_REQUEST, "password is required".to_owned())
                    })?,
                },
            },
            "trojan" => Credential {
                id: req.client_id.clone(),
                client_group_id: "group_default".into(),
                display_name: req.display_name.clone(),
                status: domain::CredentialStatus::Active,
                material: CredentialMaterial::TrojanPassword {
                    password: req.password.clone().ok_or_else(|| {
                        (StatusCode::BAD_REQUEST, "password is required".to_owned())
                    })?,
                },
            },
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("unsupported client kind: {other}"),
                ));
            }
        };
    state
        .store
        .add_credential(&req.profile_id, credential)
        .await
        .map_err(to_http_error)?;
    if let Some(quota_bytes) = req.quota_bytes {
        state
            .store
            .set_credential_quota(&req.client_id, quota_bytes)
            .await
            .map_err(to_http_error)?;
    }
    if let Some(expires_at) = req.expires_at {
        state
            .store
            .set_credential_expiry(&req.client_id, expires_at)
            .await
            .map_err(to_http_error)?;
    }
    Ok((
        StatusCode::CREATED,
        Json(CreateClientResponse {
            client_id: req.client_id,
            status: "created".into(),
        }),
    ))
}

async fn get_client_quota(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<Json<CredentialQuotaDecision>, (StatusCode, String)> {
    let decision = state
        .store
        .credential_quota_decision(&client_id)
        .await
        .map_err(to_http_error)?;
    Ok(Json(decision))
}

async fn get_client_expiry(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<Json<CredentialExpiryDecision>, (StatusCode, String)> {
    let decision = state
        .store
        .credential_expiry_decision(&client_id)
        .await
        .map_err(to_http_error)?;
    Ok(Json(decision))
}

#[derive(Debug, Deserialize)]
struct CompileDeploymentRequest {
    profile_id: String,
    node_id: String,
}

#[derive(Debug, Serialize)]
struct CompileDeploymentResponse {
    status: String,
    artifact: Artifact,
    deployment_plan: domain::DeploymentPlan,
    audit_count: usize,
    outbox_count: usize,
}

async fn compile_deployment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CompileDeploymentRequest>,
) -> Result<Response, (StatusCode, String)> {
    let idempotency_key = optional_header_value(&headers, "idempotency-key")?;
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(cached) = state
            .store
            .idempotency_response(&state.tenant_id, key)
            .await
            .map_err(to_http_error)?
        {
            return Ok((StatusCode::CREATED, Json(cached)).into_response());
        }
    }

    let profile = state
        .store
        .profile(&req.profile_id)
        .await
        .map_err(to_http_error)?;
    let node = state
        .store
        .node(&req.node_id)
        .await
        .map_err(to_http_error)?;
    let credentials = state
        .store
        .credentials_for_profile(&req.profile_id)
        .await
        .map_err(to_http_error)?;
    let mut ctx = CompileContext::new(&node.xray_version)
        .with_secret("sec_reality_private", DEV_REALITY_PRIVATE_KEY);
    for credential in credentials {
        ctx = ctx.with_credential(credential);
    }
    let compiled = compile_profile_to_xray(&profile.ir, &ctx)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let bytes = serde_json::to_vec_pretty(&compiled.config_json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let artifact = Artifact::from_bytes(
        &state.tenant_id,
        ArtifactKind::CompiledXrayConfig,
        "application/json",
        &bytes,
        "admin",
    );
    state
        .store
        .record_artifact_blob(artifact.clone(), bytes.clone())
        .await
        .map_err(to_http_error)?;

    let deployment_id = format!("dep-{}", &artifact.sha256[..12]);
    state
        .store
        .record_deployment_plan(DeploymentPlanRecord::new(
            &state.tenant_id,
            &deployment_id,
            &req.node_id,
            &req.profile_id,
            &artifact.id,
        ))
        .await
        .map_err(to_http_error)?;

    let deployment_plan = domain::DeploymentPlan {
        target_node_id: req.node_id.clone(),
        target_profile_version_id: req.profile_id.clone(),
        compiled_config_artifact_id: artifact.id.clone(),
        core_kind: "xray".into(),
        core_version: node.xray_version,
        assets_version: "dev".into(),
        rollback_pointer_id: format!("rollback-{}", artifact.sha256),
        created_by: "admin".into(),
        created_at: Utc::now(),
    };
    let sequence = state.next_sequence(&req.node_id).await;
    let command = RunnerCommand::new(
        &state.tenant_id,
        &req.node_id,
        sequence,
        Utc::now() + Duration::seconds(60),
        RunnerCommandKind::ApplyDeploymentPlan {
            deployment_id: deployment_id.clone(),
            artifact_sha256: artifact.sha256.clone(),
            config_json: compiled.config_json.clone(),
            rollback_json: None,
        },
    );
    let envelope = SignedRunnerCommand::sign(command, &state.signing_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .store
        .enqueue_runner_command(&req.node_id, envelope)
        .await
        .map_err(to_http_error)?;
    let audit_count = state.store.audit_count().await.map_err(to_http_error)?;
    let outbox_count = state.store.outbox_count().await.map_err(to_http_error)?;
    let response = CompileDeploymentResponse {
        status: "compiled".into(),
        artifact,
        deployment_plan,
        audit_count,
        outbox_count,
    };
    if let Some(key) = idempotency_key.as_deref() {
        state
            .store
            .record_idempotency_response(
                &state.tenant_id,
                key,
                serde_json::to_value(&response)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            )
            .await
            .map_err(to_http_error)?;
    }
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[derive(Debug, Deserialize)]
struct NextCommandQuery {
    last_sequence: Option<u64>,
}

async fn next_runner_command(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Query(query): Query<NextCommandQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !runner_token_valid(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let last_sequence = query.last_sequence.unwrap_or(0);
    match state
        .store
        .next_runner_command(&node_id, last_sequence)
        .await
    {
        Ok(Some(command)) => Json(command).into_response(),
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => to_http_error(error).into_response(),
    }
}

async fn submit_runner_result(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    Json(signed_result): Json<SignedDeploymentResult>,
) -> impl IntoResponse {
    if !runner_token_valid(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let node = match state.store.node(&node_id).await {
        Ok(node) => node,
        Err(error) => return to_http_error(error).into_response(),
    };
    let verify_key = match runner_result_verify_key_for_node(&state, &node) {
        Ok(key) => key,
        Err(error) => return (StatusCode::UNAUTHORIZED, error).into_response(),
    };
    let result = match signed_result.verify(&verify_key, &node_id) {
        Ok(result) => result,
        Err(error) => return (StatusCode::UNAUTHORIZED, error.to_string()).into_response(),
    };
    if let Err(error) = state.store.record_deployment_result(result.clone()).await {
        return to_http_error(error).into_response();
    }
    state.runner_results.lock().await.push(result);
    StatusCode::ACCEPTED.into_response()
}

#[derive(Debug, Serialize)]
struct RunnerResultCount {
    count: usize,
}

async fn runner_result_count(State(state): State<AppState>) -> Json<RunnerResultCount> {
    Json(RunnerResultCount {
        count: state.runner_results.lock().await.len(),
    })
}

#[derive(Debug, Serialize)]
struct DeploymentStatusResponse {
    deployment_id: String,
    status: domain::DeploymentStatus,
}

async fn get_deployment(
    State(state): State<AppState>,
    Path(deployment_id): Path<String>,
) -> Result<Json<DeploymentStatusResponse>, (StatusCode, String)> {
    let status = state
        .store
        .deployment_status(&deployment_id)
        .await
        .map_err(to_http_error)?;
    Ok(Json(DeploymentStatusResponse {
        deployment_id,
        status,
    }))
}

#[derive(Debug, Serialize)]
struct RollbackQueuedResponse {
    deployment_id: String,
    rollback_to_deployment_id: String,
    sequence: u64,
    status: String,
}

async fn queue_rollback(
    State(state): State<AppState>,
    Path(deployment_id): Path<String>,
) -> Result<(StatusCode, Json<RollbackQueuedResponse>), (StatusCode, String)> {
    let response = enqueue_rollback_command(&state, deployment_id).await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

async fn enqueue_rollback_command(
    state: &AppState,
    deployment_id: String,
) -> Result<RollbackQueuedResponse, (StatusCode, String)> {
    let rollback_pointer = state
        .store
        .rollback_pointer(&deployment_id)
        .await
        .map_err(to_http_error)?;
    let rollback_to_deployment_id =
        rollback_pointer
            .previous_deployment_id
            .clone()
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "deployment has no previous deployment to roll back to".to_owned(),
                )
            })?;
    let previous_artifact_id = rollback_pointer
        .previous_compiled_config_artifact_id
        .clone()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "deployment has no previous compiled config artifact".to_owned(),
            )
        })?;
    let snapshot = state
        .store
        .deployment_snapshot(&deployment_id)
        .await
        .map_err(to_http_error)?;
    let previous_bytes = state
        .store
        .artifact_bytes(&previous_artifact_id)
        .await
        .map_err(to_http_error)?;
    let artifact_sha256 = hex::encode(Sha256::digest(previous_bytes));
    let sequence = state.next_sequence(&snapshot.node_id).await;
    let command = RunnerCommand::new(
        &state.tenant_id,
        &snapshot.node_id,
        sequence,
        Utc::now() + Duration::seconds(60),
        RunnerCommandKind::RollbackDeployment {
            deployment_id: deployment_id.clone(),
            rollback_to_deployment_id: rollback_to_deployment_id.clone(),
            artifact_sha256,
        },
    );
    let envelope = SignedRunnerCommand::sign(command, &state.signing_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .store
        .enqueue_runner_command(&snapshot.node_id, envelope)
        .await
        .map_err(to_http_error)?;
    Ok(RollbackQueuedResponse {
        deployment_id,
        rollback_to_deployment_id,
        sequence,
        status: "queued".into(),
    })
}

async fn get_rollback_pointer(
    State(state): State<AppState>,
    Path(deployment_id): Path<String>,
) -> Result<Json<storage::RollbackPointerRecord>, (StatusCode, String)> {
    let rollback_pointer = state
        .store
        .rollback_pointer(&deployment_id)
        .await
        .map_err(to_http_error)?;
    Ok(Json(rollback_pointer))
}

async fn get_deployment_snapshot(
    State(state): State<AppState>,
    Path(deployment_id): Path<String>,
) -> Result<Json<storage::DeploymentSnapshotRecord>, (StatusCode, String)> {
    let snapshot = state
        .store
        .deployment_snapshot(&deployment_id)
        .await
        .map_err(to_http_error)?;
    Ok(Json(snapshot))
}

async fn get_deployment_health(
    State(state): State<AppState>,
    Path(deployment_id): Path<String>,
) -> Result<Json<storage::DeploymentHealthCheckRecord>, (StatusCode, String)> {
    let health = state
        .store
        .latest_deployment_health(&deployment_id)
        .await
        .map_err(to_http_error)?;
    Ok(Json(health))
}

#[derive(Debug, Deserialize)]
struct RunnerDeploymentHealthRequest {
    status: String,
    #[serde(default)]
    payload_json: serde_json::Value,
}

async fn record_runner_deployment_health(
    State(state): State<AppState>,
    Path((node_id, deployment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<RunnerDeploymentHealthRequest>,
) -> impl IntoResponse {
    if !runner_token_valid(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if req.status != "healthy" && req.status != "unhealthy" {
        return (
            StatusCode::BAD_REQUEST,
            "deployment health status must be healthy or unhealthy".to_owned(),
        )
            .into_response();
    }
    let health = DeploymentHealthCheckRecord {
        tenant_id: state.tenant_id.clone(),
        deployment_id,
        node_id,
        status: req.status,
        payload_json: req.payload_json,
        created_at: Utc::now(),
    };
    match state.store.record_deployment_health_check(health).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => to_http_error(error).into_response(),
    }
}

#[derive(Debug, Clone, Serialize)]
struct DeploymentReadinessResponse {
    deployment_id: String,
    status: String,
    reason: String,
    healthy_samples: usize,
    required_healthy_samples: usize,
    latest_health_status: Option<String>,
}

const REQUIRED_HEALTHY_DEPLOYMENT_SAMPLES: usize = 2;

async fn get_deployment_readiness(
    State(state): State<AppState>,
    Path(deployment_id): Path<String>,
) -> Result<Json<DeploymentReadinessResponse>, (StatusCode, String)> {
    Ok(Json(
        compute_deployment_readiness(&state, deployment_id).await?,
    ))
}

async fn compute_deployment_readiness(
    state: &AppState,
    deployment_id: String,
) -> Result<DeploymentReadinessResponse, (StatusCode, String)> {
    let deployment_status = state
        .store
        .deployment_status(&deployment_id)
        .await
        .map_err(to_http_error)?;
    let health_samples = state
        .store
        .deployment_health_checks(&deployment_id)
        .await
        .map_err(to_http_error)?;
    let healthy_samples = health_samples
        .iter()
        .filter(|health| health.status == "healthy")
        .count();
    let latest_health_status = health_samples
        .iter()
        .max_by_key(|health| health.created_at)
        .map(|health| health.status.clone());

    let (status, reason) = if deployment_status != DeploymentStatus::Succeeded {
        ("blocked", "waiting_for_successful_deployment")
    } else if latest_health_status
        .as_deref()
        .is_some_and(|status| status != "healthy")
    {
        ("blocked", "latest_health_unhealthy")
    } else if healthy_samples < REQUIRED_HEALTHY_DEPLOYMENT_SAMPLES {
        ("blocked", "waiting_for_healthy_samples")
    } else {
        ("ready", "ready")
    };

    Ok(DeploymentReadinessResponse {
        deployment_id,
        status: status.into(),
        reason: reason.into(),
        healthy_samples,
        required_healthy_samples: REQUIRED_HEALTHY_DEPLOYMENT_SAMPLES,
        latest_health_status,
    })
}

#[derive(Debug, Serialize)]
struct DeploymentAdvanceResponse {
    deployment_id: String,
    action: String,
    readiness: DeploymentReadinessResponse,
    rollback_to_deployment_id: Option<String>,
    sequence: Option<u64>,
}

async fn advance_deployment_rollout(
    State(state): State<AppState>,
    Path(deployment_id): Path<String>,
) -> Result<(StatusCode, Json<DeploymentAdvanceResponse>), (StatusCode, String)> {
    let readiness = compute_deployment_readiness(&state, deployment_id.clone()).await?;
    if readiness.status == "ready" {
        return Ok((
            StatusCode::ACCEPTED,
            Json(DeploymentAdvanceResponse {
                deployment_id,
                action: "promoted".into(),
                readiness,
                rollback_to_deployment_id: None,
                sequence: None,
            }),
        ));
    }
    if readiness.reason == "latest_health_unhealthy" {
        let rollback = enqueue_rollback_command(&state, deployment_id.clone()).await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(DeploymentAdvanceResponse {
                deployment_id,
                action: "rollback_queued".into(),
                readiness,
                rollback_to_deployment_id: Some(rollback.rollback_to_deployment_id),
                sequence: Some(rollback.sequence),
            }),
        ));
    }
    Ok((
        StatusCode::OK,
        Json(DeploymentAdvanceResponse {
            deployment_id,
            action: "waiting".into(),
            readiness,
            rollback_to_deployment_id: None,
            sequence: None,
        }),
    ))
}

async fn get_artifact_bytes(
    State(state): State<AppState>,
    Path(artifact_id): Path<String>,
) -> impl IntoResponse {
    match state.store.artifact_bytes(&artifact_id).await {
        Ok(bytes) => bytes.into_response(),
        Err(error) => to_http_error(error).into_response(),
    }
}

#[derive(Debug, Serialize)]
struct SubscriptionResponse {
    artifact: Artifact,
    body_base64: String,
}

#[derive(Debug, Deserialize)]
struct SubscriptionQuery {
    token: Option<String>,
}

async fn get_subscription(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    Query(query): Query<SubscriptionQuery>,
    headers: HeaderMap,
) -> Result<Json<SubscriptionResponse>, (StatusCode, String)> {
    if let Some(token) = query.token.as_deref() {
        let verified = state
            .store
            .verify_subscription_token(&profile_id, token)
            .await
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid subscription token".into(),
                )
            })?;
        let user_agent = headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        state
            .store
            .record_subscription_access(&verified.token_id, None, user_agent, "ok")
            .await
            .map_err(to_http_error)?;
    } else if state
        .store
        .subscription_token_required(&profile_id)
        .await
        .map_err(to_http_error)?
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "subscription token is required".into(),
        ));
    }
    let deployed = state
        .store
        .deployed_profile_for_subscription(&profile_id)
        .await
        .map_err(to_http_error)?;
    let artifact =
        generate_subscription_artifact(&state.tenant_id, &deployed, "subscription-service")
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(SubscriptionResponse {
        artifact: artifact.artifact,
        body_base64: artifact.body_base64,
    }))
}

async fn issue_subscription_token(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
) -> Result<(StatusCode, Json<storage::IssuedSubscriptionToken>), (StatusCode, String)> {
    let token = state
        .store
        .issue_subscription_token(&profile_id)
        .await
        .map_err(to_http_error)?;
    Ok((StatusCode::CREATED, Json(token)))
}

async fn rotate_subscription_token(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
) -> Result<(StatusCode, Json<storage::IssuedSubscriptionToken>), (StatusCode, String)> {
    let token = state
        .store
        .rotate_subscription_token(&profile_id)
        .await
        .map_err(to_http_error)?;
    Ok((StatusCode::CREATED, Json(token)))
}

fn runner_token_valid(state: &AppState, headers: &HeaderMap) -> bool {
    headers
        .get("x-runner-token")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == state.runner_api_token)
}

fn optional_header_value(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<String>, (StatusCode, String)> {
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid {name} header")))
        })
        .transpose()
}

fn runner_result_verify_key_for_node(
    state: &AppState,
    node: &NodeRecord,
) -> Result<VerifyingKey, String> {
    if node.runner_result_public_key_hex.is_empty() {
        return Ok(state.runner_result_verify_key);
    }
    parse_runner_result_public_key_hex(&node.runner_result_public_key_hex)
}

fn parse_runner_result_public_key_hex(public_key_hex: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] = hex::decode(public_key_hex)
        .map_err(|_| "invalid runner result public key hex".to_owned())?
        .try_into()
        .map_err(|_| "invalid runner result public key length".to_owned())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid runner result public key".to_owned())
}

fn profile_protocol_label(ir: &ProfileIr) -> String {
    ir.inbounds
        .first()
        .map(|inbound| match &inbound.protocol {
            InboundProtocol::Vless => match &inbound.security {
                Security::Reality { .. } => "vless-reality",
                Security::Tls { .. } => "vless-tls",
                Security::None => "vless",
            },
            InboundProtocol::Shadowsocks => "shadowsocks",
            InboundProtocol::Trojan => "trojan",
        })
        .unwrap_or("unknown")
        .into()
}

fn credential_kind_label(material: &CredentialMaterial) -> String {
    match material {
        CredentialMaterial::VlessUuid { .. } => "vless".into(),
        CredentialMaterial::ShadowsocksPassword { .. } => "shadowsocks".into(),
        CredentialMaterial::TrojanPassword { .. } => "trojan".into(),
    }
}

fn credential_status_label(status: &domain::CredentialStatus) -> String {
    match status {
        domain::CredentialStatus::Active => "active",
        domain::CredentialStatus::Revoked => "revoked",
        domain::CredentialStatus::Expired => "expired",
    }
    .into()
}

fn to_http_error(error: storage::StoreError) -> (StatusCode, String) {
    match error {
        storage::StoreError::NotFound(message) => (StatusCode::NOT_FOUND, message),
        storage::StoreError::Conflict(message) => (StatusCode::CONFLICT, message),
        storage::StoreError::ArtifactShaMismatch { .. } => {
            (StatusCode::BAD_REQUEST, error.to_string())
        }
        storage::StoreError::Sqlx(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        storage::StoreError::Serde(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}
