use async_trait::async_trait;
use chrono::{DateTime, Datelike, Utc};
use domain::{
    Artifact, Credential, CredentialMaterial, CredentialStatus, DeployedProfile, DeploymentResult,
    DeploymentStatus, ProfileIr, Security, SignedRunnerCommand,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("record not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("artifact sha256 mismatch: expected {expected}, got {actual}")]
    ArtifactShaMismatch { expected: String, actual: String },
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type StoreResult<T> = Result<T, StoreError>;

#[async_trait]
pub trait ProxyStore: Send + Sync {
    async fn register_node(&self, node: NodeRecord) -> StoreResult<()>;
    async fn register_node_with_registration_token(
        &self,
        node: NodeRecord,
        registration_token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord>;
    async fn list_nodes(&self) -> StoreResult<Vec<NodeRecord>>;
    async fn create_node_registration_token(
        &self,
        token: NodeRegistrationTokenRecord,
    ) -> StoreResult<()>;
    async fn list_node_registration_tokens(&self) -> StoreResult<Vec<NodeRegistrationTokenRecord>>;
    async fn node_registration_token(
        &self,
        token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord>;
    async fn consume_node_registration_token(
        &self,
        token: &str,
        node_id: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord>;
    async fn record_heartbeat(&self, heartbeat: HeartbeatRecord) -> StoreResult<()>;
    async fn latest_heartbeat(&self, node_id: &str) -> StoreResult<HeartbeatRecord>;
    async fn create_profile(&self, profile: ProfileRecord) -> StoreResult<()>;
    async fn list_profiles(&self) -> StoreResult<Vec<ProfileRecord>>;
    async fn add_credential(&self, profile_id: &str, credential: Credential) -> StoreResult<()>;
    async fn list_credentials(&self) -> StoreResult<Vec<CredentialRecord>>;
    async fn record_artifact(&self, artifact: Artifact) -> StoreResult<()>;
    async fn record_artifact_blob(&self, artifact: Artifact, bytes: Vec<u8>) -> StoreResult<()>;
    async fn artifact_bytes(&self, artifact_id: &str) -> StoreResult<Vec<u8>>;
    async fn artifact_bytes_by_sha256(&self, sha256: &str) -> StoreResult<Vec<u8>>;
    async fn record_deployment_plan(&self, deployment: DeploymentPlanRecord) -> StoreResult<()>;
    async fn idempotency_response(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> StoreResult<Option<serde_json::Value>>;
    async fn record_idempotency_response(
        &self,
        tenant_id: &str,
        key: &str,
        response_json: serde_json::Value,
    ) -> StoreResult<()>;
    async fn record_deployment_result(&self, result: DeploymentResult) -> StoreResult<()>;
    async fn deployment_status(&self, deployment_id: &str) -> StoreResult<DeploymentStatus>;
    async fn rollback_pointer(&self, deployment_id: &str) -> StoreResult<RollbackPointerRecord>;
    async fn deployment_snapshot(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentSnapshotRecord>;
    async fn latest_deployment_health(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentHealthCheckRecord>;
    async fn record_deployment_health_check(
        &self,
        health: DeploymentHealthCheckRecord,
    ) -> StoreResult<()>;
    async fn deployment_health_checks(
        &self,
        deployment_id: &str,
    ) -> StoreResult<Vec<DeploymentHealthCheckRecord>>;
    async fn record_usage_sample(&self, usage: UsageSampleRecord) -> StoreResult<()>;
    async fn latest_usage_sample(&self, node_id: &str) -> StoreResult<UsageSampleRecord>;
    async fn latest_usage_rollup_for_credential(
        &self,
        credential_id: &str,
        bucket: &str,
    ) -> StoreResult<UsageRollupRecord>;
    async fn set_credential_quota(&self, credential_id: &str, quota_bytes: i64) -> StoreResult<()>;
    async fn credential_quota_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialQuotaDecision>;
    async fn set_credential_expiry(
        &self,
        credential_id: &str,
        expires_at: DateTime<Utc>,
    ) -> StoreResult<()>;
    async fn credential_expiry_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialExpiryDecision>;
    async fn enqueue_runner_command(
        &self,
        node_id: &str,
        command: SignedRunnerCommand,
    ) -> StoreResult<()>;
    async fn next_runner_command(
        &self,
        node_id: &str,
        last_sequence: u64,
    ) -> StoreResult<Option<SignedRunnerCommand>>;
    async fn node(&self, node_id: &str) -> StoreResult<NodeRecord>;
    async fn update_node_runner_result_public_key(
        &self,
        node_id: &str,
        public_key_hex: &str,
    ) -> StoreResult<NodeRecord>;
    async fn profile(&self, profile_id: &str) -> StoreResult<ProfileRecord>;
    async fn credentials_for_profile(&self, profile_id: &str) -> StoreResult<Vec<Credential>>;
    async fn audit_count(&self) -> StoreResult<usize>;
    async fn outbox_count(&self) -> StoreResult<usize>;
    async fn deployed_profile_for_subscription(
        &self,
        profile_id: &str,
    ) -> StoreResult<DeployedProfile>;
    async fn issue_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken>;
    async fn rotate_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken>;
    async fn verify_subscription_token(
        &self,
        profile_id: &str,
        token: &str,
    ) -> StoreResult<SubscriptionTokenRecord>;
    async fn subscription_token_required(&self, profile_id: &str) -> StoreResult<bool>;
    async fn record_subscription_access(
        &self,
        token_id: &str,
        remote_addr: Option<String>,
        user_agent: Option<String>,
        status: &str,
    ) -> StoreResult<()>;
    async fn subscription_access_log_count(&self, token_id: &str) -> StoreResult<usize>;
    fn kind(&self) -> &'static str;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecord {
    pub tenant_id: String,
    pub node_id: String,
    pub host: String,
    pub xray_version: String,
    pub runner_result_public_key_hex: String,
    pub last_heartbeat_at: DateTime<Utc>,
}

impl NodeRecord {
    pub fn new(tenant_id: &str, node_id: &str, host: &str, xray_version: &str) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            node_id: node_id.into(),
            host: host.into(),
            xray_version: xray_version.into(),
            runner_result_public_key_hex: String::new(),
            last_heartbeat_at: Utc::now(),
        }
    }

    pub fn with_runner_result_public_key_hex(mut self, public_key_hex: impl Into<String>) -> Self {
        self.runner_result_public_key_hex = public_key_hex.into();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRegistrationTokenRecord {
    pub tenant_id: String,
    pub token_id: String,
    pub token: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub used_by_node_id: Option<String>,
}

impl NodeRegistrationTokenRecord {
    pub fn new(tenant_id: &str, token_id: &str, token: &str) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            token_id: token_id.into(),
            token: token.into(),
            status: "active".into(),
            created_at: Utc::now(),
            consumed_at: None,
            used_by_node_id: None,
        }
    }

    pub fn mark_used(mut self, node_id: &str) -> Self {
        self.status = "used".into();
        self.consumed_at = Some(Utc::now());
        self.used_by_node_id = Some(node_id.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatRecord {
    pub tenant_id: String,
    pub node_id: String,
    pub capability_snapshot: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl HeartbeatRecord {
    pub fn new(tenant_id: &str, node_id: &str, capability_snapshot: serde_json::Value) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            node_id: node_id.into(),
            capability_snapshot,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileRecord {
    pub tenant_id: String,
    pub profile_id: String,
    pub ir: ProfileIr,
    pub created_at: DateTime<Utc>,
}

impl ProfileRecord {
    pub fn new(tenant_id: &str, profile_id: &str, ir: ProfileIr) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            profile_id: profile_id.into(),
            ir,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialRecord {
    pub profile_id: String,
    pub credential: Credential,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentPlanRecord {
    pub tenant_id: String,
    pub deployment_id: String,
    pub node_id: String,
    pub profile_id: String,
    pub compiled_config_artifact_id: String,
    pub created_at: DateTime<Utc>,
}

impl DeploymentPlanRecord {
    pub fn new(
        tenant_id: &str,
        deployment_id: &str,
        node_id: &str,
        profile_id: &str,
        compiled_config_artifact_id: &str,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            deployment_id: deployment_id.into(),
            node_id: node_id.into(),
            profile_id: profile_id.into(),
            compiled_config_artifact_id: compiled_config_artifact_id.into(),
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackPointerRecord {
    pub tenant_id: String,
    pub rollback_pointer_id: String,
    pub deployment_id: String,
    pub previous_deployment_id: Option<String>,
    pub previous_compiled_config_artifact_id: Option<String>,
    pub target_compiled_config_artifact_id: String,
    pub previous_core_version: Option<String>,
    pub previous_assets_version: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl RollbackPointerRecord {
    fn new(
        deployment: &DeploymentPlanRecord,
        previous_deployment_id: Option<String>,
        previous_compiled_config_artifact_id: Option<String>,
    ) -> Self {
        Self {
            tenant_id: deployment.tenant_id.clone(),
            rollback_pointer_id: format!("rollback-{}", deployment.deployment_id),
            deployment_id: deployment.deployment_id.clone(),
            previous_deployment_id,
            previous_compiled_config_artifact_id,
            target_compiled_config_artifact_id: deployment.compiled_config_artifact_id.clone(),
            previous_core_version: None,
            previous_assets_version: None,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentSnapshotRecord {
    pub tenant_id: String,
    pub snapshot_id: String,
    pub deployment_id: String,
    pub node_id: String,
    pub profile_id: String,
    pub compiled_config_artifact_id: String,
    pub result_status: DeploymentStatus,
    pub result_message: String,
    pub result_artifact_sha256: String,
    pub observed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl DeploymentSnapshotRecord {
    fn from_result(deployment: &DeploymentPlanRecord, result: &DeploymentResult) -> Self {
        Self {
            tenant_id: deployment.tenant_id.clone(),
            snapshot_id: format!("snapshot-{}", result.deployment_id),
            deployment_id: result.deployment_id.clone(),
            node_id: deployment.node_id.clone(),
            profile_id: deployment.profile_id.clone(),
            compiled_config_artifact_id: deployment.compiled_config_artifact_id.clone(),
            result_status: result.status.clone(),
            result_message: result.message.clone(),
            result_artifact_sha256: result.artifact_sha256.clone(),
            observed_at: result.observed_at,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageSampleRecord {
    pub tenant_id: String,
    pub node_id: String,
    pub credential_id: Option<String>,
    pub uplink_bytes: i64,
    pub downlink_bytes: i64,
    pub sampled_at: DateTime<Utc>,
}

impl UsageSampleRecord {
    pub fn new(
        tenant_id: &str,
        node_id: &str,
        credential_id: Option<String>,
        uplink_bytes: i64,
        downlink_bytes: i64,
        sampled_at: DateTime<Utc>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            node_id: node_id.into(),
            credential_id,
            uplink_bytes,
            downlink_bytes,
            sampled_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageRollupRecord {
    pub tenant_id: String,
    pub credential_id: Option<String>,
    pub bucket: String,
    pub bucket_start: DateTime<Utc>,
    pub uplink_bytes: i64,
    pub downlink_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialQuotaDecision {
    pub credential_id: String,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialExpiryDecision {
    pub credential_id: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub expired: bool,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentHealthCheckRecord {
    pub tenant_id: String,
    pub deployment_id: String,
    pub node_id: String,
    pub status: String,
    pub payload_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl DeploymentHealthCheckRecord {
    fn from_result(deployment: &DeploymentPlanRecord, result: &DeploymentResult) -> Self {
        Self {
            tenant_id: deployment.tenant_id.clone(),
            deployment_id: result.deployment_id.clone(),
            node_id: deployment.node_id.clone(),
            status: health_status_for_deployment_status(&result.status).into(),
            payload_json: serde_json::json!({
                "deployment_status": format!("{:?}", result.status),
                "message": result.message,
                "artifact_sha256": result.artifact_sha256,
                "observed_at": result.observed_at,
            }),
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEventRecord {
    pub tenant_id: String,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxEventRecord {
    pub tenant_id: String,
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionTokenRecord {
    pub tenant_id: String,
    pub token_id: String,
    pub profile_id: String,
    pub token_hash: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedSubscriptionToken {
    pub token_id: String,
    pub profile_id: String,
    pub token: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionAccessLogRecord {
    pub token_id: String,
    pub remote_addr: Option<String>,
    pub user_agent: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Default)]
struct MemoryState {
    nodes: HashMap<String, NodeRecord>,
    node_registration_tokens: HashMap<String, NodeRegistrationTokenRecord>,
    heartbeats: HashMap<String, HeartbeatRecord>,
    profiles: HashMap<String, ProfileRecord>,
    credentials_by_profile: HashMap<String, Vec<Credential>>,
    artifacts: HashMap<String, Artifact>,
    artifact_blobs_by_sha256: HashMap<String, Vec<u8>>,
    idempotency_responses: HashMap<String, serde_json::Value>,
    deployments: HashMap<String, DeploymentPlanRecord>,
    deployment_statuses: HashMap<String, DeploymentStatus>,
    rollback_pointers: HashMap<String, RollbackPointerRecord>,
    deployment_snapshots: HashMap<String, DeploymentSnapshotRecord>,
    deployment_health_checks: Vec<DeploymentHealthCheckRecord>,
    usage_samples: Vec<UsageSampleRecord>,
    usage_rollups: HashMap<(Option<String>, String, DateTime<Utc>), UsageRollupRecord>,
    credential_quotas: HashMap<String, i64>,
    credential_expirations: HashMap<String, DateTime<Utc>>,
    runner_commands: HashMap<String, VecDeque<SignedRunnerCommand>>,
    subscription_tokens: HashMap<String, SubscriptionTokenRecord>,
    subscription_access_logs: Vec<SubscriptionAccessLogRecord>,
    audit_events: Vec<AuditEventRecord>,
    outbox: Vec<OutboxEventRecord>,
}

#[derive(Clone)]
pub struct MemoryStore {
    tenant_id: String,
    state: Arc<Mutex<MemoryState>>,
}

impl MemoryStore {
    pub fn new(tenant_id: &str) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            state: Arc::new(Mutex::new(MemoryState::default())),
        }
    }

    pub async fn register_node(&self, node: NodeRecord) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        state.nodes.insert(node.node_id.clone(), node.clone());
        Self::record(
            &mut state,
            &self.tenant_id,
            "runner",
            "node.registered",
            "node",
            &node.node_id,
        );
        Ok(())
    }

    pub async fn register_node_with_registration_token(
        &self,
        node: NodeRecord,
        registration_token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        let mut state = self.state.lock().await;
        let existing = state
            .node_registration_tokens
            .values()
            .find(|record| record.token == registration_token)
            .cloned()
            .ok_or_else(|| StoreError::NotFound("node_registration_token".into()))?;
        if existing.status != "active" {
            return Err(StoreError::Conflict(
                "registration token already consumed".into(),
            ));
        }

        state.nodes.insert(node.node_id.clone(), node.clone());
        Self::record(
            &mut state,
            &self.tenant_id,
            "runner",
            "node.registered",
            "node",
            &node.node_id,
        );

        let updated = existing.mark_used(&node.node_id);
        state
            .node_registration_tokens
            .insert(updated.token_id.clone(), updated.clone());
        Self::record(
            &mut state,
            &updated.tenant_id,
            "runner",
            "node_registration_token.used",
            "node_registration_token",
            &updated.token_id,
        );
        Ok(updated)
    }

    pub async fn list_nodes(&self) -> StoreResult<Vec<NodeRecord>> {
        let state = self.state.lock().await;
        let mut nodes = state.nodes.values().cloned().collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        Ok(nodes)
    }

    pub async fn create_node_registration_token(
        &self,
        token: NodeRegistrationTokenRecord,
    ) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        if state
            .node_registration_tokens
            .values()
            .any(|record| record.token == token.token)
        {
            return Ok(());
        }
        state
            .node_registration_tokens
            .insert(token.token_id.clone(), token.clone());
        Self::record(
            &mut state,
            &token.tenant_id,
            "admin",
            "node_registration_token.issued",
            "node_registration_token",
            &token.token_id,
        );
        Ok(())
    }

    pub async fn list_node_registration_tokens(
        &self,
    ) -> StoreResult<Vec<NodeRegistrationTokenRecord>> {
        let state = self.state.lock().await;
        let mut tokens = state
            .node_registration_tokens
            .values()
            .cloned()
            .collect::<Vec<_>>();
        tokens.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(tokens)
    }

    pub async fn node_registration_token(
        &self,
        token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        self.state
            .lock()
            .await
            .node_registration_tokens
            .values()
            .find(|record| record.token == token)
            .cloned()
            .ok_or_else(|| StoreError::NotFound("node_registration_token".into()))
    }

    pub async fn consume_node_registration_token(
        &self,
        token: &str,
        node_id: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        let mut state = self.state.lock().await;
        let existing = state
            .node_registration_tokens
            .values()
            .find(|record| record.token == token)
            .cloned()
            .ok_or_else(|| StoreError::NotFound("node_registration_token".into()))?;
        let updated = existing.mark_used(node_id);
        state
            .node_registration_tokens
            .insert(updated.token_id.clone(), updated.clone());
        Self::record(
            &mut state,
            &updated.tenant_id,
            "runner",
            "node_registration_token.used",
            "node_registration_token",
            &updated.token_id,
        );
        Ok(updated)
    }

    pub async fn record_heartbeat(&self, heartbeat: HeartbeatRecord) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        if !state.nodes.contains_key(&heartbeat.node_id) {
            return Err(StoreError::NotFound(format!("node:{}", heartbeat.node_id)));
        }
        state
            .heartbeats
            .insert(heartbeat.node_id.clone(), heartbeat.clone());
        Self::record(
            &mut state,
            &self.tenant_id,
            "runner",
            "node.heartbeat",
            "node",
            &heartbeat.node_id,
        );
        Ok(())
    }

    pub async fn latest_heartbeat(&self, node_id: &str) -> StoreResult<HeartbeatRecord> {
        self.state
            .lock()
            .await
            .heartbeats
            .get(node_id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("heartbeat:{node_id}")))
    }

    pub async fn create_profile(&self, profile: ProfileRecord) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        state
            .profiles
            .insert(profile.profile_id.clone(), profile.clone());
        Self::record(
            &mut state,
            &self.tenant_id,
            "admin",
            "profile.created",
            "profile",
            &profile.profile_id,
        );
        Ok(())
    }

    pub async fn list_profiles(&self) -> StoreResult<Vec<ProfileRecord>> {
        let state = self.state.lock().await;
        let mut profiles = state.profiles.values().cloned().collect::<Vec<_>>();
        profiles.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
        Ok(profiles)
    }

    pub async fn add_credential(
        &self,
        profile_id: &str,
        credential: Credential,
    ) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        if !state.profiles.contains_key(profile_id) {
            return Err(StoreError::NotFound(format!("profile:{profile_id}")));
        }
        state
            .credentials_by_profile
            .entry(profile_id.into())
            .or_default()
            .push(credential.clone());
        Self::record(
            &mut state,
            &self.tenant_id,
            "admin",
            "client.created",
            "client",
            &credential.id,
        );
        Ok(())
    }

    pub async fn list_credentials(&self) -> StoreResult<Vec<CredentialRecord>> {
        let state = self.state.lock().await;
        let mut credentials = state
            .credentials_by_profile
            .iter()
            .flat_map(|(profile_id, credentials)| {
                credentials
                    .iter()
                    .cloned()
                    .map(|credential| CredentialRecord {
                        profile_id: profile_id.clone(),
                        credential,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        credentials.sort_by(|left, right| {
            left.profile_id
                .cmp(&right.profile_id)
                .then(left.credential.id.cmp(&right.credential.id))
        });
        Ok(credentials)
    }

    pub async fn record_artifact(&self, artifact: Artifact) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        state
            .artifacts
            .insert(artifact.id.clone(), artifact.clone());
        Self::record(
            &mut state,
            &self.tenant_id,
            "control-plane",
            "artifact.created",
            "artifact",
            &artifact.id,
        );
        Ok(())
    }

    pub async fn record_artifact_blob(
        &self,
        artifact: Artifact,
        bytes: Vec<u8>,
    ) -> StoreResult<()> {
        let actual = hex_sha256(bytes.clone());
        if actual != artifact.sha256 {
            return Err(StoreError::ArtifactShaMismatch {
                expected: artifact.sha256,
                actual,
            });
        }
        let mut state = self.state.lock().await;
        state
            .artifact_blobs_by_sha256
            .insert(artifact.sha256.clone(), bytes);
        state
            .artifacts
            .insert(artifact.id.clone(), artifact.clone());
        Self::record(
            &mut state,
            &self.tenant_id,
            "control-plane",
            "artifact.created",
            "artifact",
            &artifact.id,
        );
        Ok(())
    }

    pub async fn artifact_bytes(&self, artifact_id: &str) -> StoreResult<Vec<u8>> {
        let state = self.state.lock().await;
        let artifact = state
            .artifacts
            .get(artifact_id)
            .ok_or_else(|| StoreError::NotFound(format!("artifact:{artifact_id}")))?;
        state
            .artifact_blobs_by_sha256
            .get(&artifact.sha256)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("artifact_blob:{}", artifact.sha256)))
    }

    pub async fn artifact_bytes_by_sha256(&self, sha256: &str) -> StoreResult<Vec<u8>> {
        self.state
            .lock()
            .await
            .artifact_blobs_by_sha256
            .get(sha256)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("artifact_blob:{sha256}")))
    }

    pub async fn record_deployment_plan(
        &self,
        deployment: DeploymentPlanRecord,
    ) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        let previous = state
            .deployments
            .values()
            .filter(|candidate| candidate.node_id == deployment.node_id)
            .filter(|candidate| {
                state
                    .deployment_statuses
                    .get(&candidate.deployment_id)
                    .is_some_and(|status| *status == DeploymentStatus::Succeeded)
            })
            .max_by_key(|candidate| candidate.created_at)
            .map(|candidate| {
                (
                    candidate.deployment_id.clone(),
                    candidate.compiled_config_artifact_id.clone(),
                )
            });
        let rollback_pointer = RollbackPointerRecord::new(
            &deployment,
            previous
                .as_ref()
                .map(|(deployment_id, _)| deployment_id.clone()),
            previous.map(|(_, artifact_id)| artifact_id),
        );
        state
            .deployments
            .insert(deployment.deployment_id.clone(), deployment.clone());
        state
            .deployment_statuses
            .insert(deployment.deployment_id.clone(), DeploymentStatus::Pending);
        state
            .rollback_pointers
            .insert(deployment.deployment_id.clone(), rollback_pointer);
        Self::record(
            &mut state,
            &self.tenant_id,
            "admin",
            "deployment.planned",
            "deployment",
            &deployment.deployment_id,
        );
        Ok(())
    }

    pub async fn idempotency_response(
        &self,
        _tenant_id: &str,
        key: &str,
    ) -> StoreResult<Option<serde_json::Value>> {
        Ok(self
            .state
            .lock()
            .await
            .idempotency_responses
            .get(key)
            .cloned())
    }

    pub async fn record_idempotency_response(
        &self,
        _tenant_id: &str,
        key: &str,
        response_json: serde_json::Value,
    ) -> StoreResult<()> {
        self.state
            .lock()
            .await
            .idempotency_responses
            .entry(key.to_owned())
            .or_insert(response_json);
        Ok(())
    }

    pub async fn record_deployment_result(&self, result: DeploymentResult) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        let deployment = state
            .deployments
            .get(&result.deployment_id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("deployment:{}", result.deployment_id)))?;
        state
            .deployment_statuses
            .insert(result.deployment_id.clone(), result.status.clone());
        state.deployment_snapshots.insert(
            result.deployment_id.clone(),
            DeploymentSnapshotRecord::from_result(&deployment, &result),
        );
        state
            .deployment_health_checks
            .push(DeploymentHealthCheckRecord::from_result(
                &deployment,
                &result,
            ));
        Self::record(
            &mut state,
            &self.tenant_id,
            "runner",
            "deployment.result",
            "deployment",
            &result.deployment_id,
        );
        Ok(())
    }

    pub async fn deployment_status(&self, deployment_id: &str) -> StoreResult<DeploymentStatus> {
        self.state
            .lock()
            .await
            .deployment_statuses
            .get(deployment_id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("deployment:{deployment_id}")))
    }

    pub async fn rollback_pointer(
        &self,
        deployment_id: &str,
    ) -> StoreResult<RollbackPointerRecord> {
        self.state
            .lock()
            .await
            .rollback_pointers
            .get(deployment_id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("rollback_pointer:{deployment_id}")))
    }

    pub async fn deployment_snapshot(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentSnapshotRecord> {
        self.state
            .lock()
            .await
            .deployment_snapshots
            .get(deployment_id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("deployment_snapshot:{deployment_id}")))
    }

    pub async fn latest_deployment_health(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentHealthCheckRecord> {
        self.state
            .lock()
            .await
            .deployment_health_checks
            .iter()
            .filter(|health| health.deployment_id == deployment_id)
            .max_by_key(|health| health.created_at)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("deployment_health:{deployment_id}")))
    }

    pub async fn record_deployment_health_check(
        &self,
        health: DeploymentHealthCheckRecord,
    ) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        let deployment = state
            .deployments
            .get(&health.deployment_id)
            .ok_or_else(|| StoreError::NotFound(format!("deployment:{}", health.deployment_id)))?;
        if deployment.node_id != health.node_id {
            return Err(StoreError::NotFound(format!(
                "deployment:{}:node:{}",
                health.deployment_id, health.node_id
            )));
        }
        state.deployment_health_checks.push(health.clone());
        Self::record(
            &mut state,
            &self.tenant_id,
            "runner",
            "deployment.health",
            "deployment",
            &health.deployment_id,
        );
        Ok(())
    }

    pub async fn deployment_health_checks(
        &self,
        deployment_id: &str,
    ) -> StoreResult<Vec<DeploymentHealthCheckRecord>> {
        let state = self.state.lock().await;
        if !state.deployments.contains_key(deployment_id) {
            return Err(StoreError::NotFound(format!("deployment:{deployment_id}")));
        }
        Ok(state
            .deployment_health_checks
            .iter()
            .filter(|health| health.deployment_id == deployment_id)
            .cloned()
            .collect())
    }

    pub async fn record_usage_sample(&self, usage: UsageSampleRecord) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        if !state.nodes.contains_key(&usage.node_id) {
            return Err(StoreError::NotFound(format!("node:{}", usage.node_id)));
        }
        for (bucket, bucket_start) in usage_bucket_starts(usage.sampled_at) {
            let rollup_key = (usage.credential_id.clone(), bucket.to_owned(), bucket_start);
            let rollup =
                state
                    .usage_rollups
                    .entry(rollup_key)
                    .or_insert_with(|| UsageRollupRecord {
                        tenant_id: usage.tenant_id.clone(),
                        credential_id: usage.credential_id.clone(),
                        bucket: bucket.to_owned(),
                        bucket_start,
                        uplink_bytes: 0,
                        downlink_bytes: 0,
                    });
            rollup.uplink_bytes += usage.uplink_bytes;
            rollup.downlink_bytes += usage.downlink_bytes;
        }
        state.usage_samples.push(usage);
        Ok(())
    }

    pub async fn latest_usage_sample(&self, node_id: &str) -> StoreResult<UsageSampleRecord> {
        self.state
            .lock()
            .await
            .usage_samples
            .iter()
            .filter(|usage| usage.node_id == node_id)
            .max_by_key(|usage| usage.sampled_at)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("usage:{node_id}")))
    }

    pub async fn latest_usage_rollup_for_credential(
        &self,
        credential_id: &str,
        bucket: &str,
    ) -> StoreResult<UsageRollupRecord> {
        self.state
            .lock()
            .await
            .usage_rollups
            .values()
            .filter(|rollup| rollup.credential_id.as_deref() == Some(credential_id))
            .filter(|rollup| rollup.bucket == bucket)
            .max_by_key(|rollup| rollup.bucket_start)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("usage_rollup:{credential_id}:{bucket}")))
    }

    pub async fn set_credential_quota(
        &self,
        credential_id: &str,
        quota_bytes: i64,
    ) -> StoreResult<()> {
        self.state
            .lock()
            .await
            .credential_quotas
            .insert(credential_id.to_owned(), quota_bytes);
        Ok(())
    }

    pub async fn credential_quota_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialQuotaDecision> {
        let state = self.state.lock().await;
        let quota_bytes = *state
            .credential_quotas
            .get(credential_id)
            .ok_or_else(|| StoreError::NotFound(format!("credential_quota:{credential_id}")))?;
        let used_bytes = state
            .usage_rollups
            .values()
            .filter(|rollup| rollup.credential_id.as_deref() == Some(credential_id))
            .filter(|rollup| rollup.bucket == "hour")
            .map(|rollup| rollup.uplink_bytes + rollup.downlink_bytes)
            .sum();
        Ok(quota_decision(credential_id, quota_bytes, used_bytes))
    }

    pub async fn set_credential_expiry(
        &self,
        credential_id: &str,
        expires_at: DateTime<Utc>,
    ) -> StoreResult<()> {
        self.state
            .lock()
            .await
            .credential_expirations
            .insert(credential_id.to_owned(), expires_at);
        Ok(())
    }

    pub async fn credential_expiry_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialExpiryDecision> {
        let state = self.state.lock().await;
        if !state
            .credentials_by_profile
            .values()
            .flatten()
            .any(|credential| credential.id == credential_id)
        {
            return Err(StoreError::NotFound(format!("credential:{credential_id}")));
        }
        Ok(expiry_decision(
            credential_id,
            state.credential_expirations.get(credential_id).copied(),
            Utc::now(),
        ))
    }

    pub async fn enqueue_runner_command(
        &self,
        node_id: &str,
        command: SignedRunnerCommand,
    ) -> StoreResult<()> {
        self.state
            .lock()
            .await
            .runner_commands
            .entry(node_id.to_owned())
            .or_default()
            .push_back(command);
        Ok(())
    }

    pub async fn next_runner_command(
        &self,
        node_id: &str,
        last_sequence: u64,
    ) -> StoreResult<Option<SignedRunnerCommand>> {
        let mut state = self.state.lock().await;
        let Some(queue) = state.runner_commands.get_mut(node_id) else {
            return Ok(None);
        };
        while let Some(front) = queue.front() {
            if front.command.sequence <= last_sequence {
                queue.pop_front();
            } else {
                break;
            }
        }
        Ok(queue.pop_front())
    }

    pub async fn node(&self, node_id: &str) -> StoreResult<NodeRecord> {
        self.state
            .lock()
            .await
            .nodes
            .get(node_id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("node:{node_id}")))
    }

    pub async fn update_node_runner_result_public_key(
        &self,
        node_id: &str,
        public_key_hex: &str,
    ) -> StoreResult<NodeRecord> {
        let mut state = self.state.lock().await;
        let node = state
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| StoreError::NotFound(format!("node:{node_id}")))?;
        node.runner_result_public_key_hex = public_key_hex.into();
        let node = node.clone();
        Self::record(
            &mut state,
            &self.tenant_id,
            "admin",
            "node.runner_result_key_rotated",
            "node",
            node_id,
        );
        Ok(node)
    }

    pub async fn profile(&self, profile_id: &str) -> StoreResult<ProfileRecord> {
        self.state
            .lock()
            .await
            .profiles
            .get(profile_id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("profile:{profile_id}")))
    }

    pub async fn credentials_for_profile(&self, profile_id: &str) -> StoreResult<Vec<Credential>> {
        Ok(self
            .state
            .lock()
            .await
            .credentials_by_profile
            .get(profile_id)
            .cloned()
            .unwrap_or_default())
    }

    pub async fn audit_count(&self) -> StoreResult<usize> {
        Ok(self.state.lock().await.audit_events.len())
    }

    pub async fn outbox_count(&self) -> StoreResult<usize> {
        Ok(self.state.lock().await.outbox.len())
    }

    pub async fn deployed_profile_for_subscription(
        &self,
        profile_id: &str,
    ) -> StoreResult<DeployedProfile> {
        let state = self.state.lock().await;
        let profile = state
            .profiles
            .get(profile_id)
            .ok_or_else(|| StoreError::NotFound(format!("profile:{profile_id}")))?;
        let node = state
            .nodes
            .values()
            .next()
            .ok_or_else(|| StoreError::NotFound("node:any".into()))?;
        let first_inbound = profile
            .ir
            .inbounds
            .first()
            .ok_or_else(|| StoreError::NotFound("profile inbound".into()))?;
        let server_name = match &first_inbound.security {
            Security::Reality { server_name, .. } | Security::Tls { server_name } => {
                server_name.clone()
            }
            Security::None => node.host.clone(),
        };
        let mut deployed =
            DeployedProfile::new(profile_id, &node.host, first_inbound.port, &server_name);
        for credential in state
            .credentials_by_profile
            .get(profile_id)
            .cloned()
            .unwrap_or_default()
        {
            if credential_quota_exceeded_in_memory(&state, &credential.id) {
                continue;
            }
            if credential_expired_in_memory(&state, &credential.id, Utc::now()) {
                continue;
            }
            deployed = deployed.with_credential(credential);
        }
        Ok(deployed)
    }

    pub async fn issue_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken> {
        let mut state = self.state.lock().await;
        if !state.profiles.contains_key(profile_id) {
            return Err(StoreError::NotFound(format!("profile:{profile_id}")));
        }
        let issued = new_subscription_token(profile_id);
        state.subscription_tokens.insert(
            issued.token_id.clone(),
            subscription_token_record(&self.tenant_id, &issued),
        );
        Self::record(
            &mut state,
            &self.tenant_id,
            "admin",
            "subscription_token.issued",
            "profile",
            profile_id,
        );
        Ok(issued)
    }

    pub async fn rotate_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken> {
        let mut state = self.state.lock().await;
        if !state.profiles.contains_key(profile_id) {
            return Err(StoreError::NotFound(format!("profile:{profile_id}")));
        }
        let now = Utc::now();
        for token in state
            .subscription_tokens
            .values_mut()
            .filter(|token| token.profile_id == profile_id && token.status == "active")
        {
            token.status = "rotated".into();
            token.rotated_at = Some(now);
        }
        let issued = new_subscription_token(profile_id);
        state.subscription_tokens.insert(
            issued.token_id.clone(),
            subscription_token_record(&self.tenant_id, &issued),
        );
        Self::record(
            &mut state,
            &self.tenant_id,
            "admin",
            "subscription_token.rotated",
            "profile",
            profile_id,
        );
        Ok(issued)
    }

    pub async fn verify_subscription_token(
        &self,
        profile_id: &str,
        token: &str,
    ) -> StoreResult<SubscriptionTokenRecord> {
        let token_hash = subscription_token_hash(token);
        self.state
            .lock()
            .await
            .subscription_tokens
            .values()
            .find(|record| {
                record.profile_id == profile_id
                    && record.token_hash == token_hash
                    && record.status == "active"
            })
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("subscription_token:{profile_id}")))
    }

    pub async fn subscription_token_required(&self, profile_id: &str) -> StoreResult<bool> {
        let state = self.state.lock().await;
        if !state.profiles.contains_key(profile_id) {
            return Err(StoreError::NotFound(format!("profile:{profile_id}")));
        }
        Ok(state
            .subscription_tokens
            .values()
            .any(|token| token.profile_id == profile_id && token.status == "active"))
    }

    pub async fn record_subscription_access(
        &self,
        token_id: &str,
        remote_addr: Option<String>,
        user_agent: Option<String>,
        status: &str,
    ) -> StoreResult<()> {
        let mut state = self.state.lock().await;
        if !state.subscription_tokens.contains_key(token_id) {
            return Err(StoreError::NotFound(format!(
                "subscription_token:{token_id}"
            )));
        }
        state
            .subscription_access_logs
            .push(SubscriptionAccessLogRecord {
                token_id: token_id.into(),
                remote_addr,
                user_agent,
                status: status.into(),
                created_at: Utc::now(),
            });
        Ok(())
    }

    pub async fn subscription_access_log_count(&self, token_id: &str) -> StoreResult<usize> {
        Ok(self
            .state
            .lock()
            .await
            .subscription_access_logs
            .iter()
            .filter(|log| log.token_id == token_id)
            .count())
    }

    fn record(
        state: &mut MemoryState,
        tenant_id: &str,
        actor: &str,
        action: &str,
        aggregate_type: &str,
        aggregate_id: &str,
    ) {
        let now = Utc::now();
        state.audit_events.push(AuditEventRecord {
            tenant_id: tenant_id.into(),
            actor: actor.into(),
            action: action.into(),
            subject: format!("{aggregate_type}:{aggregate_id}"),
            created_at: now,
        });
        state.outbox.push(OutboxEventRecord {
            tenant_id: tenant_id.into(),
            event_type: action.into(),
            aggregate_type: aggregate_type.into(),
            aggregate_id: aggregate_id.into(),
            status: "pending".into(),
            created_at: now,
        });
    }
}

#[async_trait]
impl ProxyStore for MemoryStore {
    async fn register_node(&self, node: NodeRecord) -> StoreResult<()> {
        MemoryStore::register_node(self, node).await
    }
    async fn register_node_with_registration_token(
        &self,
        node: NodeRecord,
        registration_token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        MemoryStore::register_node_with_registration_token(self, node, registration_token).await
    }
    async fn list_nodes(&self) -> StoreResult<Vec<NodeRecord>> {
        MemoryStore::list_nodes(self).await
    }
    async fn create_node_registration_token(
        &self,
        token: NodeRegistrationTokenRecord,
    ) -> StoreResult<()> {
        MemoryStore::create_node_registration_token(self, token).await
    }
    async fn list_node_registration_tokens(&self) -> StoreResult<Vec<NodeRegistrationTokenRecord>> {
        MemoryStore::list_node_registration_tokens(self).await
    }
    async fn node_registration_token(
        &self,
        token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        MemoryStore::node_registration_token(self, token).await
    }
    async fn consume_node_registration_token(
        &self,
        token: &str,
        node_id: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        MemoryStore::consume_node_registration_token(self, token, node_id).await
    }
    async fn record_heartbeat(&self, heartbeat: HeartbeatRecord) -> StoreResult<()> {
        MemoryStore::record_heartbeat(self, heartbeat).await
    }
    async fn latest_heartbeat(&self, node_id: &str) -> StoreResult<HeartbeatRecord> {
        MemoryStore::latest_heartbeat(self, node_id).await
    }
    async fn create_profile(&self, profile: ProfileRecord) -> StoreResult<()> {
        MemoryStore::create_profile(self, profile).await
    }
    async fn list_profiles(&self) -> StoreResult<Vec<ProfileRecord>> {
        MemoryStore::list_profiles(self).await
    }
    async fn add_credential(&self, profile_id: &str, credential: Credential) -> StoreResult<()> {
        MemoryStore::add_credential(self, profile_id, credential).await
    }
    async fn list_credentials(&self) -> StoreResult<Vec<CredentialRecord>> {
        MemoryStore::list_credentials(self).await
    }
    async fn record_artifact(&self, artifact: Artifact) -> StoreResult<()> {
        MemoryStore::record_artifact(self, artifact).await
    }
    async fn record_artifact_blob(&self, artifact: Artifact, bytes: Vec<u8>) -> StoreResult<()> {
        MemoryStore::record_artifact_blob(self, artifact, bytes).await
    }
    async fn artifact_bytes(&self, artifact_id: &str) -> StoreResult<Vec<u8>> {
        MemoryStore::artifact_bytes(self, artifact_id).await
    }
    async fn artifact_bytes_by_sha256(&self, sha256: &str) -> StoreResult<Vec<u8>> {
        MemoryStore::artifact_bytes_by_sha256(self, sha256).await
    }
    async fn record_deployment_plan(&self, deployment: DeploymentPlanRecord) -> StoreResult<()> {
        MemoryStore::record_deployment_plan(self, deployment).await
    }
    async fn idempotency_response(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> StoreResult<Option<serde_json::Value>> {
        MemoryStore::idempotency_response(self, tenant_id, key).await
    }
    async fn record_idempotency_response(
        &self,
        tenant_id: &str,
        key: &str,
        response_json: serde_json::Value,
    ) -> StoreResult<()> {
        MemoryStore::record_idempotency_response(self, tenant_id, key, response_json).await
    }
    async fn record_deployment_result(&self, result: DeploymentResult) -> StoreResult<()> {
        MemoryStore::record_deployment_result(self, result).await
    }
    async fn deployment_status(&self, deployment_id: &str) -> StoreResult<DeploymentStatus> {
        MemoryStore::deployment_status(self, deployment_id).await
    }
    async fn rollback_pointer(&self, deployment_id: &str) -> StoreResult<RollbackPointerRecord> {
        MemoryStore::rollback_pointer(self, deployment_id).await
    }
    async fn deployment_snapshot(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentSnapshotRecord> {
        MemoryStore::deployment_snapshot(self, deployment_id).await
    }
    async fn latest_deployment_health(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentHealthCheckRecord> {
        MemoryStore::latest_deployment_health(self, deployment_id).await
    }
    async fn record_deployment_health_check(
        &self,
        health: DeploymentHealthCheckRecord,
    ) -> StoreResult<()> {
        MemoryStore::record_deployment_health_check(self, health).await
    }
    async fn deployment_health_checks(
        &self,
        deployment_id: &str,
    ) -> StoreResult<Vec<DeploymentHealthCheckRecord>> {
        MemoryStore::deployment_health_checks(self, deployment_id).await
    }
    async fn record_usage_sample(&self, usage: UsageSampleRecord) -> StoreResult<()> {
        MemoryStore::record_usage_sample(self, usage).await
    }
    async fn latest_usage_sample(&self, node_id: &str) -> StoreResult<UsageSampleRecord> {
        MemoryStore::latest_usage_sample(self, node_id).await
    }
    async fn latest_usage_rollup_for_credential(
        &self,
        credential_id: &str,
        bucket: &str,
    ) -> StoreResult<UsageRollupRecord> {
        MemoryStore::latest_usage_rollup_for_credential(self, credential_id, bucket).await
    }
    async fn set_credential_quota(&self, credential_id: &str, quota_bytes: i64) -> StoreResult<()> {
        MemoryStore::set_credential_quota(self, credential_id, quota_bytes).await
    }
    async fn credential_quota_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialQuotaDecision> {
        MemoryStore::credential_quota_decision(self, credential_id).await
    }
    async fn set_credential_expiry(
        &self,
        credential_id: &str,
        expires_at: DateTime<Utc>,
    ) -> StoreResult<()> {
        MemoryStore::set_credential_expiry(self, credential_id, expires_at).await
    }
    async fn credential_expiry_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialExpiryDecision> {
        MemoryStore::credential_expiry_decision(self, credential_id).await
    }
    async fn enqueue_runner_command(
        &self,
        node_id: &str,
        command: SignedRunnerCommand,
    ) -> StoreResult<()> {
        MemoryStore::enqueue_runner_command(self, node_id, command).await
    }
    async fn next_runner_command(
        &self,
        node_id: &str,
        last_sequence: u64,
    ) -> StoreResult<Option<SignedRunnerCommand>> {
        MemoryStore::next_runner_command(self, node_id, last_sequence).await
    }
    async fn node(&self, node_id: &str) -> StoreResult<NodeRecord> {
        MemoryStore::node(self, node_id).await
    }
    async fn update_node_runner_result_public_key(
        &self,
        node_id: &str,
        public_key_hex: &str,
    ) -> StoreResult<NodeRecord> {
        MemoryStore::update_node_runner_result_public_key(self, node_id, public_key_hex).await
    }
    async fn profile(&self, profile_id: &str) -> StoreResult<ProfileRecord> {
        MemoryStore::profile(self, profile_id).await
    }
    async fn credentials_for_profile(&self, profile_id: &str) -> StoreResult<Vec<Credential>> {
        MemoryStore::credentials_for_profile(self, profile_id).await
    }
    async fn audit_count(&self) -> StoreResult<usize> {
        MemoryStore::audit_count(self).await
    }
    async fn outbox_count(&self) -> StoreResult<usize> {
        MemoryStore::outbox_count(self).await
    }
    async fn deployed_profile_for_subscription(
        &self,
        profile_id: &str,
    ) -> StoreResult<DeployedProfile> {
        MemoryStore::deployed_profile_for_subscription(self, profile_id).await
    }
    async fn issue_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken> {
        MemoryStore::issue_subscription_token(self, profile_id).await
    }
    async fn rotate_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken> {
        MemoryStore::rotate_subscription_token(self, profile_id).await
    }
    async fn verify_subscription_token(
        &self,
        profile_id: &str,
        token: &str,
    ) -> StoreResult<SubscriptionTokenRecord> {
        MemoryStore::verify_subscription_token(self, profile_id, token).await
    }
    async fn subscription_token_required(&self, profile_id: &str) -> StoreResult<bool> {
        MemoryStore::subscription_token_required(self, profile_id).await
    }
    async fn record_subscription_access(
        &self,
        token_id: &str,
        remote_addr: Option<String>,
        user_agent: Option<String>,
        status: &str,
    ) -> StoreResult<()> {
        MemoryStore::record_subscription_access(self, token_id, remote_addr, user_agent, status)
            .await
    }
    async fn subscription_access_log_count(&self, token_id: &str) -> StoreResult<usize> {
        MemoryStore::subscription_access_log_count(self, token_id).await
    }
    fn kind(&self) -> &'static str {
        "memory"
    }
}

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
    lazy: bool,
}

impl PostgresStore {
    pub fn connect_lazy(database_url: &str) -> StoreResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_lazy(database_url)?;
        Ok(Self { pool, lazy: true })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool, lazy: false }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn is_lazy(&self) -> bool {
        self.lazy
    }

    pub async fn register_node(&self, node: NodeRecord) -> StoreResult<()> {
        sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT (id) DO NOTHING")
            .bind(&node.tenant_id)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"INSERT INTO nodes (id, tenant_id, display_name, status)
               VALUES ($1, $2, $1, 'registered')
               ON CONFLICT (id) DO UPDATE SET status = 'registered'"#,
        )
        .bind(&node.node_id)
        .bind(&node.tenant_id)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"INSERT INTO node_capabilities (node_id, xray_version, capabilities_json)
               VALUES ($1, $2, $3)"#,
        )
        .bind(&node.node_id)
        .bind(&node.xray_version)
        .bind(serde_json::json!({"host": node.host, "xray_version": node.xray_version}))
        .execute(&self.pool)
        .await?;
        if !node.runner_result_public_key_hex.is_empty() {
            sqlx::query(
                r#"INSERT INTO node_identities (node_id, public_key, registered_at)
                   VALUES ($1, $2, now())
                   ON CONFLICT (node_id) DO UPDATE
                   SET public_key = EXCLUDED.public_key,
                       registered_at = COALESCE(node_identities.registered_at, EXCLUDED.registered_at)"#,
            )
            .bind(&node.node_id)
            .bind(&node.runner_result_public_key_hex)
            .execute(&self.pool)
            .await?;
        }
        self.record_event(
            &node.tenant_id,
            "runner",
            "node.registered",
            "node",
            &node.node_id,
        )
        .await?;
        Ok(())
    }

    pub async fn register_node_with_registration_token(
        &self,
        node: NodeRecord,
        registration_token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT (id) DO NOTHING")
            .bind(&node.tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            r#"INSERT INTO nodes (id, tenant_id, display_name, status)
               VALUES ($1, $2, $1, 'registered')
               ON CONFLICT (id) DO UPDATE SET status = 'registered'"#,
        )
        .bind(&node.node_id)
        .bind(&node.tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"INSERT INTO node_capabilities (node_id, xray_version, capabilities_json)
               VALUES ($1, $2, $3)"#,
        )
        .bind(&node.node_id)
        .bind(&node.xray_version)
        .bind(serde_json::json!({"host": node.host, "xray_version": node.xray_version}))
        .execute(&mut *tx)
        .await?;
        if !node.runner_result_public_key_hex.is_empty() {
            sqlx::query(
                r#"INSERT INTO node_identities (node_id, public_key, registered_at)
                   VALUES ($1, $2, now())
                   ON CONFLICT (node_id) DO UPDATE
                   SET public_key = EXCLUDED.public_key,
                       registered_at = COALESCE(node_identities.registered_at, EXCLUDED.registered_at)"#,
            )
            .bind(&node.node_id)
            .bind(&node.runner_result_public_key_hex)
            .execute(&mut *tx)
            .await?;
        }

        let token_row = sqlx::query(
            r#"UPDATE node_registration_tokens
               SET status = 'used', consumed_at = now(), used_by_node_id = $2
               WHERE token = $1 AND status = 'active'
               RETURNING id, tenant_id, token, status, created_at, consumed_at, used_by_node_id"#,
        )
        .bind(registration_token)
        .bind(&node.node_id)
        .fetch_optional(&mut *tx)
        .await?;
        let token = match token_row {
            Some(row) => node_registration_token_from_row(row)?,
            None => {
                let exists =
                    sqlx::query("SELECT status FROM node_registration_tokens WHERE token = $1")
                        .bind(registration_token)
                        .fetch_optional(&mut *tx)
                        .await?;
                return match exists {
                    Some(_) => Err(StoreError::Conflict(
                        "registration token already consumed".into(),
                    )),
                    None => Err(StoreError::NotFound("node_registration_token".into())),
                };
            }
        };

        record_event_in_tx(
            &mut tx,
            &node.tenant_id,
            "runner",
            "node.registered",
            "node",
            &node.node_id,
        )
        .await?;
        record_event_in_tx(
            &mut tx,
            &token.tenant_id,
            "runner",
            "node_registration_token.used",
            "node_registration_token",
            &token.token_id,
        )
        .await?;
        tx.commit().await?;
        Ok(token)
    }

    pub async fn record_heartbeat(&self, heartbeat: HeartbeatRecord) -> StoreResult<()> {
        let session_id = format!("{}-dev-session", heartbeat.node_id);
        sqlx::query(
            r#"INSERT INTO runner_sessions (id, node_id)
               VALUES ($1, $2)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(&session_id)
        .bind(&heartbeat.node_id)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"INSERT INTO node_heartbeats (node_id, session_id, payload_json)
               VALUES ($1, $2, $3)"#,
        )
        .bind(&heartbeat.node_id)
        .bind(&session_id)
        .bind(&heartbeat.capability_snapshot)
        .execute(&self.pool)
        .await?;
        self.record_event(
            &heartbeat.tenant_id,
            "runner",
            "node.heartbeat",
            "node",
            &heartbeat.node_id,
        )
        .await?;
        Ok(())
    }

    pub async fn latest_heartbeat(&self, node_id: &str) -> StoreResult<HeartbeatRecord> {
        let row = sqlx::query(
            r#"SELECT n.tenant_id, h.node_id, h.payload_json, h.created_at
               FROM node_heartbeats h
               JOIN nodes n ON n.id = h.node_id
               WHERE h.node_id = $1
               ORDER BY h.created_at DESC
               LIMIT 1"#,
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("heartbeat:{node_id}")))?;
        Ok(HeartbeatRecord {
            tenant_id: row.try_get("tenant_id")?,
            node_id: row.try_get("node_id")?,
            capability_snapshot: row.try_get("payload_json")?,
            created_at: row.try_get("created_at")?,
        })
    }

    pub async fn create_profile(&self, profile: ProfileRecord) -> StoreResult<()> {
        sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT (id) DO NOTHING")
            .bind(&profile.tenant_id)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"INSERT INTO profiles (id, tenant_id, name)
               VALUES ($1, $2, $1)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(&profile.profile_id)
        .bind(&profile.tenant_id)
        .execute(&self.pool)
        .await?;
        let ir_json = serde_json::to_value(&profile.ir).expect("Profile IR serializes");
        let input_hash =
            hex_sha256(serde_json::to_vec(&ir_json).expect("Profile IR JSON serializes"));
        let version_id = format!("{}-v1", profile.profile_id);
        sqlx::query(
            r#"INSERT INTO profile_versions
               (id, tenant_id, profile_id, version, ir_json, schema_version, compiler_version,
                target_core_kind, target_core_version, feature_flags, assets_version, input_hash, created_by)
               VALUES ($1, $2, $3, 1, $4, $5, NULL, 'xray', $6, '{}', 'dev', $7, 'admin')
               ON CONFLICT (profile_id, version) DO NOTHING"#,
        )
        .bind(&version_id)
        .bind(&profile.tenant_id)
        .bind(&profile.profile_id)
        .bind(ir_json)
        .bind(&profile.ir.schema_version)
        .bind(&profile.ir.runtime.core_version)
        .bind(input_hash)
        .execute(&self.pool)
        .await?;
        self.record_event(
            &profile.tenant_id,
            "admin",
            "profile.created",
            "profile",
            &profile.profile_id,
        )
        .await?;
        Ok(())
    }

    pub async fn list_profiles(&self) -> StoreResult<Vec<ProfileRecord>> {
        let rows = sqlx::query(
            r#"SELECT DISTINCT ON (profile_id) tenant_id, profile_id, ir_json, created_at
               FROM profile_versions
               ORDER BY profile_id ASC, version DESC"#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let tenant_id: String = row.try_get("tenant_id")?;
                let profile_id: String = row.try_get("profile_id")?;
                let ir_json: serde_json::Value = row.try_get("ir_json")?;
                let created_at: DateTime<Utc> = row.try_get("created_at")?;
                Ok(ProfileRecord {
                    tenant_id,
                    profile_id,
                    ir: serde_json::from_value(ir_json)?,
                    created_at,
                })
            })
            .collect()
    }

    pub async fn add_credential(
        &self,
        profile_id: &str,
        credential: Credential,
    ) -> StoreResult<()> {
        let row = sqlx::query("SELECT tenant_id FROM profiles WHERE id = $1")
            .bind(profile_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| StoreError::NotFound(format!("profile:{profile_id}")))?;
        let tenant_id: String = row.try_get("tenant_id")?;
        sqlx::query(
            r#"INSERT INTO clients (id, tenant_id, display_name, status)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name, status = EXCLUDED.status"#,
        )
        .bind(&credential.id)
        .bind(&tenant_id)
        .bind(&credential.display_name)
        .bind(format!("{:?}", credential.status).to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
        let (kind, secret_ref) = match &credential.material {
            CredentialMaterial::VlessUuid { .. } => {
                ("vless_uuid", format!("secret:{}", credential.id))
            }
            CredentialMaterial::ShadowsocksPassword { .. } => {
                ("shadowsocks_password", format!("secret:{}", credential.id))
            }
            CredentialMaterial::TrojanPassword { .. } => {
                ("trojan_password", format!("secret:{}", credential.id))
            }
        };
        let material_bytes = serde_json::to_vec(&credential.material)?;
        sqlx::query(
            r#"INSERT INTO secrets (id, tenant_id, kind, ciphertext, key_id)
               VALUES ($1, $2, $3, $4, 'dev-local')
               ON CONFLICT (id) DO UPDATE SET ciphertext = EXCLUDED.ciphertext"#,
        )
        .bind(&secret_ref)
        .bind(&tenant_id)
        .bind(kind)
        .bind(material_bytes)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"INSERT INTO credentials (id, tenant_id, client_id, client_group_id, kind, secret_ref, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status"#,
        )
        .bind(&credential.id)
        .bind(&tenant_id)
        .bind(&credential.id)
        .bind(&credential.client_group_id)
        .bind(kind)
        .bind(secret_ref)
        .bind(format!("{:?}", credential.status).to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"INSERT INTO profile_credentials (profile_id, credential_id)
               VALUES ($1, $2) ON CONFLICT DO NOTHING"#,
        )
        .bind(profile_id)
        .bind(&credential.id)
        .execute(&self.pool)
        .await?;
        self.record_event(
            &tenant_id,
            "admin",
            "client.created",
            "client",
            &credential.id,
        )
        .await?;
        Ok(())
    }

    pub async fn list_credentials(&self) -> StoreResult<Vec<CredentialRecord>> {
        let rows = sqlx::query(
            r#"SELECT pc.profile_id, c.id, c.client_group_id, c.status, cl.display_name, s.ciphertext
               FROM profile_credentials pc
               JOIN credentials c ON c.id = pc.credential_id
               JOIN clients cl ON cl.id = c.client_id
               JOIN secrets s ON s.id = c.secret_ref
               ORDER BY pc.profile_id ASC, c.created_at ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut credentials = Vec::with_capacity(rows.len());
        for row in rows {
            let profile_id: String = row.try_get("profile_id")?;
            let id: String = row.try_get("id")?;
            let client_group_id: String = row.try_get("client_group_id")?;
            let status_raw: String = row.try_get("status")?;
            let display_name: String = row.try_get("display_name")?;
            let ciphertext: Vec<u8> = row.try_get("ciphertext")?;
            let material: CredentialMaterial = serde_json::from_slice(&ciphertext)?;
            credentials.push(CredentialRecord {
                profile_id,
                credential: Credential {
                    id,
                    client_group_id,
                    display_name,
                    status: parse_credential_status(&status_raw),
                    material,
                },
            });
        }
        Ok(credentials)
    }

    pub async fn record_artifact(&self, artifact: Artifact) -> StoreResult<()> {
        sqlx::query(
            r#"INSERT INTO artifacts
               (id, tenant_id, kind, schema_version, media_type, sha256, storage_uri, redaction_status, created_by)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               ON CONFLICT (tenant_id, sha256) DO NOTHING"#,
        )
        .bind(&artifact.id)
        .bind(&artifact.tenant_id)
        .bind(format!("{:?}", artifact.kind))
        .bind(&artifact.schema_version)
        .bind(&artifact.media_type)
        .bind(&artifact.sha256)
        .bind(&artifact.storage_uri)
        .bind(format!("{:?}", artifact.redaction_status))
        .bind(&artifact.created_by)
        .execute(&self.pool)
        .await?;
        self.record_event(
            &artifact.tenant_id,
            "control-plane",
            "artifact.created",
            "artifact",
            &artifact.id,
        )
        .await?;
        Ok(())
    }

    pub async fn record_artifact_blob(
        &self,
        artifact: Artifact,
        bytes: Vec<u8>,
    ) -> StoreResult<()> {
        let actual = hex_sha256(bytes.clone());
        if actual != artifact.sha256 {
            return Err(StoreError::ArtifactShaMismatch {
                expected: artifact.sha256,
                actual,
            });
        }
        sqlx::query(
            r#"INSERT INTO artifact_blobs (sha256, bytes)
               VALUES ($1, $2)
               ON CONFLICT (sha256) DO NOTHING"#,
        )
        .bind(&artifact.sha256)
        .bind(bytes)
        .execute(&self.pool)
        .await?;
        self.record_artifact(artifact).await
    }

    pub async fn artifact_bytes(&self, artifact_id: &str) -> StoreResult<Vec<u8>> {
        let row = sqlx::query(
            r#"SELECT b.bytes
               FROM artifacts a
               JOIN artifact_blobs b ON b.sha256 = a.sha256
               WHERE a.id = $1"#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("artifact:{artifact_id}")))?;
        Ok(row.try_get("bytes")?)
    }

    pub async fn artifact_bytes_by_sha256(&self, sha256: &str) -> StoreResult<Vec<u8>> {
        let row = sqlx::query("SELECT bytes FROM artifact_blobs WHERE sha256 = $1")
            .bind(sha256)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| StoreError::NotFound(format!("artifact_blob:{sha256}")))?;
        Ok(row.try_get("bytes")?)
    }

    pub async fn record_deployment_plan(
        &self,
        deployment: DeploymentPlanRecord,
    ) -> StoreResult<()> {
        let previous = sqlx::query(
            r#"SELECT id, compiled_config_artifact_id
               FROM deployments
               WHERE tenant_id = $1 AND node_id = $2 AND status = 'Succeeded'
               ORDER BY finished_at DESC NULLS LAST, created_at DESC
               LIMIT 1"#,
        )
        .bind(&deployment.tenant_id)
        .bind(&deployment.node_id)
        .fetch_optional(&self.pool)
        .await?;
        let row = sqlx::query(
            "SELECT id FROM profile_versions WHERE profile_id = $1 ORDER BY version DESC LIMIT 1",
        )
        .bind(&deployment.profile_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| {
            StoreError::NotFound(format!("profile_version:{}", deployment.profile_id))
        })?;
        let profile_version_id: String = row.try_get("id")?;
        sqlx::query(
            r#"INSERT INTO deployments
               (id, tenant_id, node_id, profile_version_id, status, compiled_config_artifact_id)
               VALUES ($1, $2, $3, $4, 'Pending', $5)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(&deployment.deployment_id)
        .bind(&deployment.tenant_id)
        .bind(&deployment.node_id)
        .bind(profile_version_id)
        .bind(&deployment.compiled_config_artifact_id)
        .execute(&self.pool)
        .await?;
        let previous_deployment_id: Option<String> =
            previous.as_ref().map(|row| row.try_get("id")).transpose()?;
        let previous_artifact_id: Option<String> = previous
            .as_ref()
            .map(|row| row.try_get("compiled_config_artifact_id"))
            .transpose()?;
        let rollback_pointer =
            RollbackPointerRecord::new(&deployment, previous_deployment_id, previous_artifact_id);
        sqlx::query(
            r#"INSERT INTO rollback_pointers
               (id, tenant_id, deployment_id, previous_deployment_id,
                previous_compiled_config_artifact_id, target_compiled_config_artifact_id,
                previous_core_version, previous_assets_version, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(&rollback_pointer.rollback_pointer_id)
        .bind(&rollback_pointer.tenant_id)
        .bind(&rollback_pointer.deployment_id)
        .bind(&rollback_pointer.previous_deployment_id)
        .bind(&rollback_pointer.previous_compiled_config_artifact_id)
        .bind(&rollback_pointer.target_compiled_config_artifact_id)
        .bind(&rollback_pointer.previous_core_version)
        .bind(&rollback_pointer.previous_assets_version)
        .bind(rollback_pointer.created_at)
        .execute(&self.pool)
        .await?;
        sqlx::query("UPDATE deployments SET rollback_pointer_id = $2 WHERE id = $1")
            .bind(&deployment.deployment_id)
            .bind(&rollback_pointer.rollback_pointer_id)
            .execute(&self.pool)
            .await?;
        self.record_event(
            &deployment.tenant_id,
            "admin",
            "deployment.planned",
            "deployment",
            &deployment.deployment_id,
        )
        .await?;
        Ok(())
    }

    pub async fn idempotency_response(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> StoreResult<Option<serde_json::Value>> {
        let row = sqlx::query(
            r#"SELECT response_json
               FROM idempotency_keys
               WHERE tenant_id = $1 AND key = $2"#,
        )
        .bind(tenant_id)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => Ok(Some(row.try_get("response_json")?)),
            None => Ok(None),
        }
    }

    pub async fn record_idempotency_response(
        &self,
        tenant_id: &str,
        key: &str,
        response_json: serde_json::Value,
    ) -> StoreResult<()> {
        sqlx::query(
            r#"INSERT INTO idempotency_keys (tenant_id, key, response_json)
               VALUES ($1, $2, $3)
               ON CONFLICT (tenant_id, key) DO NOTHING"#,
        )
        .bind(tenant_id)
        .bind(key)
        .bind(response_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_deployment_result(&self, result: DeploymentResult) -> StoreResult<()> {
        let status = format!("{:?}", result.status);
        let deployment_row = sqlx::query(
            r#"SELECT d.tenant_id, d.id AS deployment_id, d.node_id,
                      pv.profile_id, d.compiled_config_artifact_id, d.created_at
               FROM deployments d
               JOIN profile_versions pv ON pv.id = d.profile_version_id
               WHERE d.id = $1"#,
        )
        .bind(&result.deployment_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("deployment:{}", result.deployment_id)))?;
        let rows = sqlx::query(
            r#"UPDATE deployments
               SET status = $2, finished_at = COALESCE(finished_at, now())
               WHERE id = $1"#,
        )
        .bind(&result.deployment_id)
        .bind(&status)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if rows == 0 {
            return Err(StoreError::NotFound(format!(
                "deployment:{}",
                result.deployment_id
            )));
        }
        let deployment = DeploymentPlanRecord {
            tenant_id: deployment_row.try_get("tenant_id")?,
            deployment_id: deployment_row.try_get("deployment_id")?,
            node_id: deployment_row.try_get("node_id")?,
            profile_id: deployment_row.try_get("profile_id")?,
            compiled_config_artifact_id: deployment_row.try_get("compiled_config_artifact_id")?,
            created_at: deployment_row.try_get("created_at")?,
        };
        let snapshot = DeploymentSnapshotRecord::from_result(&deployment, &result);
        sqlx::query(
            r#"INSERT INTO deployment_snapshots (id, deployment_id, snapshot_json, created_at)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (id) DO UPDATE
               SET snapshot_json = EXCLUDED.snapshot_json, created_at = EXCLUDED.created_at"#,
        )
        .bind(&snapshot.snapshot_id)
        .bind(&snapshot.deployment_id)
        .bind(serde_json::to_value(&snapshot)?)
        .bind(snapshot.created_at)
        .execute(&self.pool)
        .await?;
        let health = DeploymentHealthCheckRecord::from_result(&deployment, &result);
        sqlx::query(
            r#"INSERT INTO deployment_health_checks (deployment_id, status, payload_json, created_at)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(&health.deployment_id)
        .bind(&health.status)
        .bind(&health.payload_json)
        .bind(health.created_at)
        .execute(&self.pool)
        .await?;
        self.record_event(
            &deployment.tenant_id,
            "runner",
            "deployment.result",
            "deployment",
            &result.deployment_id,
        )
        .await?;
        Ok(())
    }

    pub async fn deployment_status(&self, deployment_id: &str) -> StoreResult<DeploymentStatus> {
        let row = sqlx::query("SELECT status FROM deployments WHERE id = $1")
            .bind(deployment_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| StoreError::NotFound(format!("deployment:{deployment_id}")))?;
        let status: String = row.try_get("status")?;
        Ok(parse_deployment_status(&status))
    }

    pub async fn rollback_pointer(
        &self,
        deployment_id: &str,
    ) -> StoreResult<RollbackPointerRecord> {
        let row = sqlx::query(
            r#"SELECT id, tenant_id, deployment_id, previous_deployment_id,
                      previous_compiled_config_artifact_id, target_compiled_config_artifact_id,
                      previous_core_version, previous_assets_version, created_at
               FROM rollback_pointers
               WHERE deployment_id = $1"#,
        )
        .bind(deployment_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("rollback_pointer:{deployment_id}")))?;
        Ok(RollbackPointerRecord {
            tenant_id: row.try_get("tenant_id")?,
            rollback_pointer_id: row.try_get("id")?,
            deployment_id: row.try_get("deployment_id")?,
            previous_deployment_id: row.try_get("previous_deployment_id")?,
            previous_compiled_config_artifact_id: row
                .try_get("previous_compiled_config_artifact_id")?,
            target_compiled_config_artifact_id: row
                .try_get("target_compiled_config_artifact_id")?,
            previous_core_version: row.try_get("previous_core_version")?,
            previous_assets_version: row.try_get("previous_assets_version")?,
            created_at: row.try_get("created_at")?,
        })
    }

    pub async fn deployment_snapshot(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentSnapshotRecord> {
        let row = sqlx::query(
            r#"SELECT snapshot_json
               FROM deployment_snapshots
               WHERE deployment_id = $1
               ORDER BY created_at DESC
               LIMIT 1"#,
        )
        .bind(deployment_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("deployment_snapshot:{deployment_id}")))?;
        let snapshot_json: serde_json::Value = row.try_get("snapshot_json")?;
        Ok(serde_json::from_value(snapshot_json)?)
    }

    pub async fn latest_deployment_health(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentHealthCheckRecord> {
        let row = sqlx::query(
            r#"SELECT d.tenant_id, h.deployment_id, d.node_id, h.status,
                      h.payload_json, h.created_at
               FROM deployment_health_checks h
               JOIN deployments d ON d.id = h.deployment_id
               WHERE h.deployment_id = $1
               ORDER BY h.created_at DESC
               LIMIT 1"#,
        )
        .bind(deployment_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("deployment_health:{deployment_id}")))?;
        Ok(DeploymentHealthCheckRecord {
            tenant_id: row.try_get("tenant_id")?,
            deployment_id: row.try_get("deployment_id")?,
            node_id: row.try_get("node_id")?,
            status: row.try_get("status")?,
            payload_json: row.try_get("payload_json")?,
            created_at: row.try_get("created_at")?,
        })
    }

    pub async fn record_deployment_health_check(
        &self,
        health: DeploymentHealthCheckRecord,
    ) -> StoreResult<()> {
        let row = sqlx::query("SELECT tenant_id, node_id FROM deployments WHERE id = $1")
            .bind(&health.deployment_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| StoreError::NotFound(format!("deployment:{}", health.deployment_id)))?;
        let node_id: String = row.try_get("node_id")?;
        if node_id != health.node_id {
            return Err(StoreError::NotFound(format!(
                "deployment:{}:node:{}",
                health.deployment_id, health.node_id
            )));
        }
        sqlx::query(
            r#"INSERT INTO deployment_health_checks
               (deployment_id, status, payload_json, created_at)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(&health.deployment_id)
        .bind(&health.status)
        .bind(&health.payload_json)
        .bind(health.created_at)
        .execute(&self.pool)
        .await?;
        let tenant_id: String = row.try_get("tenant_id")?;
        self.record_event(
            &tenant_id,
            "runner",
            "deployment.health",
            "deployment",
            &health.deployment_id,
        )
        .await?;
        Ok(())
    }

    pub async fn deployment_health_checks(
        &self,
        deployment_id: &str,
    ) -> StoreResult<Vec<DeploymentHealthCheckRecord>> {
        let exists = sqlx::query("SELECT 1 FROM deployments WHERE id = $1")
            .bind(deployment_id)
            .fetch_optional(&self.pool)
            .await?
            .is_some();
        if !exists {
            return Err(StoreError::NotFound(format!("deployment:{deployment_id}")));
        }
        let rows = sqlx::query(
            r#"SELECT d.tenant_id, h.deployment_id, d.node_id, h.status,
                      h.payload_json, h.created_at
               FROM deployment_health_checks h
               JOIN deployments d ON d.id = h.deployment_id
               WHERE h.deployment_id = $1
               ORDER BY h.created_at ASC, h.id ASC"#,
        )
        .bind(deployment_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(DeploymentHealthCheckRecord {
                    tenant_id: row.try_get("tenant_id")?,
                    deployment_id: row.try_get("deployment_id")?,
                    node_id: row.try_get("node_id")?,
                    status: row.try_get("status")?,
                    payload_json: row.try_get("payload_json")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    pub async fn record_usage_sample(&self, usage: UsageSampleRecord) -> StoreResult<()> {
        sqlx::query(
            r#"INSERT INTO usage_records
               (tenant_id, node_id, credential_id, uplink_bytes, downlink_bytes, sampled_at)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(&usage.tenant_id)
        .bind(&usage.node_id)
        .bind(&usage.credential_id)
        .bind(usage.uplink_bytes)
        .bind(usage.downlink_bytes)
        .bind(usage.sampled_at)
        .execute(&self.pool)
        .await?;
        for (bucket, bucket_start) in usage_bucket_starts(usage.sampled_at) {
            sqlx::query(
                r#"INSERT INTO usage_rollups
                   (tenant_id, credential_id, bucket, bucket_start, uplink_bytes, downlink_bytes)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (tenant_id, credential_id, bucket, bucket_start)
                   DO UPDATE SET
                     uplink_bytes = usage_rollups.uplink_bytes + EXCLUDED.uplink_bytes,
                     downlink_bytes = usage_rollups.downlink_bytes + EXCLUDED.downlink_bytes"#,
            )
            .bind(&usage.tenant_id)
            .bind(&usage.credential_id)
            .bind(bucket)
            .bind(bucket_start)
            .bind(usage.uplink_bytes)
            .bind(usage.downlink_bytes)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn latest_usage_sample(&self, node_id: &str) -> StoreResult<UsageSampleRecord> {
        let row = sqlx::query(
            r#"SELECT tenant_id, node_id, credential_id, uplink_bytes, downlink_bytes, sampled_at
               FROM usage_records
               WHERE node_id = $1
               ORDER BY sampled_at DESC
               LIMIT 1"#,
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("usage:{node_id}")))?;
        Ok(UsageSampleRecord {
            tenant_id: row.try_get("tenant_id")?,
            node_id: row.try_get("node_id")?,
            credential_id: row.try_get("credential_id")?,
            uplink_bytes: row.try_get("uplink_bytes")?,
            downlink_bytes: row.try_get("downlink_bytes")?,
            sampled_at: row.try_get("sampled_at")?,
        })
    }

    pub async fn latest_usage_rollup_for_credential(
        &self,
        credential_id: &str,
        bucket: &str,
    ) -> StoreResult<UsageRollupRecord> {
        let row = sqlx::query(
            r#"SELECT tenant_id, credential_id, bucket, bucket_start, uplink_bytes, downlink_bytes
               FROM usage_rollups
               WHERE credential_id = $1 AND bucket = $2
               ORDER BY bucket_start DESC
               LIMIT 1"#,
        )
        .bind(credential_id)
        .bind(bucket)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("usage_rollup:{credential_id}:{bucket}")))?;
        Ok(UsageRollupRecord {
            tenant_id: row.try_get("tenant_id")?,
            credential_id: row.try_get("credential_id")?,
            bucket: row.try_get("bucket")?,
            bucket_start: row.try_get("bucket_start")?,
            uplink_bytes: row.try_get("uplink_bytes")?,
            downlink_bytes: row.try_get("downlink_bytes")?,
        })
    }

    pub async fn set_credential_quota(
        &self,
        credential_id: &str,
        quota_bytes: i64,
    ) -> StoreResult<()> {
        sqlx::query(
            r#"INSERT INTO credential_quotas (credential_id, quota_bytes)
               VALUES ($1, $2)
               ON CONFLICT (credential_id)
               DO UPDATE SET quota_bytes = EXCLUDED.quota_bytes, updated_at = now()"#,
        )
        .bind(credential_id)
        .bind(quota_bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn credential_quota_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialQuotaDecision> {
        let quota_row = sqlx::query(
            r#"SELECT quota_bytes
               FROM credential_quotas
               WHERE credential_id = $1"#,
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("credential_quota:{credential_id}")))?;
        let quota_bytes: i64 = quota_row.try_get("quota_bytes")?;

        let used_row = sqlx::query(
            r#"SELECT COALESCE(SUM(uplink_bytes + downlink_bytes), 0)::bigint AS used_bytes
               FROM usage_rollups
               WHERE credential_id = $1 AND bucket = 'hour'"#,
        )
        .bind(credential_id)
        .fetch_one(&self.pool)
        .await?;
        let used_bytes: i64 = used_row.try_get("used_bytes")?;
        Ok(quota_decision(credential_id, quota_bytes, used_bytes))
    }

    pub async fn set_credential_expiry(
        &self,
        credential_id: &str,
        expires_at: DateTime<Utc>,
    ) -> StoreResult<()> {
        let rows = sqlx::query("UPDATE credentials SET expires_at = $2 WHERE id = $1")
            .bind(credential_id)
            .bind(expires_at)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if rows == 0 {
            return Err(StoreError::NotFound(format!("credential:{credential_id}")));
        }
        Ok(())
    }

    pub async fn credential_expiry_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialExpiryDecision> {
        let row = sqlx::query("SELECT expires_at FROM credentials WHERE id = $1")
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| StoreError::NotFound(format!("credential:{credential_id}")))?;
        Ok(expiry_decision(
            credential_id,
            row.try_get("expires_at")?,
            Utc::now(),
        ))
    }

    pub async fn enqueue_runner_command(
        &self,
        node_id: &str,
        command: SignedRunnerCommand,
    ) -> StoreResult<()> {
        let envelope_json = serde_json::to_value(&command)?;
        sqlx::query(
            r#"INSERT INTO runner_commands (tenant_id, node_id, sequence, envelope_json, status)
               VALUES ($1, $2, $3, $4, 'pending')
               ON CONFLICT (node_id, sequence) DO NOTHING"#,
        )
        .bind(&command.command.tenant_id)
        .bind(node_id)
        .bind(command.command.sequence as i64)
        .bind(envelope_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn next_runner_command(
        &self,
        node_id: &str,
        last_sequence: u64,
    ) -> StoreResult<Option<SignedRunnerCommand>> {
        sqlx::query(
            "UPDATE runner_commands SET status = 'skipped' WHERE node_id = $1 AND sequence <= $2 AND status = 'pending'",
        )
        .bind(node_id)
        .bind(last_sequence as i64)
        .execute(&self.pool)
        .await?;
        let Some(row) = sqlx::query(
            r#"UPDATE runner_commands
               SET status = 'leased', leased_at = now()
               WHERE id = (
                 SELECT id FROM runner_commands
                 WHERE node_id = $1 AND sequence > $2 AND status = 'pending'
                 ORDER BY sequence ASC
                 LIMIT 1
               )
               RETURNING envelope_json"#,
        )
        .bind(node_id)
        .bind(last_sequence as i64)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        let envelope_json: serde_json::Value = row.try_get("envelope_json")?;
        Ok(Some(serde_json::from_value(envelope_json)?))
    }

    pub async fn node(&self, node_id: &str) -> StoreResult<NodeRecord> {
        let row = sqlx::query(
            r#"SELECT n.tenant_id, n.id AS node_id, n.created_at,
                      nc.xray_version, nc.capabilities_json,
                      ni.public_key AS runner_result_public_key_hex
               FROM nodes n
               LEFT JOIN node_identities ni ON ni.node_id = n.id
               LEFT JOIN LATERAL (
                 SELECT xray_version, capabilities_json
                 FROM node_capabilities
                 WHERE node_id = n.id
                 ORDER BY created_at DESC
                 LIMIT 1
               ) nc ON true
               WHERE n.id = $1"#,
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("node:{node_id}")))?;
        let tenant_id: String = row.try_get("tenant_id")?;
        let node_id: String = row.try_get("node_id")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let xray_version: Option<String> = row.try_get("xray_version")?;
        let capabilities_json: Option<serde_json::Value> = row.try_get("capabilities_json")?;
        let runner_result_public_key_hex: Option<String> =
            row.try_get("runner_result_public_key_hex")?;
        let host = capabilities_json
            .as_ref()
            .and_then(|v| v.get("host"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{node_id}.example"));
        Ok(NodeRecord {
            tenant_id,
            node_id,
            host,
            xray_version: xray_version.unwrap_or_else(|| "unknown".into()),
            runner_result_public_key_hex: runner_result_public_key_hex.unwrap_or_default(),
            last_heartbeat_at: created_at,
        })
    }

    pub async fn list_nodes(&self) -> StoreResult<Vec<NodeRecord>> {
        let rows = sqlx::query(
            r#"SELECT n.tenant_id, n.id AS node_id, n.created_at,
                      nc.xray_version, nc.capabilities_json,
                      ni.public_key AS runner_result_public_key_hex
               FROM nodes n
               LEFT JOIN node_identities ni ON ni.node_id = n.id
               LEFT JOIN LATERAL (
                 SELECT xray_version, capabilities_json
                 FROM node_capabilities
                 WHERE node_id = n.id
                 ORDER BY created_at DESC
                 LIMIT 1
               ) nc ON true
               ORDER BY n.id"#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let tenant_id: String = row.try_get("tenant_id")?;
                let node_id: String = row.try_get("node_id")?;
                let created_at: DateTime<Utc> = row.try_get("created_at")?;
                let xray_version: Option<String> = row.try_get("xray_version")?;
                let capabilities_json: Option<serde_json::Value> =
                    row.try_get("capabilities_json")?;
                let runner_result_public_key_hex: Option<String> =
                    row.try_get("runner_result_public_key_hex")?;
                let host = capabilities_json
                    .as_ref()
                    .and_then(|v| v.get("host"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{node_id}.example"));
                Ok(NodeRecord {
                    tenant_id,
                    node_id,
                    host,
                    xray_version: xray_version.unwrap_or_else(|| "unknown".into()),
                    runner_result_public_key_hex: runner_result_public_key_hex.unwrap_or_default(),
                    last_heartbeat_at: created_at,
                })
            })
            .collect()
    }

    pub async fn create_node_registration_token(
        &self,
        token: NodeRegistrationTokenRecord,
    ) -> StoreResult<()> {
        sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT (id) DO NOTHING")
            .bind(&token.tenant_id)
            .execute(&self.pool)
            .await?;
        let result = sqlx::query(
            r#"INSERT INTO node_registration_tokens
               (id, tenant_id, token, status, created_at, consumed_at, used_by_node_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (token) DO NOTHING"#,
        )
        .bind(&token.token_id)
        .bind(&token.tenant_id)
        .bind(&token.token)
        .bind(&token.status)
        .bind(token.created_at)
        .bind(token.consumed_at)
        .bind(&token.used_by_node_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(());
        }
        self.record_event(
            &token.tenant_id,
            "admin",
            "node_registration_token.issued",
            "node_registration_token",
            &token.token_id,
        )
        .await?;
        Ok(())
    }

    pub async fn list_node_registration_tokens(
        &self,
    ) -> StoreResult<Vec<NodeRegistrationTokenRecord>> {
        let rows = sqlx::query(
            r#"SELECT id, tenant_id, token, status, created_at, consumed_at, used_by_node_id
               FROM node_registration_tokens
               ORDER BY created_at ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(node_registration_token_from_row)
            .collect()
    }

    pub async fn node_registration_token(
        &self,
        token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        let row = sqlx::query(
            r#"SELECT id, tenant_id, token, status, created_at, consumed_at, used_by_node_id
               FROM node_registration_tokens
               WHERE token = $1"#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound("node_registration_token".into()))?;
        node_registration_token_from_row(row)
    }

    pub async fn consume_node_registration_token(
        &self,
        token: &str,
        node_id: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        let row = sqlx::query(
            r#"UPDATE node_registration_tokens
               SET status = 'used', consumed_at = now(), used_by_node_id = $2
               WHERE token = $1 AND status = 'active'
               RETURNING id, tenant_id, token, status, created_at, consumed_at, used_by_node_id"#,
        )
        .bind(token)
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound("node_registration_token".into()))?;
        let record = node_registration_token_from_row(row)?;
        self.record_event(
            &record.tenant_id,
            "runner",
            "node_registration_token.used",
            "node_registration_token",
            &record.token_id,
        )
        .await?;
        Ok(record)
    }

    pub async fn update_node_runner_result_public_key(
        &self,
        node_id: &str,
        public_key_hex: &str,
    ) -> StoreResult<NodeRecord> {
        let node = self.node(node_id).await?;
        sqlx::query(
            r#"INSERT INTO node_identities (node_id, public_key, registered_at)
               VALUES ($1, $2, now())
               ON CONFLICT (node_id) DO UPDATE
               SET public_key = EXCLUDED.public_key"#,
        )
        .bind(node_id)
        .bind(public_key_hex)
        .execute(&self.pool)
        .await?;
        self.record_event(
            &node.tenant_id,
            "admin",
            "node.runner_result_key_rotated",
            "node",
            node_id,
        )
        .await?;
        self.node(node_id).await
    }

    pub async fn profile(&self, profile_id: &str) -> StoreResult<ProfileRecord> {
        let row = sqlx::query(
            r#"SELECT tenant_id, profile_id, ir_json, created_at
               FROM profile_versions
               WHERE profile_id = $1
               ORDER BY version DESC
               LIMIT 1"#,
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("profile:{profile_id}")))?;
        let tenant_id: String = row.try_get("tenant_id")?;
        let profile_id: String = row.try_get("profile_id")?;
        let ir_json: serde_json::Value = row.try_get("ir_json")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        Ok(ProfileRecord {
            tenant_id,
            profile_id,
            ir: serde_json::from_value(ir_json)?,
            created_at,
        })
    }

    pub async fn credentials_for_profile(&self, profile_id: &str) -> StoreResult<Vec<Credential>> {
        let rows = sqlx::query(
            r#"SELECT c.id, c.client_group_id, c.status, cl.display_name, s.ciphertext
               FROM profile_credentials pc
               JOIN credentials c ON c.id = pc.credential_id
               JOIN clients cl ON cl.id = c.client_id
               JOIN secrets s ON s.id = c.secret_ref
               WHERE pc.profile_id = $1
               ORDER BY c.created_at ASC"#,
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await?;
        let mut credentials = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.try_get("id")?;
            let client_group_id: String = row.try_get("client_group_id")?;
            let status_raw: String = row.try_get("status")?;
            let display_name: String = row.try_get("display_name")?;
            let ciphertext: Vec<u8> = row.try_get("ciphertext")?;
            let material: CredentialMaterial = serde_json::from_slice(&ciphertext)?;
            credentials.push(Credential {
                id,
                client_group_id,
                display_name,
                status: parse_credential_status(&status_raw),
                material,
            });
        }
        Ok(credentials)
    }

    pub async fn deployed_profile_for_subscription(
        &self,
        profile_id: &str,
    ) -> StoreResult<DeployedProfile> {
        let profile = self.profile(profile_id).await?;
        let node_row = sqlx::query("SELECT id FROM nodes ORDER BY created_at ASC LIMIT 1")
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| StoreError::NotFound("node:any".into()))?;
        let node_id: String = node_row.try_get("id")?;
        let node = self.node(&node_id).await?;
        let first_inbound = profile
            .ir
            .inbounds
            .first()
            .ok_or_else(|| StoreError::NotFound("profile inbound".into()))?;
        let server_name = match &first_inbound.security {
            Security::Reality { server_name, .. } | Security::Tls { server_name } => {
                server_name.clone()
            }
            Security::None => node.host.clone(),
        };
        let mut deployed =
            DeployedProfile::new(profile_id, &node.host, first_inbound.port, &server_name);
        for credential in self.credentials_for_profile(profile_id).await? {
            match self.credential_quota_decision(&credential.id).await {
                Ok(decision) if !decision.allowed => continue,
                Ok(_) | Err(StoreError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
            if !self
                .credential_expiry_decision(&credential.id)
                .await?
                .allowed
            {
                continue;
            }
            deployed = deployed.with_credential(credential);
        }
        Ok(deployed)
    }

    pub async fn issue_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken> {
        let profile = self.profile(profile_id).await?;
        let issued = new_subscription_token(profile_id);
        sqlx::query(
            r#"INSERT INTO subscription_tokens
               (id, tenant_id, profile_id, token_hash, status)
               VALUES ($1, $2, $3, $4, 'active')"#,
        )
        .bind(&issued.token_id)
        .bind(&profile.tenant_id)
        .bind(profile_id)
        .bind(subscription_token_hash(&issued.token))
        .execute(&self.pool)
        .await?;
        self.record_event(
            &profile.tenant_id,
            "admin",
            "subscription_token.issued",
            "profile",
            profile_id,
        )
        .await?;
        Ok(issued)
    }

    pub async fn rotate_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken> {
        let profile = self.profile(profile_id).await?;
        sqlx::query(
            r#"UPDATE subscription_tokens
               SET status = 'rotated', rotated_at = now()
               WHERE profile_id = $1 AND status = 'active'"#,
        )
        .bind(profile_id)
        .execute(&self.pool)
        .await?;
        let issued = new_subscription_token(profile_id);
        sqlx::query(
            r#"INSERT INTO subscription_tokens
               (id, tenant_id, profile_id, token_hash, status)
               VALUES ($1, $2, $3, $4, 'active')"#,
        )
        .bind(&issued.token_id)
        .bind(&profile.tenant_id)
        .bind(profile_id)
        .bind(subscription_token_hash(&issued.token))
        .execute(&self.pool)
        .await?;
        self.record_event(
            &profile.tenant_id,
            "admin",
            "subscription_token.rotated",
            "profile",
            profile_id,
        )
        .await?;
        Ok(issued)
    }

    pub async fn verify_subscription_token(
        &self,
        profile_id: &str,
        token: &str,
    ) -> StoreResult<SubscriptionTokenRecord> {
        let row = sqlx::query(
            r#"SELECT id, tenant_id, profile_id, token_hash, status, created_at, rotated_at
               FROM subscription_tokens
               WHERE profile_id = $1 AND token_hash = $2 AND status = 'active'"#,
        )
        .bind(profile_id)
        .bind(subscription_token_hash(token))
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::NotFound(format!("subscription_token:{profile_id}")))?;
        Ok(SubscriptionTokenRecord {
            tenant_id: row.try_get("tenant_id")?,
            token_id: row.try_get("id")?,
            profile_id: row.try_get("profile_id")?,
            token_hash: row.try_get("token_hash")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
            rotated_at: row.try_get("rotated_at")?,
        })
    }

    pub async fn subscription_token_required(&self, profile_id: &str) -> StoreResult<bool> {
        let _ = self.profile(profile_id).await?;
        let row = sqlx::query(
            r#"SELECT count(*) AS count
               FROM subscription_tokens
               WHERE profile_id = $1 AND status = 'active'"#,
        )
        .bind(profile_id)
        .fetch_one(&self.pool)
        .await?;
        let count: i64 = row.try_get("count")?;
        Ok(count > 0)
    }

    pub async fn record_subscription_access(
        &self,
        token_id: &str,
        remote_addr: Option<String>,
        user_agent: Option<String>,
        status: &str,
    ) -> StoreResult<()> {
        sqlx::query(
            r#"INSERT INTO subscription_access_logs
               (token_id, remote_addr, user_agent, status)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(token_id)
        .bind(remote_addr)
        .bind(user_agent)
        .bind(status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn subscription_access_log_count(&self, token_id: &str) -> StoreResult<usize> {
        let row = sqlx::query(
            r#"SELECT count(*) AS count
               FROM subscription_access_logs
               WHERE token_id = $1"#,
        )
        .bind(token_id)
        .fetch_one(&self.pool)
        .await?;
        let count: i64 = row.try_get("count")?;
        Ok(count as usize)
    }

    pub async fn audit_count(&self) -> StoreResult<usize> {
        let row = sqlx::query("SELECT count(*) AS count FROM audit_events")
            .fetch_one(&self.pool)
            .await?;
        let count: i64 = row.try_get("count")?;
        Ok(count as usize)
    }

    pub async fn outbox_count(&self) -> StoreResult<usize> {
        let row = sqlx::query("SELECT count(*) AS count FROM event_outbox")
            .fetch_one(&self.pool)
            .await?;
        let count: i64 = row.try_get("count")?;
        Ok(count as usize)
    }

    async fn record_event(
        &self,
        tenant_id: &str,
        actor: &str,
        action: &str,
        aggregate_type: &str,
        aggregate_id: &str,
    ) -> StoreResult<()> {
        sqlx::query(
            r#"INSERT INTO audit_events (tenant_id, actor, action, subject, payload_json)
               VALUES ($1, $2, $3, $4, '{}')"#,
        )
        .bind(tenant_id)
        .bind(actor)
        .bind(action)
        .bind(format!("{aggregate_type}:{aggregate_id}"))
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"INSERT INTO event_outbox
               (tenant_id, event_type, aggregate_type, aggregate_id, payload_json)
               VALUES ($1, $2, $3, $4, '{}')"#,
        )
        .bind(tenant_id)
        .bind(action)
        .bind(aggregate_type)
        .bind(aggregate_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl ProxyStore for PostgresStore {
    async fn register_node(&self, node: NodeRecord) -> StoreResult<()> {
        PostgresStore::register_node(self, node).await
    }
    async fn register_node_with_registration_token(
        &self,
        node: NodeRecord,
        registration_token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        PostgresStore::register_node_with_registration_token(self, node, registration_token).await
    }
    async fn list_nodes(&self) -> StoreResult<Vec<NodeRecord>> {
        PostgresStore::list_nodes(self).await
    }
    async fn create_node_registration_token(
        &self,
        token: NodeRegistrationTokenRecord,
    ) -> StoreResult<()> {
        PostgresStore::create_node_registration_token(self, token).await
    }
    async fn list_node_registration_tokens(&self) -> StoreResult<Vec<NodeRegistrationTokenRecord>> {
        PostgresStore::list_node_registration_tokens(self).await
    }
    async fn node_registration_token(
        &self,
        token: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        PostgresStore::node_registration_token(self, token).await
    }
    async fn consume_node_registration_token(
        &self,
        token: &str,
        node_id: &str,
    ) -> StoreResult<NodeRegistrationTokenRecord> {
        PostgresStore::consume_node_registration_token(self, token, node_id).await
    }
    async fn record_heartbeat(&self, heartbeat: HeartbeatRecord) -> StoreResult<()> {
        PostgresStore::record_heartbeat(self, heartbeat).await
    }
    async fn latest_heartbeat(&self, node_id: &str) -> StoreResult<HeartbeatRecord> {
        PostgresStore::latest_heartbeat(self, node_id).await
    }
    async fn create_profile(&self, profile: ProfileRecord) -> StoreResult<()> {
        PostgresStore::create_profile(self, profile).await
    }
    async fn list_profiles(&self) -> StoreResult<Vec<ProfileRecord>> {
        PostgresStore::list_profiles(self).await
    }
    async fn add_credential(&self, profile_id: &str, credential: Credential) -> StoreResult<()> {
        PostgresStore::add_credential(self, profile_id, credential).await
    }
    async fn list_credentials(&self) -> StoreResult<Vec<CredentialRecord>> {
        PostgresStore::list_credentials(self).await
    }
    async fn record_artifact(&self, artifact: Artifact) -> StoreResult<()> {
        PostgresStore::record_artifact(self, artifact).await
    }
    async fn record_artifact_blob(&self, artifact: Artifact, bytes: Vec<u8>) -> StoreResult<()> {
        PostgresStore::record_artifact_blob(self, artifact, bytes).await
    }
    async fn artifact_bytes(&self, artifact_id: &str) -> StoreResult<Vec<u8>> {
        PostgresStore::artifact_bytes(self, artifact_id).await
    }
    async fn artifact_bytes_by_sha256(&self, sha256: &str) -> StoreResult<Vec<u8>> {
        PostgresStore::artifact_bytes_by_sha256(self, sha256).await
    }
    async fn record_deployment_plan(&self, deployment: DeploymentPlanRecord) -> StoreResult<()> {
        PostgresStore::record_deployment_plan(self, deployment).await
    }
    async fn idempotency_response(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> StoreResult<Option<serde_json::Value>> {
        PostgresStore::idempotency_response(self, tenant_id, key).await
    }
    async fn record_idempotency_response(
        &self,
        tenant_id: &str,
        key: &str,
        response_json: serde_json::Value,
    ) -> StoreResult<()> {
        PostgresStore::record_idempotency_response(self, tenant_id, key, response_json).await
    }
    async fn record_deployment_result(&self, result: DeploymentResult) -> StoreResult<()> {
        PostgresStore::record_deployment_result(self, result).await
    }
    async fn deployment_status(&self, deployment_id: &str) -> StoreResult<DeploymentStatus> {
        PostgresStore::deployment_status(self, deployment_id).await
    }
    async fn rollback_pointer(&self, deployment_id: &str) -> StoreResult<RollbackPointerRecord> {
        PostgresStore::rollback_pointer(self, deployment_id).await
    }
    async fn deployment_snapshot(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentSnapshotRecord> {
        PostgresStore::deployment_snapshot(self, deployment_id).await
    }
    async fn latest_deployment_health(
        &self,
        deployment_id: &str,
    ) -> StoreResult<DeploymentHealthCheckRecord> {
        PostgresStore::latest_deployment_health(self, deployment_id).await
    }
    async fn record_deployment_health_check(
        &self,
        health: DeploymentHealthCheckRecord,
    ) -> StoreResult<()> {
        PostgresStore::record_deployment_health_check(self, health).await
    }
    async fn deployment_health_checks(
        &self,
        deployment_id: &str,
    ) -> StoreResult<Vec<DeploymentHealthCheckRecord>> {
        PostgresStore::deployment_health_checks(self, deployment_id).await
    }
    async fn record_usage_sample(&self, usage: UsageSampleRecord) -> StoreResult<()> {
        PostgresStore::record_usage_sample(self, usage).await
    }
    async fn latest_usage_sample(&self, node_id: &str) -> StoreResult<UsageSampleRecord> {
        PostgresStore::latest_usage_sample(self, node_id).await
    }
    async fn latest_usage_rollup_for_credential(
        &self,
        credential_id: &str,
        bucket: &str,
    ) -> StoreResult<UsageRollupRecord> {
        PostgresStore::latest_usage_rollup_for_credential(self, credential_id, bucket).await
    }
    async fn set_credential_quota(&self, credential_id: &str, quota_bytes: i64) -> StoreResult<()> {
        PostgresStore::set_credential_quota(self, credential_id, quota_bytes).await
    }
    async fn credential_quota_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialQuotaDecision> {
        PostgresStore::credential_quota_decision(self, credential_id).await
    }
    async fn set_credential_expiry(
        &self,
        credential_id: &str,
        expires_at: DateTime<Utc>,
    ) -> StoreResult<()> {
        PostgresStore::set_credential_expiry(self, credential_id, expires_at).await
    }
    async fn credential_expiry_decision(
        &self,
        credential_id: &str,
    ) -> StoreResult<CredentialExpiryDecision> {
        PostgresStore::credential_expiry_decision(self, credential_id).await
    }
    async fn enqueue_runner_command(
        &self,
        node_id: &str,
        command: SignedRunnerCommand,
    ) -> StoreResult<()> {
        PostgresStore::enqueue_runner_command(self, node_id, command).await
    }
    async fn next_runner_command(
        &self,
        node_id: &str,
        last_sequence: u64,
    ) -> StoreResult<Option<SignedRunnerCommand>> {
        PostgresStore::next_runner_command(self, node_id, last_sequence).await
    }
    async fn node(&self, node_id: &str) -> StoreResult<NodeRecord> {
        PostgresStore::node(self, node_id).await
    }
    async fn update_node_runner_result_public_key(
        &self,
        node_id: &str,
        public_key_hex: &str,
    ) -> StoreResult<NodeRecord> {
        PostgresStore::update_node_runner_result_public_key(self, node_id, public_key_hex).await
    }
    async fn profile(&self, profile_id: &str) -> StoreResult<ProfileRecord> {
        PostgresStore::profile(self, profile_id).await
    }
    async fn credentials_for_profile(&self, profile_id: &str) -> StoreResult<Vec<Credential>> {
        PostgresStore::credentials_for_profile(self, profile_id).await
    }
    async fn audit_count(&self) -> StoreResult<usize> {
        PostgresStore::audit_count(self).await
    }
    async fn outbox_count(&self) -> StoreResult<usize> {
        PostgresStore::outbox_count(self).await
    }
    async fn deployed_profile_for_subscription(
        &self,
        profile_id: &str,
    ) -> StoreResult<DeployedProfile> {
        PostgresStore::deployed_profile_for_subscription(self, profile_id).await
    }
    async fn issue_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken> {
        PostgresStore::issue_subscription_token(self, profile_id).await
    }
    async fn rotate_subscription_token(
        &self,
        profile_id: &str,
    ) -> StoreResult<IssuedSubscriptionToken> {
        PostgresStore::rotate_subscription_token(self, profile_id).await
    }
    async fn verify_subscription_token(
        &self,
        profile_id: &str,
        token: &str,
    ) -> StoreResult<SubscriptionTokenRecord> {
        PostgresStore::verify_subscription_token(self, profile_id, token).await
    }
    async fn subscription_token_required(&self, profile_id: &str) -> StoreResult<bool> {
        PostgresStore::subscription_token_required(self, profile_id).await
    }
    async fn record_subscription_access(
        &self,
        token_id: &str,
        remote_addr: Option<String>,
        user_agent: Option<String>,
        status: &str,
    ) -> StoreResult<()> {
        PostgresStore::record_subscription_access(self, token_id, remote_addr, user_agent, status)
            .await
    }
    async fn subscription_access_log_count(&self, token_id: &str) -> StoreResult<usize> {
        PostgresStore::subscription_access_log_count(self, token_id).await
    }
    fn kind(&self) -> &'static str {
        "postgres"
    }
}

fn parse_credential_status(raw: &str) -> CredentialStatus {
    match raw {
        "active" => CredentialStatus::Active,
        "revoked" => CredentialStatus::Revoked,
        "expired" => CredentialStatus::Expired,
        _ => CredentialStatus::Revoked,
    }
}

fn parse_deployment_status(raw: &str) -> DeploymentStatus {
    match raw {
        "Pending" | "pending" | "planned" => DeploymentStatus::Pending,
        "Succeeded" | "succeeded" => DeploymentStatus::Succeeded,
        "Failed" | "failed" => DeploymentStatus::Failed,
        "RolledBack" | "rolled_back" => DeploymentStatus::RolledBack,
        _ => DeploymentStatus::Failed,
    }
}

fn health_status_for_deployment_status(status: &DeploymentStatus) -> &'static str {
    match status {
        DeploymentStatus::Succeeded | DeploymentStatus::RolledBack => "healthy",
        DeploymentStatus::Pending | DeploymentStatus::Failed => "unhealthy",
    }
}

fn quota_decision(
    credential_id: &str,
    quota_bytes: i64,
    used_bytes: i64,
) -> CredentialQuotaDecision {
    let allowed = used_bytes <= quota_bytes;
    CredentialQuotaDecision {
        credential_id: credential_id.into(),
        quota_bytes,
        used_bytes,
        allowed,
        reason: if allowed {
            "within_quota".into()
        } else {
            "quota_exceeded".into()
        },
    }
}

fn credential_quota_exceeded_in_memory(state: &MemoryState, credential_id: &str) -> bool {
    let Some(quota_bytes) = state.credential_quotas.get(credential_id) else {
        return false;
    };
    let used_bytes: i64 = state
        .usage_rollups
        .values()
        .filter(|rollup| rollup.credential_id.as_deref() == Some(credential_id))
        .map(|rollup| rollup.uplink_bytes + rollup.downlink_bytes)
        .sum();
    used_bytes > *quota_bytes
}

fn expiry_decision(
    credential_id: &str,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> CredentialExpiryDecision {
    let expired = expires_at.is_some_and(|expires_at| expires_at <= now);
    CredentialExpiryDecision {
        credential_id: credential_id.into(),
        expires_at,
        expired,
        allowed: !expired,
        reason: match (expires_at, expired) {
            (None, _) => "no_expiry".into(),
            (Some(_), true) => "expired".into(),
            (Some(_), false) => "not_expired".into(),
        },
    }
}

fn credential_expired_in_memory(
    state: &MemoryState,
    credential_id: &str,
    now: DateTime<Utc>,
) -> bool {
    expiry_decision(
        credential_id,
        state.credential_expirations.get(credential_id).copied(),
        now,
    )
    .expired
}

fn new_subscription_token(profile_id: &str) -> IssuedSubscriptionToken {
    let token_id = format!("subtok-{}", Uuid::new_v4());
    let secret = Uuid::new_v4();
    IssuedSubscriptionToken {
        token_id: token_id.clone(),
        profile_id: profile_id.into(),
        token: format!("{token_id}.{secret}"),
        status: "active".into(),
    }
}

fn subscription_token_record(
    tenant_id: &str,
    issued: &IssuedSubscriptionToken,
) -> SubscriptionTokenRecord {
    SubscriptionTokenRecord {
        tenant_id: tenant_id.into(),
        token_id: issued.token_id.clone(),
        profile_id: issued.profile_id.clone(),
        token_hash: subscription_token_hash(&issued.token),
        status: issued.status.clone(),
        created_at: Utc::now(),
        rotated_at: None,
    }
}

fn subscription_token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn node_registration_token_from_row(
    row: sqlx::postgres::PgRow,
) -> StoreResult<NodeRegistrationTokenRecord> {
    Ok(NodeRegistrationTokenRecord {
        tenant_id: row.try_get("tenant_id")?,
        token_id: row.try_get("id")?,
        token: row.try_get("token")?,
        status: row.try_get("status")?,
        created_at: row.try_get("created_at")?,
        consumed_at: row.try_get("consumed_at")?,
        used_by_node_id: row.try_get("used_by_node_id")?,
    })
}

async fn record_event_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    actor: &str,
    action: &str,
    aggregate_type: &str,
    aggregate_id: &str,
) -> StoreResult<()> {
    sqlx::query(
        r#"INSERT INTO audit_events (tenant_id, actor, action, subject, payload_json)
           VALUES ($1, $2, $3, $4, '{}')"#,
    )
    .bind(tenant_id)
    .bind(actor)
    .bind(action)
    .bind(format!("{aggregate_type}:{aggregate_id}"))
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        r#"INSERT INTO event_outbox
           (tenant_id, event_type, aggregate_type, aggregate_id, payload_json)
           VALUES ($1, $2, $3, $4, '{}')"#,
    )
    .bind(tenant_id)
    .bind(action)
    .bind(aggregate_type)
    .bind(aggregate_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn hour_bucket_start(sampled_at: DateTime<Utc>) -> DateTime<Utc> {
    let timestamp = sampled_at.timestamp();
    let hour_start = timestamp - timestamp.rem_euclid(3600);
    DateTime::<Utc>::from_timestamp(hour_start, 0).expect("valid unix hour bucket")
}

fn day_bucket_start(sampled_at: DateTime<Utc>) -> DateTime<Utc> {
    let timestamp = sampled_at.timestamp();
    let day_start = timestamp - timestamp.rem_euclid(86_400);
    DateTime::<Utc>::from_timestamp(day_start, 0).expect("valid unix day bucket")
}

fn month_bucket_start(sampled_at: DateTime<Utc>) -> DateTime<Utc> {
    sampled_at
        .date_naive()
        .with_day(1)
        .expect("day one exists for every month")
        .and_hms_opt(0, 0, 0)
        .expect("valid unix month bucket")
        .and_utc()
}

fn usage_bucket_starts(sampled_at: DateTime<Utc>) -> [(&'static str, DateTime<Utc>); 3] {
    [
        ("hour", hour_bucket_start(sampled_at)),
        ("day", day_bucket_start(sampled_at)),
        ("month", month_bucket_start(sampled_at)),
    ]
}

fn hex_sha256(bytes: Vec<u8>) -> String {
    hex::encode(Sha256::digest(bytes))
}
