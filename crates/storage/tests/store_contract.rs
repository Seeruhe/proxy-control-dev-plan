use chrono::{DateTime, Duration, Utc};
use domain::{
    Artifact, ArtifactKind, Credential, DeployedProfile, DeploymentResult, DeploymentStatus,
    ProfileIr, RunnerCommand, RunnerCommandKind, SignedRunnerCommand,
};
use ed25519_dalek::SigningKey;
use storage::*;

#[tokio::test]
async fn memory_store_records_p0_flow_and_builds_subscription_view() {
    let store = MemoryStore::new("tenant-dev");
    store
        .register_node(NodeRecord::new(
            "tenant-dev",
            "node-a",
            "node-a.example",
            "1.8.8",
        ))
        .await
        .unwrap();
    store
        .create_profile(ProfileRecord::new(
            "tenant-dev",
            "profile-a",
            ProfileIr::vless_reality_example("group_default", "sec_reality_private"),
        ))
        .await
        .unwrap();
    store
        .add_credential(
            "profile-a",
            Credential::active_vless(
                "cred-a",
                "group_default",
                "2f4f6f8a-1111-4c4c-9999-111111111111",
                "Alice",
            ),
        )
        .await
        .unwrap();
    store
        .add_credential(
            "profile-a",
            Credential::revoked_vless(
                "cred-b",
                "group_default",
                "33333333-3333-4333-9333-333333333333",
                "Bob",
            ),
        )
        .await
        .unwrap();

    let artifact = Artifact::from_bytes(
        "tenant-dev",
        ArtifactKind::CompiledXrayConfig,
        "application/json",
        br#"{"inbounds":[]}"#,
        "admin",
    );
    store.record_artifact(artifact.clone()).await.unwrap();
    store
        .record_deployment_plan(DeploymentPlanRecord::new(
            "tenant-dev",
            "dep-a",
            "node-a",
            "profile-a",
            &artifact.id,
        ))
        .await
        .unwrap();

    assert_eq!(store.audit_count().await.unwrap(), 6);
    assert_eq!(store.outbox_count().await.unwrap(), 6);

    let profile: DeployedProfile = store
        .deployed_profile_for_subscription("profile-a")
        .await
        .unwrap();
    assert_eq!(profile.host, "node-a.example");
    assert_eq!(profile.port, 443);
    assert_eq!(profile.credentials.len(), 2);
}

#[tokio::test]
async fn memory_store_rotates_subscription_tokens_and_logs_access() {
    let store = MemoryStore::new("tenant-dev");
    store
        .create_profile(ProfileRecord::new(
            "tenant-dev",
            "profile-token",
            ProfileIr::vless_reality_example("group_default", "sec_reality_private"),
        ))
        .await
        .unwrap();

    let first = store
        .issue_subscription_token("profile-token")
        .await
        .unwrap();
    let verified = store
        .verify_subscription_token("profile-token", &first.token)
        .await
        .unwrap();
    assert_eq!(verified.token_id, first.token_id);
    assert_eq!(verified.profile_id, "profile-token");
    assert_eq!(verified.status, "active");

    store
        .record_subscription_access(
            &verified.token_id,
            Some("127.0.0.1".into()),
            Some("curl".into()),
            "ok",
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .subscription_access_log_count(&verified.token_id)
            .await
            .unwrap(),
        1
    );

    let second = store
        .rotate_subscription_token("profile-token")
        .await
        .unwrap();
    assert_ne!(first.token, second.token);
    assert!(store
        .verify_subscription_token("profile-token", &first.token)
        .await
        .is_err());
    assert_eq!(
        store
            .verify_subscription_token("profile-token", &second.token)
            .await
            .unwrap()
            .status,
        "active"
    );
}

#[tokio::test]
async fn memory_store_lists_registered_nodes_in_stable_order() {
    let store = MemoryStore::new("tenant-dev");
    store
        .register_node(NodeRecord::new(
            "tenant-dev",
            "node-b",
            "node-b.example",
            "26.3.27",
        ))
        .await
        .unwrap();
    store
        .register_node(NodeRecord::new(
            "tenant-dev",
            "node-a",
            "node-a.example",
            "1.8.8",
        ))
        .await
        .unwrap();

    let nodes = store.list_nodes().await.unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].node_id, "node-a");
    assert_eq!(nodes[0].host, "node-a.example");
    assert_eq!(nodes[1].node_id, "node-b");
    assert_eq!(nodes[1].xray_version, "26.3.27");
}

#[tokio::test]
async fn postgres_store_can_be_constructed_without_connecting_for_repository_wiring() {
    let store =
        PostgresStore::connect_lazy("postgres://proxy:proxy@localhost:5432/proxy_control").unwrap();
    assert!(store.is_lazy());
}

async fn exercise_store_trait(store: &(dyn ProxyStore + Send + Sync)) {
    store
        .register_node(NodeRecord::new(
            "tenant-dev",
            "node-trait",
            "node-trait.example",
            "1.8.8",
        ))
        .await
        .unwrap();
    assert_eq!(
        store.node("node-trait").await.unwrap().host,
        "node-trait.example"
    );
}

#[tokio::test]
async fn memory_store_implements_proxy_store_trait_for_control_plane_injection() {
    let store = MemoryStore::new("tenant-dev");
    exercise_store_trait(&store).await;
}

#[tokio::test]
async fn memory_store_persists_runner_command_queue_semantics() {
    let store = MemoryStore::new("tenant-dev");
    let signing = SigningKey::from_bytes(&[21u8; 32]);
    let first = SignedRunnerCommand::sign(
        RunnerCommand::new(
            "tenant-dev",
            "node-a",
            1,
            Utc::now() + Duration::seconds(60),
            RunnerCommandKind::CollectMetrics,
        ),
        &signing,
    )
    .unwrap();
    let second = SignedRunnerCommand::sign(
        RunnerCommand::new(
            "tenant-dev",
            "node-a",
            2,
            Utc::now() + Duration::seconds(60),
            RunnerCommandKind::CollectLogWindow { lines: 10 },
        ),
        &signing,
    )
    .unwrap();

    store.enqueue_runner_command("node-a", first).await.unwrap();
    store
        .enqueue_runner_command("node-a", second)
        .await
        .unwrap();

    let command = store
        .next_runner_command("node-a", 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(command.command.sequence, 1);
    let command = store
        .next_runner_command("node-a", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(command.command.sequence, 2);
    assert!(store
        .next_runner_command("node-a", 2)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn memory_store_records_rollback_pointer_and_deployment_snapshot() {
    let store = MemoryStore::new("tenant-dev");
    store
        .register_node(NodeRecord::new(
            "tenant-dev",
            "node-a",
            "node-a.example",
            "1.8.8",
        ))
        .await
        .unwrap();
    store
        .create_profile(ProfileRecord::new(
            "tenant-dev",
            "profile-a",
            ProfileIr::vless_reality_example("group_default", "sec_reality_private"),
        ))
        .await
        .unwrap();

    let first_artifact = Artifact::from_bytes(
        "tenant-dev",
        ArtifactKind::CompiledXrayConfig,
        "application/json",
        br#"{"tag":"first"}"#,
        "admin",
    );
    store.record_artifact(first_artifact.clone()).await.unwrap();
    store
        .record_deployment_plan(DeploymentPlanRecord::new(
            "tenant-dev",
            "dep-first",
            "node-a",
            "profile-a",
            &first_artifact.id,
        ))
        .await
        .unwrap();
    store
        .record_deployment_result(DeploymentResult {
            deployment_id: "dep-first".into(),
            status: DeploymentStatus::Succeeded,
            message: "first release active".into(),
            artifact_sha256: first_artifact.sha256.clone(),
            observed_at: Utc::now(),
        })
        .await
        .unwrap();

    let next_artifact = Artifact::from_bytes(
        "tenant-dev",
        ArtifactKind::CompiledXrayConfig,
        "application/json",
        br#"{"tag":"next"}"#,
        "admin",
    );
    store.record_artifact(next_artifact.clone()).await.unwrap();
    store
        .record_deployment_plan(DeploymentPlanRecord::new(
            "tenant-dev",
            "dep-next",
            "node-a",
            "profile-a",
            &next_artifact.id,
        ))
        .await
        .unwrap();

    let rollback = store.rollback_pointer("dep-next").await.unwrap();
    assert_eq!(rollback.deployment_id, "dep-next");
    assert_eq!(
        rollback.previous_deployment_id.as_deref(),
        Some("dep-first")
    );
    assert_eq!(
        rollback.previous_compiled_config_artifact_id.as_deref(),
        Some(first_artifact.id.as_str())
    );
    assert_eq!(
        rollback.target_compiled_config_artifact_id,
        next_artifact.id
    );

    store
        .record_deployment_result(DeploymentResult {
            deployment_id: "dep-next".into(),
            status: DeploymentStatus::RolledBack,
            message: "config test failed; rolled back to previous active release".into(),
            artifact_sha256: next_artifact.sha256.clone(),
            observed_at: Utc::now(),
        })
        .await
        .unwrap();
    let snapshot = store.deployment_snapshot("dep-next").await.unwrap();
    assert_eq!(snapshot.deployment_id, "dep-next");
    assert_eq!(snapshot.node_id, "node-a");
    assert_eq!(snapshot.profile_id, "profile-a");
    assert_eq!(snapshot.compiled_config_artifact_id, next_artifact.id);
    assert_eq!(snapshot.result_status, DeploymentStatus::RolledBack);
    assert!(snapshot.result_message.contains("rolled back"));

    let health = store.latest_deployment_health("dep-next").await.unwrap();
    assert_eq!(health.deployment_id, "dep-next");
    assert_eq!(health.node_id, "node-a");
    assert_eq!(health.status, "healthy");
    assert_eq!(health.payload_json["deployment_status"], "RolledBack");
}

#[tokio::test]
async fn memory_store_records_unhealthy_health_check_for_failed_deployment() {
    let store = MemoryStore::new("tenant-dev");
    store
        .register_node(NodeRecord::new(
            "tenant-dev",
            "node-health",
            "node-health.example",
            "1.8.8",
        ))
        .await
        .unwrap();
    store
        .create_profile(ProfileRecord::new(
            "tenant-dev",
            "profile-health",
            ProfileIr::vless_reality_example("group_default", "sec_reality_private"),
        ))
        .await
        .unwrap();
    let artifact = Artifact::from_bytes(
        "tenant-dev",
        ArtifactKind::CompiledXrayConfig,
        "application/json",
        br#"{"tag":"health"}"#,
        "admin",
    );
    store.record_artifact(artifact.clone()).await.unwrap();
    store
        .record_deployment_plan(DeploymentPlanRecord::new(
            "tenant-dev",
            "dep-health",
            "node-health",
            "profile-health",
            &artifact.id,
        ))
        .await
        .unwrap();
    store
        .record_deployment_result(DeploymentResult {
            deployment_id: "dep-health".into(),
            status: DeploymentStatus::Failed,
            message: "health probe failed".into(),
            artifact_sha256: artifact.sha256,
            observed_at: Utc::now(),
        })
        .await
        .unwrap();

    let health = store.latest_deployment_health("dep-health").await.unwrap();
    assert_eq!(health.status, "unhealthy");
    assert_eq!(health.payload_json["message"], "health probe failed");
}

#[tokio::test]
async fn memory_store_records_additional_deployment_health_samples_for_readiness() {
    let store = MemoryStore::new("tenant-dev");
    store
        .register_node(NodeRecord::new(
            "tenant-dev",
            "node-ready",
            "node-ready.example",
            "1.8.8",
        ))
        .await
        .unwrap();
    store
        .create_profile(ProfileRecord::new(
            "tenant-dev",
            "profile-ready",
            ProfileIr::vless_reality_example("group_default", "sec_reality_private"),
        ))
        .await
        .unwrap();
    let artifact = Artifact::from_bytes(
        "tenant-dev",
        ArtifactKind::CompiledXrayConfig,
        "application/json",
        br#"{"tag":"ready"}"#,
        "admin",
    );
    store.record_artifact(artifact.clone()).await.unwrap();
    store
        .record_deployment_plan(DeploymentPlanRecord::new(
            "tenant-dev",
            "dep-ready",
            "node-ready",
            "profile-ready",
            &artifact.id,
        ))
        .await
        .unwrap();
    store
        .record_deployment_result(DeploymentResult {
            deployment_id: "dep-ready".into(),
            status: DeploymentStatus::Succeeded,
            message: "runner applied config".into(),
            artifact_sha256: artifact.sha256,
            observed_at: Utc::now(),
        })
        .await
        .unwrap();

    store
        .record_deployment_health_check(DeploymentHealthCheckRecord {
            tenant_id: "tenant-dev".into(),
            deployment_id: "dep-ready".into(),
            node_id: "node-ready".into(),
            status: "healthy".into(),
            payload_json: serde_json::json!({"probe":"subscription_fetch_ok"}),
            created_at: Utc::now() + Duration::seconds(1),
        })
        .await
        .unwrap();

    let samples = store.deployment_health_checks("dep-ready").await.unwrap();
    assert_eq!(samples.len(), 2);
    assert!(samples.iter().all(|sample| sample.status == "healthy"));
    assert_eq!(
        store
            .latest_deployment_health("dep-ready")
            .await
            .unwrap()
            .payload_json["probe"],
        "subscription_fetch_ok"
    );

    let wrong_node = store
        .record_deployment_health_check(DeploymentHealthCheckRecord {
            tenant_id: "tenant-dev".into(),
            deployment_id: "dep-ready".into(),
            node_id: "node-other".into(),
            status: "healthy".into(),
            payload_json: serde_json::json!({}),
            created_at: Utc::now(),
        })
        .await;
    assert!(wrong_node.is_err());
}

#[tokio::test]
async fn memory_store_records_latest_raw_usage_sample() {
    let store = MemoryStore::new("tenant-dev");
    store
        .register_node(NodeRecord::new(
            "tenant-dev",
            "node-usage",
            "node-usage.example",
            "1.8.8",
        ))
        .await
        .unwrap();

    let sampled_at = DateTime::parse_from_rfc3339("2026-06-14T03:04:05Z")
        .unwrap()
        .with_timezone(&Utc);
    let older = UsageSampleRecord::new(
        "tenant-dev",
        "node-usage",
        Some("cred-a".into()),
        100,
        200,
        sampled_at,
    );
    let newer = UsageSampleRecord::new(
        "tenant-dev",
        "node-usage",
        Some("cred-a".into()),
        300,
        400,
        sampled_at + Duration::seconds(5),
    );
    store.record_usage_sample(older).await.unwrap();
    store.record_usage_sample(newer).await.unwrap();

    let latest = store.latest_usage_sample("node-usage").await.unwrap();
    assert_eq!(latest.node_id, "node-usage");
    assert_eq!(latest.credential_id.as_deref(), Some("cred-a"));
    assert_eq!(latest.uplink_bytes, 300);
    assert_eq!(latest.downlink_bytes, 400);

    let rollup = store
        .latest_usage_rollup_for_credential("cred-a", "hour")
        .await
        .unwrap();
    assert_eq!(rollup.tenant_id, "tenant-dev");
    assert_eq!(rollup.credential_id.as_deref(), Some("cred-a"));
    assert_eq!(rollup.bucket, "hour");
    assert_eq!(rollup.uplink_bytes, 400);
    assert_eq!(rollup.downlink_bytes, 600);
    assert_eq!(rollup.bucket_start.timestamp() % 3600, 0);

    let daily_rollup = store
        .latest_usage_rollup_for_credential("cred-a", "day")
        .await
        .unwrap();
    assert_eq!(daily_rollup.bucket, "day");
    assert_eq!(daily_rollup.uplink_bytes, 400);
    assert_eq!(daily_rollup.downlink_bytes, 600);
    assert_eq!(
        daily_rollup.bucket_start.to_rfc3339(),
        "2026-06-14T00:00:00+00:00"
    );

    let monthly_rollup = store
        .latest_usage_rollup_for_credential("cred-a", "month")
        .await
        .unwrap();
    assert_eq!(monthly_rollup.bucket, "month");
    assert_eq!(monthly_rollup.uplink_bytes, 400);
    assert_eq!(monthly_rollup.downlink_bytes, 600);
    assert_eq!(
        monthly_rollup.bucket_start.to_rfc3339(),
        "2026-06-01T00:00:00+00:00"
    );

    store.set_credential_quota("cred-a", 900).await.unwrap();
    let decision = store.credential_quota_decision("cred-a").await.unwrap();
    assert_eq!(decision.credential_id, "cred-a");
    assert_eq!(decision.quota_bytes, 900);
    assert_eq!(decision.used_bytes, 1000);
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "quota_exceeded");
}

#[tokio::test]
async fn memory_store_records_artifact_blob_and_rejects_sha_mismatch() {
    let store = MemoryStore::new("tenant-dev");
    let bytes = br#"{"inbounds":[],"outbounds":[]}"#;
    let artifact = Artifact::from_bytes(
        "tenant-dev",
        ArtifactKind::CompiledXrayConfig,
        "application/json",
        bytes,
        "admin",
    );

    store
        .record_artifact_blob(artifact.clone(), bytes.to_vec())
        .await
        .unwrap();
    assert_eq!(store.artifact_bytes(&artifact.id).await.unwrap(), bytes);
    assert_eq!(
        store
            .artifact_bytes_by_sha256(&artifact.sha256)
            .await
            .unwrap(),
        bytes
    );

    let err = store
        .record_artifact_blob(artifact, b"{\"tampered\":true}".to_vec())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("artifact sha256 mismatch"), "{err}");
}
