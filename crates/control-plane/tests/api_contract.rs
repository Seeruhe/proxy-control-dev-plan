use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine;
use chrono::{Duration, Utc};
use control_plane::*;
use domain::{DeploymentResult, DeploymentStatus, SignedDeploymentResult, SignedRunnerCommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use http_body_util::BodyExt;
use serde_json::json;
use sha2::Digest;
use tower::ServiceExt;

#[tokio::test]
async fn system_capabilities_describe_current_architecture_and_deferred_wheels() {
    let app = build_router(AppState::dev());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/system/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let capabilities: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(capabilities["product"], "RelayX");
    assert_eq!(capabilities["p0_status"], "executable");
    assert!(capabilities["core_path"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["name"] == "Rust runner -> xray-core"));
    assert!(capabilities["backend_wheels"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |item| item["name"] == "Node registration lease" && item["status"] == "p0-implemented"
        ));
    assert!(capabilities["deferred_wheels"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["name"] == "A2A boundary" && item["status"] == "p1-deferred"));
    assert!(capabilities["deferred_wheels"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["name"] == "BYOM integration" && item["status"] == "p1-deferred"));
}

#[tokio::test]
async fn node_registration_token_is_consumed_after_first_successful_registration() {
    let app = build_router(AppState::dev());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/nodes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list["nodes"].as_array().unwrap().len(), 0);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/nodes/registration-tokens")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(tokens["tokens"][0]["token"], "dev-registration-token");
    assert_eq!(tokens["tokens"][0]["status"], "active");

    let first = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/nodes/register")
        .header("content-type", "application/json")
        .body(Body::from(json!({"registration_token":"dev-registration-token","node_id":"node-first","xray_version":"1.8.8"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/nodes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list["nodes"][0]["node_id"], "node-first");
    assert_eq!(list["nodes"][0]["xray_version"], "1.8.8");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/nodes/registration-tokens")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(tokens["tokens"][0]["status"], "used");
    assert_eq!(tokens["tokens"][0]["used_by_node_id"], "node-first");

    let second = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/nodes/register")
        .header("content-type", "application/json")
        .body(Body::from(json!({"registration_token":"dev-registration-token","node_id":"node-second","xray_version":"1.8.8"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);

    let issued = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/nodes/registration-tokens")
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    let body = issued.into_body().collect().await.unwrap().to_bytes();
    let issued: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let issued_token = issued["token"].as_str().unwrap();

    let second = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/nodes/register")
        .header("content-type", "application/json")
        .body(Body::from(json!({"registration_token":issued_token,"node_id":"node-second","xray_version":"26.3.27"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn p0_api_registers_node_compiles_profile_creates_audit_and_subscription() {
    let app = build_router(AppState::dev());

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/nodes/register")
        .header("content-type", "application/json")
        .body(Body::from(json!({"registration_token":"dev-registration-token","node_id":"node-a","xray_version":"1.8.8"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/runner/nodes/node-a/heartbeat")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"capability_snapshot":{"xray_version":"1.8.8","os":"linux"}})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/runner/nodes/node-a/heartbeat")
                .header("content-type", "application/json")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::from(
                    json!({"capability_snapshot":{"xray_version":"1.8.8","os":"linux"}})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/nodes/node-a/heartbeat")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let heartbeat: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(heartbeat["node_id"], "node-a");
    assert_eq!(heartbeat["capability_snapshot"]["xray_version"], "1.8.8");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-a","server_name":"example.com"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-a","profile_id":"profile-a","display_name":"Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/deployments/compile")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-a","node_id":"node-a"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let deployment: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(deployment["status"], "compiled");
    assert!(deployment["artifact"]["sha256"].as_str().unwrap().len() == 64);
    assert_eq!(deployment["audit_count"], 8);
    assert_eq!(deployment["outbox_count"], 8);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/artifacts/{}/bytes",
                    deployment["artifact"]["id"].as_str().unwrap()
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let artifact_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let artifact_json: serde_json::Value = serde_json::from_slice(&artifact_bytes).unwrap();
    assert_eq!(artifact_json["inbounds"][0]["protocol"], "vless");
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&artifact_bytes)),
        deployment["artifact"]["sha256"].as_str().unwrap()
    );

    let deployment_id = format!(
        "dep-{}",
        &deployment["artifact"]["sha256"].as_str().unwrap()[..12]
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/deployments/{deployment_id}/rollback-pointer"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let rollback: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(rollback["deployment_id"], deployment_id);
    assert_eq!(
        rollback["target_compiled_config_artifact_id"],
        deployment["artifact"]["id"]
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/runner/nodes/node-a/commands/next?last_sequence=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/runner/nodes/node-a/commands/next?last_sequence=0")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let envelope: SignedRunnerCommand = serde_json::from_slice(&body).unwrap();
    let mut seen = std::collections::HashSet::new();
    let command = envelope
        .verify(
            &AppState::dev_control_plane_verify_key(),
            "node-a",
            0,
            &mut seen,
            Utc::now(),
        )
        .unwrap();
    assert_eq!(command.sequence, 1);
    assert_eq!(command.node_id, "node-a");

    let result = DeploymentResult {
        deployment_id: match command.kind {
            domain::RunnerCommandKind::ApplyDeploymentPlan { deployment_id, .. } => deployment_id,
            _ => unreachable!("compile endpoint queues apply deployment commands"),
        },
        status: DeploymentStatus::Succeeded,
        message: "runner applied test command".into(),
        artifact_sha256: deployment["artifact"]["sha256"]
            .as_str()
            .unwrap()
            .to_owned(),
        observed_at: Utc::now(),
    };
    let signed_result = SignedDeploymentResult::sign(
        "node-a",
        result.clone(),
        &SigningKey::from_bytes(&[22u8; 32]),
    )
    .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/runner/nodes/node-a/results")
                .header("content-type", "application/json")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::from(serde_json::to_string(&signed_result).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/runner/results/count")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let count: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(count["count"], 1);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/deployments/{}", result.deployment_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let deployment_state: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(deployment_state["status"], "Succeeded");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/deployments/{}/snapshot", result.deployment_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let snapshot: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(snapshot["deployment_id"], result.deployment_id);
    assert_eq!(snapshot["node_id"], "node-a");
    assert_eq!(snapshot["profile_id"], "profile-a");
    assert_eq!(snapshot["result_status"], "Succeeded");
    assert_eq!(
        snapshot["compiled_config_artifact_id"],
        deployment["artifact"]["id"]
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/deployments/{}/health", result.deployment_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let health: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(health["deployment_id"], result.deployment_id);
    assert_eq!(health["node_id"], "node-a");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["payload_json"]["deployment_status"], "Succeeded");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/runner/nodes/node-a/commands/next?last_sequence=1")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/subscriptions/profile-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let sub: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let decoded = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(sub["body_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(decoded.contains("vless://2f4f6f8a-1111-4c4c-9999-111111111111@node-a.example:443"));
}

#[tokio::test]
async fn api_lists_profiles_and_clients_as_sanitized_inventory() {
    let app = build_router(AppState::dev());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/shadowsocks")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-inventory","port":8388}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(json!({"client_id":"client-inventory","profile_id":"profile-inventory","display_name":"Inventory Alice","kind":"shadowsocks","method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZg=="}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/profiles")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let profiles: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(profiles["profiles"][0]["profile_id"], "profile-inventory");
    assert_eq!(profiles["profiles"][0]["protocol"], "shadowsocks");
    assert_eq!(profiles["profiles"][0]["credential_count"], 1);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/clients")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let clients: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(clients["clients"][0]["client_id"], "client-inventory");
    assert_eq!(clients["clients"][0]["profile_id"], "profile-inventory");
    assert_eq!(clients["clients"][0]["kind"], "shadowsocks");
    assert!(!body
        .windows(b"password".len())
        .any(|window| window == b"password"));
    assert!(!body
        .windows(b"MDEyMzQ1Njc4OWFiY2RlZg==".len())
        .any(|window| window == b"MDEyMzQ1Njc4OWFiY2RlZg=="));
}

#[tokio::test]
async fn app_state_selects_store_from_database_url_env() {
    std::env::remove_var("DATABASE_URL");
    let memory_state = AppState::from_env().await.unwrap();
    assert_eq!(memory_state.store_kind(), "memory");

    std::env::set_var(
        "DATABASE_URL",
        "postgres://proxy:proxy@localhost:5432/proxy_control",
    );
    let postgres_state = AppState::from_env().await.unwrap();
    assert_eq!(postgres_state.store_kind(), "postgres");
    std::env::remove_var("DATABASE_URL");
}

#[tokio::test]
async fn api_creates_and_compiles_shadowsocks_profile() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-ss").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/shadowsocks")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-ss","port":8388}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-ss","profile_id":"profile-ss","display_name":"SS Alice","kind":"shadowsocks","method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZg=="}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    compile_profile(&app, "profile-ss", "node-ss").await;
    let envelope = next_command(&app, "node-ss").await;
    let command = envelope
        .verify(
            &AppState::dev_control_plane_verify_key(),
            "node-ss",
            0,
            &mut std::collections::HashSet::new(),
            Utc::now(),
        )
        .unwrap();
    let domain::RunnerCommandKind::ApplyDeploymentPlan { config_json, .. } = command.kind else {
        unreachable!("compile endpoint queues apply deployment commands")
    };
    assert_eq!(config_json["inbounds"][0]["protocol"], "shadowsocks");
    assert_eq!(
        config_json["inbounds"][0]["settings"]["password"],
        "MDEyMzQ1Njc4OWFiY2RlZg=="
    );
}

#[tokio::test]
async fn api_rejects_invalid_shadowsocks_2022_psk_during_compile() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-ss-invalid").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/shadowsocks")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-ss-invalid"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-ss-invalid","profile_id":"profile-ss-invalid","display_name":"Invalid SS","kind":"shadowsocks","method":"2022-blake3-aes-128-gcm","password":"ss-password"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/deployments/compile")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-ss-invalid","node_id":"node-ss-invalid"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        error.contains("2022-blake3-aes-128-gcm requires a base64-encoded 16-byte psk"),
        "{error}"
    );
}

#[tokio::test]
async fn api_creates_and_compiles_trojan_profile() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-trojan").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/trojan")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-trojan","server_name":"trojan.example.com"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-trojan","profile_id":"profile-trojan","display_name":"Trojan Alice","kind":"trojan","password":"trojan-password"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    compile_profile(&app, "profile-trojan", "node-trojan").await;
    let envelope = next_command(&app, "node-trojan").await;
    let command = envelope
        .verify(
            &AppState::dev_control_plane_verify_key(),
            "node-trojan",
            0,
            &mut std::collections::HashSet::new(),
            Utc::now(),
        )
        .unwrap();
    let domain::RunnerCommandKind::ApplyDeploymentPlan { config_json, .. } = command.kind else {
        unreachable!("compile endpoint queues apply deployment commands")
    };
    assert_eq!(config_json["inbounds"][0]["protocol"], "trojan");
    assert_eq!(
        config_json["inbounds"][0]["settings"]["clients"][0]["password"],
        "trojan-password"
    );
    assert_eq!(
        config_json["inbounds"][0]["streamSettings"]["tlsSettings"]["serverName"],
        "trojan.example.com"
    );
}

#[tokio::test]
async fn runner_reports_raw_usage_sample_and_admin_reads_latest() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-usage").await;
    let sampled_at = Utc::now();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/runner/nodes/node-usage/usage")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"credential_id":"client-a","uplink_bytes":100,"downlink_bytes":200,"sampled_at":sampled_at}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/runner/nodes/node-usage/usage")
                .header("content-type", "application/json")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::from(
                    json!({"credential_id":"client-a","uplink_bytes":300,"downlink_bytes":400,"sampled_at":sampled_at}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/usage/nodes/node-usage/latest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let usage: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(usage["node_id"], "node-usage");
    assert_eq!(usage["credential_id"], "client-a");
    assert_eq!(usage["uplink_bytes"], 300);
    assert_eq!(usage["downlink_bytes"], 400);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/usage/credentials/client-a/rollups/latest?bucket=hour")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let rollup: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(rollup["credential_id"], "client-a");
    assert_eq!(rollup["bucket"], "hour");
    assert_eq!(rollup["uplink_bytes"], 300);
    assert_eq!(rollup["downlink_bytes"], 400);

    for bucket in ["day", "month"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/usage/credentials/client-a/rollups/latest?bucket={bucket}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rollup: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(rollup["credential_id"], "client-a");
        assert_eq!(rollup["bucket"], bucket);
        assert_eq!(rollup["uplink_bytes"], 300);
        assert_eq!(rollup["downlink_bytes"], 400);
    }
}

#[tokio::test]
async fn client_quota_decision_uses_usage_rollups() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-quota").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-quota","server_name":"quota.example.com"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-quota","profile_id":"profile-quota","display_name":"Quota Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111","quota_bytes":500}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let sampled_at = Utc::now();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/runner/nodes/node-quota/usage")
                .header("content-type", "application/json")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::from(
                    json!({"credential_id":"client-quota","uplink_bytes":300,"downlink_bytes":400,"sampled_at":sampled_at}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/clients/client-quota/quota")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let decision: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(decision["credential_id"], "client-quota");
    assert_eq!(decision["quota_bytes"], 500);
    assert_eq!(decision["used_bytes"], 700);
    assert_eq!(decision["allowed"], false);
    assert_eq!(decision["reason"], "quota_exceeded");
}

#[tokio::test]
async fn subscription_hides_quota_exceeded_credentials() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-sub-quota").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-sub-quota","server_name":"quota.example.com"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-over-quota","profile_id":"profile-sub-quota","display_name":"Over Quota","uuid":"11111111-1111-4111-9111-111111111111","quota_bytes":500}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-within-quota","profile_id":"profile-sub-quota","display_name":"Within Quota","uuid":"22222222-2222-4222-9222-222222222222","quota_bytes":5000}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/runner/nodes/node-sub-quota/usage")
                .header("content-type", "application/json")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::from(
                    json!({"credential_id":"client-over-quota","uplink_bytes":300,"downlink_bytes":400}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/subscriptions/profile-sub-quota")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let sub: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let decoded = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(sub["body_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(!decoded.contains("11111111-1111-4111-9111-111111111111"));
    assert!(decoded.contains("22222222-2222-4222-9222-222222222222"));
}

#[tokio::test]
async fn client_expiry_decision_hides_expired_subscription_credentials() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-expiry").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-expiry","server_name":"expiry.example.com"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let expired_at = Utc::now() - Duration::days(1);
    let valid_until = Utc::now() + Duration::days(1);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-expired","profile_id":"profile-expiry","display_name":"Expired Alice","uuid":"11111111-1111-4111-9111-111111111111","expires_at":expired_at}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-valid","profile_id":"profile-expiry","display_name":"Valid Alice","uuid":"22222222-2222-4222-9222-222222222222","expires_at":valid_until}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/clients/client-expired/expiry")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let decision: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(decision["credential_id"], "client-expired");
    assert_eq!(decision["expired"], true);
    assert_eq!(decision["allowed"], false);
    assert_eq!(decision["reason"], "expired");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/subscriptions/profile-expiry")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let sub: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let decoded = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(sub["body_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(!decoded.contains("11111111-1111-4111-9111-111111111111"));
    assert!(decoded.contains("22222222-2222-4222-9222-222222222222"));
}

#[tokio::test]
async fn subscription_token_rotation_invalidates_previous_token() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-sub-token").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-sub-token","server_name":"sub.example.com"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-sub-token","profile_id":"profile-sub-token","display_name":"Sub Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/subscriptions/profile-sub-token/tokens")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let first: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let first_token = first["token"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/subscriptions/profile-sub-token?token={first_token}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/subscriptions/profile-sub-token/tokens/rotate")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let second: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let second_token = second["token"].as_str().unwrap();
    assert_ne!(first_token, second_token);

    let old_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/subscriptions/profile-sub-token?token={first_token}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(old_response.status(), StatusCode::UNAUTHORIZED);

    let new_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/subscriptions/profile-sub-token?token={second_token}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(new_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn compile_deployment_idempotency_key_replays_without_duplicate_command() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-idem").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-idem","server_name":"idem.example.com"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-idem","profile_id":"profile-idem","display_name":"Idem Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let first =
        compile_profile_with_idempotency_key(&app, "profile-idem", "node-idem", "idem-1").await;
    let second =
        compile_profile_with_idempotency_key(&app, "profile-idem", "node-idem", "idem-1").await;
    assert_eq!(second, first);

    let command = next_command(&app, "node-idem").await;
    assert_eq!(command.command.sequence, 1);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/runner/nodes/node-idem/commands/next?last_sequence=1")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn api_queues_operator_rollback_command_from_rollback_pointer() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-rollback").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-rollback","server_name":"example.com"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-a","profile_id":"profile-rollback","display_name":"Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    compile_profile(&app, "profile-rollback", "node-rollback").await;
    let first = next_command_after(&app, "node-rollback", 0).await;
    let (first_deployment_id, first_artifact_sha256) = apply_command_ids(&first);
    submit_signed_result(
        &app,
        "node-rollback",
        &first_deployment_id,
        DeploymentStatus::Succeeded,
        &first_artifact_sha256,
    )
    .await;

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-b","profile_id":"profile-rollback","display_name":"Bob","uuid":"33333333-3333-4333-9333-333333333333"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    compile_profile(&app, "profile-rollback", "node-rollback").await;
    let second = next_command_after(&app, "node-rollback", 1).await;
    let (second_deployment_id, second_artifact_sha256) = apply_command_ids(&second);
    assert_ne!(first_deployment_id, second_deployment_id);
    submit_signed_result(
        &app,
        "node-rollback",
        &second_deployment_id,
        DeploymentStatus::Succeeded,
        &second_artifact_sha256,
    )
    .await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/deployments/{second_deployment_id}/rollback"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let rollback = next_command_after(&app, "node-rollback", 2).await;
    let command = rollback
        .verify(
            &AppState::dev_control_plane_verify_key(),
            "node-rollback",
            2,
            &mut std::collections::HashSet::new(),
            Utc::now(),
        )
        .unwrap();
    assert_eq!(command.sequence, 3);
    let domain::RunnerCommandKind::RollbackDeployment {
        deployment_id,
        rollback_to_deployment_id,
        artifact_sha256,
    } = command.kind
    else {
        unreachable!("rollback endpoint queues rollback deployment commands")
    };
    assert_eq!(deployment_id, second_deployment_id);
    assert_eq!(rollback_to_deployment_id, first_deployment_id);
    assert_eq!(artifact_sha256, first_artifact_sha256);
}

#[tokio::test]
async fn runner_result_verification_uses_per_node_registered_public_key() {
    let app = build_router(AppState::dev());
    let node_signing = SigningKey::from_bytes(&[31u8; 32]);
    let node_public_key_hex = hex::encode(VerifyingKey::from(&node_signing).to_bytes());

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/nodes/register")
        .header("content-type", "application/json")
        .body(Body::from(json!({"registration_token":"dev-registration-token","node_id":"node-keyed","xray_version":"1.8.8","runner_result_public_key_hex":node_public_key_hex}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-keyed","server_name":"example.com"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-keyed","profile_id":"profile-keyed","display_name":"Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    compile_profile(&app, "profile-keyed", "node-keyed").await;
    let command = next_command_after(&app, "node-keyed", 0).await;
    let (deployment_id, artifact_sha256) = apply_command_ids(&command);

    let wrong_key_response = submit_signed_result_with_key(
        &app,
        "node-keyed",
        &deployment_id,
        DeploymentStatus::Succeeded,
        &artifact_sha256,
        SigningKey::from_bytes(&[22u8; 32]),
    )
    .await;
    assert_eq!(wrong_key_response.status(), StatusCode::UNAUTHORIZED);

    let accepted = submit_signed_result_with_key(
        &app,
        "node-keyed",
        &deployment_id,
        DeploymentStatus::Succeeded,
        &artifact_sha256,
        node_signing,
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn deployment_readiness_waits_for_multiple_healthy_samples_and_blocks_unhealthy_latest() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-readiness").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-readiness","server_name":"example.com"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-readiness","profile_id":"profile-readiness","display_name":"Ready Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    compile_profile(&app, "profile-readiness", "node-readiness").await;
    let command = next_command(&app, "node-readiness").await;
    let (deployment_id, artifact_sha256) = apply_command_ids(&command);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/deployments/{deployment_id}/readiness"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let readiness: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(readiness["status"], "blocked");
    assert_eq!(readiness["reason"], "waiting_for_successful_deployment");
    assert_eq!(readiness["healthy_samples"], 0);
    assert_eq!(readiness["required_healthy_samples"], 2);

    submit_signed_result(
        &app,
        "node-readiness",
        &deployment_id,
        DeploymentStatus::Succeeded,
        &artifact_sha256,
    )
    .await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/deployments/{deployment_id}/readiness"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let readiness: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(readiness["status"], "blocked");
    assert_eq!(readiness["reason"], "waiting_for_healthy_samples");
    assert_eq!(readiness["healthy_samples"], 1);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/runner/nodes/node-readiness/deployments/{deployment_id}/health"
                ))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"status":"healthy","payload_json":{"probe":"subscription_fetch_ok"}})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/runner/nodes/node-readiness/deployments/{deployment_id}/health"
                ))
                .header("content-type", "application/json")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::from(
                    json!({"status":"healthy","payload_json":{"probe":"subscription_fetch_ok"}})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/deployments/{deployment_id}/readiness"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let readiness: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(readiness["status"], "ready");
    assert_eq!(readiness["reason"], "ready");
    assert_eq!(readiness["healthy_samples"], 2);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/runner/nodes/node-readiness/deployments/{deployment_id}/health"
                ))
                .header("content-type", "application/json")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::from(
                    json!({"status":"unhealthy","payload_json":{"probe":"subscription_fetch_failed"}})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/deployments/{deployment_id}/readiness"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let readiness: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(readiness["status"], "blocked");
    assert_eq!(readiness["reason"], "latest_health_unhealthy");
}

#[tokio::test]
async fn rollout_advance_promotes_ready_deployment_and_auto_queues_rollback_on_unhealthy() {
    let app = build_router(AppState::dev());
    register_node(&app, "node-advance").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-advance","server_name":"example.com"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-advance-a","profile_id":"profile-advance","display_name":"Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    compile_profile(&app, "profile-advance", "node-advance").await;
    let first = next_command_after(&app, "node-advance", 0).await;
    let (first_deployment_id, first_artifact_sha256) = apply_command_ids(&first);
    submit_signed_result(
        &app,
        "node-advance",
        &first_deployment_id,
        DeploymentStatus::Succeeded,
        &first_artifact_sha256,
    )
    .await;
    post_deployment_health(&app, "node-advance", &first_deployment_id, "healthy").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/deployments/{first_deployment_id}/advance"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let promoted: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(promoted["deployment_id"], first_deployment_id);
    assert_eq!(promoted["action"], "promoted");
    assert_eq!(promoted["readiness"]["status"], "ready");

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-advance-b","profile_id":"profile-advance","display_name":"Bob","uuid":"33333333-3333-4333-9333-333333333333"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    compile_profile(&app, "profile-advance", "node-advance").await;
    let second = next_command_after(&app, "node-advance", 1).await;
    let (second_deployment_id, second_artifact_sha256) = apply_command_ids(&second);
    submit_signed_result(
        &app,
        "node-advance",
        &second_deployment_id,
        DeploymentStatus::Succeeded,
        &second_artifact_sha256,
    )
    .await;
    post_deployment_health(&app, "node-advance", &second_deployment_id, "unhealthy").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/deployments/{second_deployment_id}/advance"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let rollback_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(rollback_response["deployment_id"], second_deployment_id);
    assert_eq!(rollback_response["action"], "rollback_queued");
    assert_eq!(
        rollback_response["rollback_to_deployment_id"],
        first_deployment_id
    );
    assert_eq!(
        rollback_response["readiness"]["reason"],
        "latest_health_unhealthy"
    );

    let rollback = next_command_after(&app, "node-advance", 2).await;
    let command = rollback
        .verify(
            &AppState::dev_control_plane_verify_key(),
            "node-advance",
            2,
            &mut std::collections::HashSet::new(),
            Utc::now(),
        )
        .unwrap();
    let domain::RunnerCommandKind::RollbackDeployment {
        deployment_id,
        rollback_to_deployment_id,
        artifact_sha256,
    } = command.kind
    else {
        unreachable!("advance endpoint should queue rollback command")
    };
    assert_eq!(deployment_id, second_deployment_id);
    assert_eq!(rollback_to_deployment_id, first_deployment_id);
    assert_eq!(artifact_sha256, first_artifact_sha256);
}

#[tokio::test]
async fn runner_result_key_rotation_rejects_old_key_and_accepts_new_key() {
    let app = build_router(AppState::dev());
    let old_signing = SigningKey::from_bytes(&[41u8; 32]);
    let old_public_key_hex = hex::encode(VerifyingKey::from(&old_signing).to_bytes());
    let new_signing = SigningKey::from_bytes(&[42u8; 32]);
    let new_public_key_hex = hex::encode(VerifyingKey::from(&new_signing).to_bytes());

    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/nodes/register")
        .header("content-type", "application/json")
        .body(Body::from(json!({"registration_token":"dev-registration-token","node_id":"node-rotate-key","xray_version":"1.8.8","runner_result_public_key_hex":old_public_key_hex}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/profiles/vless-reality")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":"profile-rotate-key","server_name":"example.com"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/clients")
        .header("content-type", "application/json")
        .body(Body::from(json!({"client_id":"client-rotate-key","profile_id":"profile-rotate-key","display_name":"Rotated Alice","uuid":"2f4f6f8a-1111-4c4c-9999-111111111111"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    compile_profile(&app, "profile-rotate-key", "node-rotate-key").await;
    let command = next_command_after(&app, "node-rotate-key", 0).await;
    let (deployment_id, artifact_sha256) = apply_command_ids(&command);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/nodes/node-rotate-key/runner-result-key/rotate")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"runner_result_public_key_hex":new_public_key_hex}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let rotated: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(rotated["node_id"], "node-rotate-key");
    assert_eq!(rotated["status"], "rotated");

    let old_key_response = submit_signed_result_with_key(
        &app,
        "node-rotate-key",
        &deployment_id,
        DeploymentStatus::Succeeded,
        &artifact_sha256,
        old_signing,
    )
    .await;
    assert_eq!(old_key_response.status(), StatusCode::UNAUTHORIZED);

    let new_key_response = submit_signed_result_with_key(
        &app,
        "node-rotate-key",
        &deployment_id,
        DeploymentStatus::Succeeded,
        &artifact_sha256,
        new_signing,
    )
    .await;
    assert_eq!(new_key_response.status(), StatusCode::ACCEPTED);
}

async fn register_node(app: &axum::Router, node_id: &str) {
    let response = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/nodes/register")
        .header("content-type", "application/json")
        .body(Body::from(json!({"registration_token":"dev-registration-token","node_id":node_id,"xray_version":"1.8.8"}).to_string()))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn compile_profile(app: &axum::Router, profile_id: &str, node_id: &str) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/deployments/compile")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"profile_id":profile_id,"node_id":node_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn compile_profile_with_idempotency_key(
    app: &axum::Router,
    profile_id: &str,
    node_id: &str,
    idempotency_key: &str,
) -> serde_json::Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/deployments/compile")
                .header("content-type", "application/json")
                .header("idempotency-key", idempotency_key)
                .body(Body::from(
                    json!({"profile_id":profile_id,"node_id":node_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

async fn next_command(app: &axum::Router, node_id: &str) -> SignedRunnerCommand {
    next_command_after(app, node_id, 0).await
}

async fn next_command_after(
    app: &axum::Router,
    node_id: &str,
    last_sequence: u64,
) -> SignedRunnerCommand {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/runner/nodes/{node_id}/commands/next?last_sequence={last_sequence}"
                ))
                .header("x-runner-token", "dev-runner-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn apply_command_ids(command: &SignedRunnerCommand) -> (String, String) {
    let domain::RunnerCommandKind::ApplyDeploymentPlan {
        deployment_id,
        artifact_sha256,
        ..
    } = &command.command.kind
    else {
        unreachable!("expected apply deployment command")
    };
    (deployment_id.clone(), artifact_sha256.clone())
}

async fn submit_signed_result(
    app: &axum::Router,
    node_id: &str,
    deployment_id: &str,
    status: DeploymentStatus,
    artifact_sha256: &str,
) {
    let response = submit_signed_result_with_key(
        app,
        node_id,
        deployment_id,
        status,
        artifact_sha256,
        SigningKey::from_bytes(&[22u8; 32]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

async fn post_deployment_health(
    app: &axum::Router,
    node_id: &str,
    deployment_id: &str,
    status: &str,
) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/runner/nodes/{node_id}/deployments/{deployment_id}/health"
                ))
                .header("content-type", "application/json")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::from(
                    json!({"status":status,"payload_json":{"probe":"advance_test"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

async fn submit_signed_result_with_key(
    app: &axum::Router,
    node_id: &str,
    deployment_id: &str,
    status: DeploymentStatus,
    artifact_sha256: &str,
    signing_key: SigningKey,
) -> axum::response::Response {
    let result = DeploymentResult {
        deployment_id: deployment_id.into(),
        status,
        message: "test runner result".into(),
        artifact_sha256: artifact_sha256.into(),
        observed_at: Utc::now(),
    };
    let signed = SignedDeploymentResult::sign(node_id, result, &signing_key).unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/runner/nodes/{node_id}/results"))
                .header("content-type", "application/json")
                .header("x-runner-token", "dev-runner-token")
                .body(Body::from(serde_json::to_string(&signed).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}
