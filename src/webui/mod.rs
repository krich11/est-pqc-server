use anyhow::Result;
use argon2::{password_hash::PasswordHash, PasswordVerifier};
use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, StatusCode, Uri,
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::{fs, net::SocketAddr, path::Path, process::Command, sync::Arc};
use tokio::net::TcpListener;
use tracing::info;

use crate::est::{
    self, EnrollmentArtifactSummary, EnrollmentConfig, PendingEnrollmentRecord,
    PendingEnrollmentState, ServerConfig, WebUiAuthMode,
};

#[derive(RustEmbed)]
#[folder = "webui/static/"]
struct WebUiAssets;

#[derive(Clone)]
pub struct WebUiState {
    pub config: ServerConfig,
}

#[derive(Debug, Serialize)]
struct WebUiStatus {
    est_listen_address: String,
    est_listen_port: u16,
    webui_enabled: bool,
    webui_listen_address: String,
    webui_listen_port: u16,
    systemd_unit_name: String,
    pending_enrollment_count: usize,
    issued_enrollment_count: usize,
    webui_auth_mode: String,
    systemd_active_state: String,
    systemd_enabled_state: String,
}

#[derive(Debug, Serialize)]
struct SystemdStatus {
    unit_name: String,
    active_state: String,
    enabled_state: String,
}

#[derive(Debug, Serialize)]
struct SystemdActionResult {
    unit_name: String,
    action: String,
    success: bool,
    output: String,
}

#[derive(Debug, Deserialize)]
struct RejectRequest {
    reason: Option<String>,
}

pub async fn run_webui(config: ServerConfig) -> Result<()> {
    let state = Arc::new(WebUiState { config });

    let app = Router::new()
        .route("/", get(index))
        .route("/style.css", get(static_asset))
        .route("/app.js", get(static_asset))
        .route("/api/status", get(api_status))
        .route("/api/config", get(api_config))
        .route("/api/rules", get(api_rules))
        .route("/api/enrollment/pending", get(api_pending_enrollments))
        .route("/api/enrollment/history", get(api_enrollment_history))
        .route(
            "/api/enrollment/pending/:operation/:artifact_id/approve",
            post(api_approve_pending_enrollment),
        )
        .route(
            "/api/enrollment/pending/:operation/:artifact_id/reject",
            post(api_reject_pending_enrollment),
        )
        .route("/api/systemd/status", get(api_systemd_status))
        .route("/api/systemd/:action", post(api_systemd_action))
        .with_state(state.clone());

    let bind_address = format!(
        "{}:{}",
        state.config.webui.listen_address, state.config.webui.listen_port
    );
    let socket_addr: SocketAddr = bind_address.parse()?;
    let listener = TcpListener::bind(socket_addr).await?;

    info!("WebUI listener started on https://{bind_address}");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn index(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    authorize(&state, &headers)?;
    let asset = WebUiAssets::get("index.html").ok_or(StatusCode::NOT_FOUND)?;
    Ok(Html(String::from_utf8_lossy(asset.data.as_ref()).into_owned()).into_response())
}

async fn static_asset(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, StatusCode> {
    authorize(&state, &headers)?;
    let asset_name = uri.path().trim_start_matches('/');
    let asset = WebUiAssets::get(asset_name).ok_or(StatusCode::NOT_FOUND)?;
    let content_type = match Path::new(asset_name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
    {
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        _ => "application/octet-stream",
    };

    Ok((
        [(CONTENT_TYPE, content_type)],
        Body::from(asset.data.into_owned()),
    )
        .into_response())
}

async fn api_status(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<WebUiStatus>, StatusCode> {
    authorize(&state, &headers)?;
    Ok(Json(build_status(&state.config)))
}

async fn api_config(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<ServerConfig>, StatusCode> {
    authorize(&state, &headers)?;
    Ok(Json(state.config.clone()))
}

async fn api_rules(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<EnrollmentConfig>, StatusCode> {
    authorize(&state, &headers)?;
    Ok(Json(state.config.enrollment.clone()))
}

async fn api_pending_enrollments(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<PendingEnrollmentRecord>>, StatusCode> {
    authorize(&state, &headers)?;
    let records = est::list_pending_enrollments(Path::new(&state.config.pending_enrollment_dir))
        .map_err(internal_error)?;
    Ok(Json(records))
}

async fn api_enrollment_history(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<EnrollmentArtifactSummary>>, StatusCode> {
    authorize(&state, &headers)?;
    let artifacts = est::list_enrollment_artifacts(Path::new(&state.config.enrollment_storage_dir))
        .map_err(internal_error)?;
    Ok(Json(artifacts))
}

async fn api_approve_pending_enrollment(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath((operation, artifact_id)): AxumPath<(String, String)>,
) -> Result<Json<PendingEnrollmentRecord>, StatusCode> {
    authorize(&state, &headers)?;
    let record = est::update_pending_enrollment_state(
        Path::new(&state.config.pending_enrollment_dir),
        &operation,
        &artifact_id,
        PendingEnrollmentState::Approved,
        None,
    )
    .map_err(internal_error)?;
    Ok(Json(record))
}

async fn api_reject_pending_enrollment(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath((operation, artifact_id)): AxumPath<(String, String)>,
    Json(payload): Json<RejectRequest>,
) -> Result<Json<PendingEnrollmentRecord>, StatusCode> {
    authorize(&state, &headers)?;
    let reason = payload
        .reason
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "rejected by administrator".to_owned());

    let record = est::update_pending_enrollment_state(
        Path::new(&state.config.pending_enrollment_dir),
        &operation,
        &artifact_id,
        PendingEnrollmentState::Rejected,
        Some(reason),
    )
    .map_err(internal_error)?;
    Ok(Json(record))
}

async fn api_systemd_status(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<SystemdStatus>, StatusCode> {
    authorize(&state, &headers)?;
    Ok(Json(query_systemd_status(
        &state.config.webui.systemd_unit_name,
    )))
}

async fn api_systemd_action(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(action): AxumPath<String>,
) -> Result<Json<SystemdActionResult>, StatusCode> {
    authorize(&state, &headers)?;

    let action = action.trim().to_ascii_lowercase();
    if !matches!(action.as_str(), "start" | "stop" | "restart") {
        return Err(StatusCode::BAD_REQUEST);
    }

    let output = Command::new("systemctl")
        .arg(&action)
        .arg(&state.config.webui.systemd_unit_name)
        .output()
        .map_err(|error| internal_error(error.into()))?;

    let mut combined = String::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.trim().is_empty() {
        combined.push_str(stdout.trim());
    }
    if !stderr.trim().is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(stderr.trim());
    }

    Ok(Json(SystemdActionResult {
        unit_name: state.config.webui.systemd_unit_name.clone(),
        action,
        success: output.status.success(),
        output: combined,
    }))
}

fn authorize(state: &WebUiState, headers: &HeaderMap) -> Result<(), StatusCode> {
    match state.config.webui.auth_mode {
        WebUiAuthMode::Basic => authorize_basic(state, headers),
        WebUiAuthMode::Mtls => Ok(()),
    }
}

fn authorize_basic(state: &WebUiState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let header_value = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let encoded = header_value
        .strip_prefix("Basic ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let credentials = String::from_utf8(decoded).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let (username, password) = credentials
        .split_once(':')
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if username != state.config.webui.admin_username {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let parsed_hash = PasswordHash::new(&state.config.webui.admin_password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(())
}

fn build_status(config: &ServerConfig) -> WebUiStatus {
    let systemd_status = query_systemd_status(&config.webui.systemd_unit_name);

    WebUiStatus {
        est_listen_address: config.listen_address.clone(),
        est_listen_port: config.listen_port,
        webui_enabled: config.webui.enabled,
        webui_listen_address: config.webui.listen_address.clone(),
        webui_listen_port: config.webui.listen_port,
        systemd_unit_name: config.webui.systemd_unit_name.clone(),
        pending_enrollment_count: count_artifact_dirs(&config.pending_enrollment_dir),
        issued_enrollment_count: count_artifact_dirs(&config.enrollment_storage_dir),
        webui_auth_mode: match config.webui.auth_mode {
            WebUiAuthMode::Basic => "basic",
            WebUiAuthMode::Mtls => "mtls",
        }
        .to_owned(),
        systemd_active_state: systemd_status.active_state,
        systemd_enabled_state: systemd_status.enabled_state,
    }
}

fn query_systemd_status(unit_name: &str) -> SystemdStatus {
    let active_state = query_systemctl(&["is-active", unit_name]);
    let enabled_state = query_systemctl(&["is-enabled", unit_name]);

    SystemdStatus {
        unit_name: unit_name.to_owned(),
        active_state,
        enabled_state,
    }
}

fn query_systemctl(args: &[&str]) -> String {
    match Command::new("systemctl").args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

            if !stdout.is_empty() {
                stdout
            } else if !stderr.is_empty() {
                stderr
            } else if output.status.success() {
                "ok".to_owned()
            } else {
                "unknown".to_owned()
            }
        }
        Err(error) => format!("unavailable: {error}"),
    }
}

fn count_artifact_dirs(path: &str) -> usize {
    let root = Path::new(path);
    if !root.exists() {
        return 0;
    }

    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_dir(entry.path()).ok())
        .map(|entries| entries.filter_map(Result::ok).count())
        .sum()
}

fn internal_error(error: anyhow::Error) -> StatusCode {
    let _ = error.context("webui operation failed");
    StatusCode::INTERNAL_SERVER_ERROR
}
