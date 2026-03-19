mod cert_store;

use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHash, SaltString},
    PasswordHasher, PasswordVerifier,
};
use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{
        header::{
            AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, PRAGMA, SET_COOKIE,
            WWW_AUTHENTICATE,
        },
        HeaderMap, StatusCode, Uri,
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use openssl::{rand::rand_bytes, sha::sha256};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, RwLock},
};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use self::cert_store::{
    certificate_store_root, delete_leaf_certificate, delete_trusted_ca, get_leaf_certificate,
    get_trusted_ca, initialize_certificate_store, list_leaf_certificates, list_trusted_ca,
    upload_leaf_certificate, upload_trusted_ca, CertificateDetail, CertificateSummary,
    UploadLeafCertificateRequest, UploadTrustedCaRequest,
};
use crate::est::{
    self, EnrollmentArtifactSummary, EnrollmentConfig, PendingEnrollmentRecord,
    PendingEnrollmentState, ServerConfig, WebUiAuthMode, WebUiUser, WebUiUserRole,
};

const BASIC_AUTH_CHALLENGE: &str = r#"Basic realm="EST WebUI""#;
const LOGOUT_MARKER_COOKIE_NAME: &str = "est_webui_logout_nonce";

#[derive(RustEmbed)]
#[folder = "webui/static/"]
struct WebUiAssets;

pub struct WebUiState {
    pub config_path: PathBuf,
    pub certificate_store_path: PathBuf,
    pub config: RwLock<ServerConfig>,
    pub logout_markers: RwLock<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
struct AuthenticatedUser {
    username: String,
    role: WebUiUserRole,
}

#[derive(Debug, Serialize)]
struct AuthenticatedUserInfo {
    username: String,
    role: String,
    can_manage_users: bool,
    can_edit_config: bool,
    can_modify_policy: bool,
    can_manage_certificates: bool,
    can_manage_enrollments: bool,
    can_manage_systemd: bool,
    read_only: bool,
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
    current_user: AuthenticatedUserInfo,
}

#[derive(Debug, Serialize)]
struct SystemdStatus {
    unit_name: String,
    description: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    enabled_state: String,
    main_pid: String,
    tasks_current: String,
    memory_current: String,
    recent_journal: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SystemdActionResult {
    unit_name: String,
    action: String,
    success: bool,
    output: String,
}

#[derive(Debug, Serialize)]
struct WebUiUserSummary {
    username: String,
    role: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct RejectRequest {
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    role: WebUiUserRole,
}

#[derive(Debug, Deserialize)]
struct UpdateUserPasswordRequest {
    password: String,
}

#[derive(Debug, Deserialize)]
struct UpdateUserRoleRequest {
    role: WebUiUserRole,
}

#[derive(Debug, Deserialize)]
struct UpdateUserEnabledRequest {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct ChangeOwnPasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug)]
enum WebUiError {
    Status(StatusCode),
    Unauthorized,
    Message(StatusCode, String),
}

impl IntoResponse for WebUiError {
    fn into_response(self) -> Response {
        match self {
            Self::Status(status) => status.into_response(),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                [
                    (WWW_AUTHENTICATE, BASIC_AUTH_CHALLENGE),
                    (CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
                    (PRAGMA, "no-cache"),
                ],
            )
                .into_response(),
            Self::Message(status, message) => (status, message).into_response(),
        }
    }
}

pub async fn run_webui(config_path: PathBuf, config: ServerConfig) -> Result<()> {
    let certificate_store_path = certificate_store_root();
    initialize_certificate_store(&certificate_store_path)?;

    let state = Arc::new(WebUiState {
        config_path,
        certificate_store_path,
        config: RwLock::new(config),
        logout_markers: RwLock::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/logout", get(logout))
        .route("/style.css", get(static_asset))
        .route("/app.js", get(static_asset))
        .route("/api/status", get(api_status))
        .route("/api/config", get(api_config).post(api_update_config))
        .route(
            "/api/certstore/ca",
            get(api_list_trusted_ca).post(api_upload_trusted_ca),
        )
        .route(
            "/api/certstore/ca/:fingerprint",
            get(api_get_trusted_ca).delete(api_delete_trusted_ca),
        )
        .route(
            "/api/certstore/leaf",
            get(api_list_leaf_certificates).post(api_upload_leaf_certificate),
        )
        .route(
            "/api/certstore/leaf/:fingerprint",
            get(api_get_leaf_certificate).delete(api_delete_leaf_certificate),
        )
        .route("/api/rules", get(api_rules).post(api_update_rules))
        .route("/api/me", get(api_me))
        .route("/api/users", get(api_users).post(api_create_user))
        .route(
            "/api/users/:username/password",
            post(api_update_user_password),
        )
        .route("/api/users/:username/role", post(api_update_user_role))
        .route(
            "/api/users/:username/enabled",
            post(api_update_user_enabled),
        )
        .route("/api/users/:username/delete", post(api_delete_user))
        .route("/api/account/password", post(api_change_own_password))
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

    let config = state
        .config
        .read()
        .map_err(|_| anyhow::anyhow!("failed to read WebUI configuration"))?
        .clone();
    let bind_address = format!(
        "{}:{}",
        config.webui.listen_address, config.webui.listen_port
    );
    let socket_addr: SocketAddr = bind_address.parse()?;
    let listener = TcpListener::bind(socket_addr).await?;

    info!("WebUI listener started on http://{bind_address}");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn index(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Response, WebUiError> {
    authenticate_user(&state, &headers)?;
    let asset = WebUiAssets::get("index.html").ok_or(WebUiError::Status(StatusCode::NOT_FOUND))?;
    Ok(Html(String::from_utf8_lossy(asset.data.as_ref()).into_owned()).into_response())
}

async fn static_asset(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, WebUiError> {
    let asset_name = uri.path().trim_start_matches('/');
    if asset_name != "style.css" {
        authenticate_user(&state, &headers)?;
    }
    let asset = WebUiAssets::get(asset_name).ok_or(WebUiError::Status(StatusCode::NOT_FOUND))?;
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

async fn logout(State(state): State<Arc<WebUiState>>, headers: HeaderMap) -> Response {
    let set_cookie = current_config(&state)
        .ok()
        .and_then(|config| {
            if config.webui.auth_mode != WebUiAuthMode::Basic {
                return None;
            }

            let fingerprint = authorization_fingerprint(&headers)?;
            let marker = generate_logout_marker().ok()?;
            state
                .logout_markers
                .write()
                .ok()?
                .insert(marker.clone(), fingerprint);

            Some(build_logout_marker_cookie(&marker))
        })
        .unwrap_or_else(expire_logout_marker_cookie);

    (
        StatusCode::OK,
        [
            (SET_COOKIE, set_cookie.as_str()),
            (CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
            (PRAGMA, "no-cache"),
            (CONTENT_TYPE, "text/html; charset=utf-8"),
        ],
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Logged out · EST PQC Server</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body class="logout-page">
  <main class="logout-shell">
    <section class="panel logout-panel">
      <div class="brand logout-brand">
        <div class="brand-mark">EST</div>
        <div>
          <h1>EST PQC Server</h1>
          <p>Administrative WebUI</p>
        </div>
      </div>
      <span class="role-badge">Session ended</span>
      <h2>Logged out</h2>
      <p class="muted">
        You have been logged out of the EST WebUI.
      </p>
      <p class="muted">
        This page is shown without issuing a new Basic authentication challenge.
      </p>
      <p class="muted">
        The browser must present fresh credentials before the WebUI will accept another login.
      </p>
      <div class="logout-actions">
        <a class="primary-button logout-link" href="/">Return to login</a>
      </div>
    </section>
  </main>
</body>
</html>"#,
    )
        .into_response()
}

async fn api_status(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<WebUiStatus>, WebUiError> {
    let user = authenticate_user(&state, &headers)?;
    Ok(Json(build_status(&current_config(&state)?, &user)))
}

async fn api_config(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<ServerConfig>, WebUiError> {
    authenticate_user(&state, &headers)?;
    Ok(Json(current_config(&state)?))
}

async fn api_update_config(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    Json(payload): Json<ServerConfig>,
) -> Result<Json<ServerConfig>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_admin(&actor)?;

    persist_config(&state, &payload).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "save-config",
            "persist updated config",
            &format!("{error:?}"),
        );
        error
    })?;
    replace_config(&state, payload.clone()).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "save-config",
            "replace in-memory config",
            &format!("{error:?}"),
        );
        error
    })?;

    Ok(Json(payload))
}

async fn api_list_trusted_ca(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<CertificateSummary>>, WebUiError> {
    authenticate_user(&state, &headers)?;
    let certificates = list_trusted_ca(&state.certificate_store_path).map_err(internal_error)?;
    Ok(Json(certificates))
}

async fn api_upload_trusted_ca(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    Json(payload): Json<UploadTrustedCaRequest>,
) -> Result<Json<CertificateSummary>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_admin(&actor)?;

    let filename = payload.filename.clone();
    let certificate =
        upload_trusted_ca(&state.certificate_store_path, payload).map_err(|error| {
            log_webui_failure(
                Some(&actor),
                "upload-trusted-ca",
                &format!("filename={filename}"),
                &error.to_string(),
            );
            internal_error(error)
        })?;
    Ok(Json(certificate))
}

async fn api_get_trusted_ca(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(fingerprint): AxumPath<String>,
) -> Result<Json<CertificateDetail>, WebUiError> {
    authenticate_user(&state, &headers)?;
    let certificate =
        get_trusted_ca(&state.certificate_store_path, &fingerprint).map_err(internal_error)?;
    Ok(Json(certificate))
}

async fn api_delete_trusted_ca(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(fingerprint): AxumPath<String>,
) -> Result<StatusCode, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_admin(&actor)?;

    delete_trusted_ca(&state.certificate_store_path, &fingerprint).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "delete-trusted-ca",
            &format!("fingerprint={fingerprint}"),
            &error.to_string(),
        );
        internal_error(error)
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_list_leaf_certificates(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<CertificateSummary>>, WebUiError> {
    authenticate_user(&state, &headers)?;
    let certificates =
        list_leaf_certificates(&state.certificate_store_path).map_err(internal_error)?;
    Ok(Json(certificates))
}

async fn api_upload_leaf_certificate(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    Json(payload): Json<UploadLeafCertificateRequest>,
) -> Result<Json<CertificateSummary>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_admin(&actor)?;

    let filename = payload.filename.clone();
    let config = current_config(&state)?;
    let openssl_binary = if config.openssl_binary.trim().is_empty() {
        "openssl".to_owned()
    } else {
        config.openssl_binary
    };

    let certificate =
        upload_leaf_certificate(&state.certificate_store_path, payload, &openssl_binary).map_err(
            |error| {
                log_webui_failure(
                    Some(&actor),
                    "upload-leaf-certificate",
                    &format!("filename={filename}"),
                    &error.to_string(),
                );
                if error.to_string() == "The Trusted CA must be loaded first." {
                    WebUiError::Message(StatusCode::BAD_REQUEST, error.to_string())
                } else {
                    internal_error(error)
                }
            },
        )?;
    Ok(Json(certificate))
}

async fn api_get_leaf_certificate(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(fingerprint): AxumPath<String>,
) -> Result<Json<CertificateDetail>, WebUiError> {
    authenticate_user(&state, &headers)?;
    let certificate = get_leaf_certificate(&state.certificate_store_path, &fingerprint)
        .map_err(internal_error)?;
    Ok(Json(certificate))
}

async fn api_delete_leaf_certificate(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(fingerprint): AxumPath<String>,
) -> Result<StatusCode, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_admin(&actor)?;

    delete_leaf_certificate(&state.certificate_store_path, &fingerprint).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "delete-leaf-certificate",
            &format!("fingerprint={fingerprint}"),
            &error.to_string(),
        );
        internal_error(error)
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_rules(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<EnrollmentConfig>, WebUiError> {
    authenticate_user(&state, &headers)?;
    Ok(Json(current_config(&state)?.enrollment))
}

async fn api_update_rules(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    Json(payload): Json<EnrollmentConfig>,
) -> Result<Json<EnrollmentConfig>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_admin(&actor)?;

    let mut config = writeable_config(&state)?;
    config.enrollment = payload.clone();

    persist_config(&state, &config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "save-rules",
            "persist enrollment policy",
            &format!("{error:?}"),
        );
        error
    })?;
    replace_config(&state, config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "save-rules",
            "replace in-memory enrollment policy",
            &format!("{error:?}"),
        );
        error
    })?;

    Ok(Json(payload))
}

async fn api_me(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<AuthenticatedUserInfo>, WebUiError> {
    let user = authenticate_user(&state, &headers)?;
    Ok(Json(user_info(&user)))
}

async fn api_users(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<WebUiUserSummary>>, WebUiError> {
    authenticate_user(&state, &headers)?;

    let config = current_config(&state)?;
    let users = effective_webui_users(&config)
        .into_iter()
        .map(|entry| WebUiUserSummary {
            username: entry.username,
            role: role_label(&entry.role).to_owned(),
            enabled: entry.enabled,
        })
        .collect();

    Ok(Json(users))
}

async fn api_create_user(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<WebUiUserSummary>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_super_admin(&actor)?;

    let username = payload.username.trim().to_owned();
    if username.is_empty() {
        return Err(WebUiError::Message(
            StatusCode::BAD_REQUEST,
            "username must not be empty".to_owned(),
        ));
    }
    if payload.password.is_empty() {
        return Err(WebUiError::Message(
            StatusCode::BAD_REQUEST,
            "password must not be empty".to_owned(),
        ));
    }

    let mut config = writeable_config(&state)?;
    ensure_user_list_materialized(&mut config);

    if config
        .webui
        .users
        .iter()
        .any(|user| user.username == username)
    {
        return Err(WebUiError::Message(
            StatusCode::CONFLICT,
            format!("user `{username}` already exists"),
        ));
    }

    let password_hash = hash_password(&payload.password).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "create-user",
            &format!("username={username} role={}", role_label(&payload.role)),
            &format!("{error:?}"),
        );
        error
    })?;
    let created_user = WebUiUser {
        username: username.clone(),
        password_hash,
        role: payload.role,
        enabled: true,
    };
    let summary = WebUiUserSummary {
        username: username.clone(),
        role: role_label(&created_user.role).to_owned(),
        enabled: true,
    };

    config.webui.users.push(created_user);
    persist_config(&state, &config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "create-user",
            &format!("username={username}"),
            &format!("{error:?}"),
        );
        error
    })?;
    replace_config(&state, config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "create-user",
            &format!("username={username}"),
            &format!("{error:?}"),
        );
        error
    })?;

    Ok(Json(summary))
}

async fn api_update_user_password(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(username): AxumPath<String>,
    Json(payload): Json<UpdateUserPasswordRequest>,
) -> Result<Json<WebUiUserSummary>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_super_admin(&actor)?;

    if payload.password.is_empty() {
        return Err(WebUiError::Message(
            StatusCode::BAD_REQUEST,
            "password must not be empty".to_owned(),
        ));
    }

    let mut config = writeable_config(&state)?;
    ensure_user_list_materialized(&mut config);

    let user = config
        .webui
        .users
        .iter_mut()
        .find(|user| user.username == username)
        .ok_or_else(|| {
            WebUiError::Message(
                StatusCode::NOT_FOUND,
                format!("user `{username}` not found"),
            )
        })?;

    user.password_hash = hash_password(&payload.password).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "update-user-password",
            &format!("username={username}"),
            &format!("{error:?}"),
        );
        error
    })?;
    let summary = WebUiUserSummary {
        username: user.username.clone(),
        role: role_label(&user.role).to_owned(),
        enabled: user.enabled,
    };

    persist_config(&state, &config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "update-user-password",
            &format!("username={username}"),
            &format!("{error:?}"),
        );
        error
    })?;
    replace_config(&state, config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "update-user-password",
            &format!("username={username}"),
            &format!("{error:?}"),
        );
        error
    })?;

    Ok(Json(summary))
}

async fn api_update_user_role(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(username): AxumPath<String>,
    Json(payload): Json<UpdateUserRoleRequest>,
) -> Result<Json<WebUiUserSummary>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_super_admin(&actor)?;

    let mut config = writeable_config(&state)?;
    ensure_user_list_materialized(&mut config);

    let user_index = config
        .webui
        .users
        .iter()
        .position(|user| user.username == username)
        .ok_or_else(|| {
            WebUiError::Message(
                StatusCode::NOT_FOUND,
                format!("user `{username}` not found"),
            )
        })?;

    let requested_role = payload.role.clone();
    config.webui.users[user_index].role = requested_role.clone();
    ensure_super_admin_present(&config.webui.users)?;

    let summary = WebUiUserSummary {
        username: config.webui.users[user_index].username.clone(),
        role: role_label(&config.webui.users[user_index].role).to_owned(),
        enabled: config.webui.users[user_index].enabled,
    };

    persist_config(&state, &config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "update-user-role",
            &format!("username={username} role={}", role_label(&requested_role)),
            &format!("{error:?}"),
        );
        error
    })?;
    replace_config(&state, config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "update-user-role",
            &format!("username={username} role={}", role_label(&requested_role)),
            &format!("{error:?}"),
        );
        error
    })?;

    Ok(Json(summary))
}

async fn api_update_user_enabled(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(username): AxumPath<String>,
    Json(payload): Json<UpdateUserEnabledRequest>,
) -> Result<Json<WebUiUserSummary>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_super_admin(&actor)?;

    let mut config = writeable_config(&state)?;
    ensure_user_list_materialized(&mut config);

    let user_index = config
        .webui
        .users
        .iter()
        .position(|user| user.username == username)
        .ok_or_else(|| {
            WebUiError::Message(
                StatusCode::NOT_FOUND,
                format!("user `{username}` not found"),
            )
        })?;

    config.webui.users[user_index].enabled = payload.enabled;
    ensure_super_admin_present(&config.webui.users)?;

    let summary = WebUiUserSummary {
        username: config.webui.users[user_index].username.clone(),
        role: role_label(&config.webui.users[user_index].role).to_owned(),
        enabled: config.webui.users[user_index].enabled,
    };

    persist_config(&state, &config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "update-user-enabled",
            &format!("username={username} enabled={}", payload.enabled),
            &format!("{error:?}"),
        );
        error
    })?;
    replace_config(&state, config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "update-user-enabled",
            &format!("username={username} enabled={}", payload.enabled),
            &format!("{error:?}"),
        );
        error
    })?;

    Ok(Json(summary))
}

async fn api_delete_user(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(username): AxumPath<String>,
) -> Result<Json<Vec<WebUiUserSummary>>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_super_admin(&actor)?;

    let mut config = writeable_config(&state)?;
    ensure_user_list_materialized(&mut config);

    let original_len = config.webui.users.len();
    config.webui.users.retain(|user| user.username != username);

    if config.webui.users.len() == original_len {
        return Err(WebUiError::Message(
            StatusCode::NOT_FOUND,
            format!("user `{username}` not found"),
        ));
    }

    ensure_super_admin_present(&config.webui.users)?;
    persist_config(&state, &config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "delete-user",
            &format!("username={username}"),
            &format!("{error:?}"),
        );
        error
    })?;
    let summaries = config
        .webui
        .users
        .iter()
        .map(|user| WebUiUserSummary {
            username: user.username.clone(),
            role: role_label(&user.role).to_owned(),
            enabled: user.enabled,
        })
        .collect();
    replace_config(&state, config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "delete-user",
            &format!("username={username}"),
            &format!("{error:?}"),
        );
        error
    })?;

    Ok(Json(summaries))
}

async fn api_change_own_password(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    Json(payload): Json<ChangeOwnPasswordRequest>,
) -> Result<Json<AuthenticatedUserInfo>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    if payload.new_password.is_empty() {
        return Err(WebUiError::Message(
            StatusCode::BAD_REQUEST,
            "new_password must not be empty".to_owned(),
        ));
    }

    let mut config = writeable_config(&state)?;
    ensure_user_list_materialized(&mut config);

    let user = config
        .webui
        .users
        .iter_mut()
        .find(|user| user.username == actor.username)
        .ok_or_else(|| {
            WebUiError::Message(
                StatusCode::NOT_FOUND,
                format!("current user `{}` not found", actor.username),
            )
        })?;

    verify_password_hash(&user.password_hash, &payload.current_password).map_err(|_| {
        log_webui_failure(
            Some(&actor),
            "change-own-password",
            &format!("username={}", actor.username),
            "current password verification failed",
        );
        WebUiError::Message(
            StatusCode::UNAUTHORIZED,
            "current password verification failed".to_owned(),
        )
    })?;

    user.password_hash = hash_password(&payload.new_password).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "change-own-password",
            &format!("username={}", actor.username),
            &format!("{error:?}"),
        );
        error
    })?;
    persist_config(&state, &config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "change-own-password",
            &format!("username={}", actor.username),
            &format!("{error:?}"),
        );
        error
    })?;
    replace_config(&state, config).map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "change-own-password",
            &format!("username={}", actor.username),
            &format!("{error:?}"),
        );
        error
    })?;

    Ok(Json(user_info(&actor)))
}

async fn api_pending_enrollments(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<PendingEnrollmentRecord>>, WebUiError> {
    authenticate_user(&state, &headers)?;
    let config = current_config(&state)?;
    let records = est::list_pending_enrollments(Path::new(&config.pending_enrollment_dir))
        .map_err(internal_error)?;
    Ok(Json(records))
}

async fn api_enrollment_history(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<EnrollmentArtifactSummary>>, WebUiError> {
    authenticate_user(&state, &headers)?;
    let config = current_config(&state)?;
    let artifacts = est::list_enrollment_artifacts(Path::new(&config.enrollment_storage_dir))
        .map_err(internal_error)?;
    Ok(Json(artifacts))
}

async fn api_approve_pending_enrollment(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath((operation, artifact_id)): AxumPath<(String, String)>,
) -> Result<Json<PendingEnrollmentRecord>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_admin(&actor)?;
    let config = current_config(&state)?;
    let record = est::update_pending_enrollment_state(
        Path::new(&config.pending_enrollment_dir),
        &operation,
        &artifact_id,
        PendingEnrollmentState::Approved,
        None,
    )
    .map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "approve-pending-enrollment",
            &format!("operation={operation} artifact_id={artifact_id}"),
            &error.to_string(),
        );
        internal_error(error)
    })?;
    Ok(Json(record))
}

async fn api_reject_pending_enrollment(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath((operation, artifact_id)): AxumPath<(String, String)>,
    Json(payload): Json<RejectRequest>,
) -> Result<Json<PendingEnrollmentRecord>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_admin(&actor)?;
    let config = current_config(&state)?;
    let reason = payload
        .reason
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "rejected by administrator".to_owned());

    let record = est::update_pending_enrollment_state(
        Path::new(&config.pending_enrollment_dir),
        &operation,
        &artifact_id,
        PendingEnrollmentState::Rejected,
        Some(reason),
    )
    .map_err(|error| {
        log_webui_failure(
            Some(&actor),
            "reject-pending-enrollment",
            &format!("operation={operation} artifact_id={artifact_id}"),
            &error.to_string(),
        );
        internal_error(error)
    })?;
    Ok(Json(record))
}

async fn api_systemd_status(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
) -> Result<Json<SystemdStatus>, WebUiError> {
    authenticate_user(&state, &headers)?;
    let config = current_config(&state)?;
    Ok(Json(query_systemd_status(&config.webui.systemd_unit_name)))
}

async fn api_systemd_action(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    AxumPath(action): AxumPath<String>,
) -> Result<Json<SystemdActionResult>, WebUiError> {
    let actor = authenticate_user(&state, &headers)?;
    ensure_admin(&actor)?;
    let config = current_config(&state)?;

    let action = action.trim().to_ascii_lowercase();
    if !matches!(action.as_str(), "start" | "stop" | "restart" | "reload") {
        log_webui_failure(
            Some(&actor),
            "systemd-action",
            &format!("action={action}"),
            "unsupported systemd action",
        );
        return Err(WebUiError::Status(StatusCode::BAD_REQUEST));
    }

    let output = Command::new("systemctl")
        .arg(&action)
        .arg(&config.webui.systemd_unit_name)
        .output()
        .map_err(|error| {
            log_webui_failure(
                Some(&actor),
                "systemd-action",
                &format!("action={action} unit={}", config.webui.systemd_unit_name),
                &error.to_string(),
            );
            internal_error(error.into())
        })?;

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

    if !output.status.success() {
        log_webui_failure(
            Some(&actor),
            "systemd-action",
            &format!("action={action} unit={}", config.webui.systemd_unit_name),
            combined.trim(),
        );
    }

    Ok(Json(SystemdActionResult {
        unit_name: config.webui.systemd_unit_name,
        action,
        success: output.status.success(),
        output: combined,
    }))
}

fn current_config(state: &Arc<WebUiState>) -> Result<ServerConfig, WebUiError> {
    state
        .config
        .read()
        .map(|config| config.clone())
        .map_err(|_| WebUiError::Status(StatusCode::INTERNAL_SERVER_ERROR))
}

fn writeable_config(state: &Arc<WebUiState>) -> Result<ServerConfig, WebUiError> {
    current_config(state)
}

fn replace_config(state: &Arc<WebUiState>, config: ServerConfig) -> Result<(), WebUiError> {
    let mut guard = state
        .config
        .write()
        .map_err(|_| WebUiError::Status(StatusCode::INTERNAL_SERVER_ERROR))?;
    *guard = config;
    Ok(())
}

fn persist_config(state: &Arc<WebUiState>, config: &ServerConfig) -> Result<(), WebUiError> {
    let content = toml::to_string_pretty(config)
        .context("failed to serialize configuration")
        .map_err(internal_error)?;
    fs::write(&state.config_path, content)
        .with_context(|| format!("failed to write `{}`", state.config_path.display()))
        .map_err(internal_error)?;
    Ok(())
}

fn ensure_user_list_materialized(config: &mut ServerConfig) {
    if !config.webui.users.is_empty() {
        return;
    }

    if config.webui.admin_username.trim().is_empty()
        || config.webui.admin_password_hash.trim().is_empty()
    {
        return;
    }

    config.webui.users.push(WebUiUser {
        username: config.webui.admin_username.clone(),
        password_hash: config.webui.admin_password_hash.clone(),
        role: WebUiUserRole::SuperAdmin,
        enabled: true,
    });
}

fn effective_webui_users(config: &ServerConfig) -> Vec<WebUiUser> {
    let mut cloned = config.clone();
    ensure_user_list_materialized(&mut cloned);
    cloned.webui.users
}

fn authenticate_user(
    state: &Arc<WebUiState>,
    headers: &HeaderMap,
) -> Result<AuthenticatedUser, WebUiError> {
    let config = current_config(state)?;
    match config.webui.auth_mode {
        WebUiAuthMode::Basic => authenticate_basic_user(state, &config, headers),
        WebUiAuthMode::Mtls => Ok(AuthenticatedUser {
            username: "mtls-authenticated".to_owned(),
            role: WebUiUserRole::SuperAdmin,
        }),
    }
}

fn authenticate_basic_user(
    state: &Arc<WebUiState>,
    config: &ServerConfig,
    headers: &HeaderMap,
) -> Result<AuthenticatedUser, WebUiError> {
    let header_value = match headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => value,
        None => {
            eprintln!("webui auth failure: missing Authorization header");
            return Err(WebUiError::Unauthorized);
        }
    };

    let encoded = match header_value.strip_prefix("Basic ") {
        Some(value) => value,
        None => {
            eprintln!("webui auth failure: unsupported Authorization scheme");
            return Err(WebUiError::Unauthorized);
        }
    };

    if let Some(marker) = logout_marker_from_headers(headers) {
        let fingerprint = authorization_fingerprint(headers).ok_or(WebUiError::Unauthorized)?;
        let mut logout_markers = state
            .logout_markers
            .write()
            .map_err(|_| WebUiError::Status(StatusCode::INTERNAL_SERVER_ERROR))?;
        if logout_markers.get(marker.as_str()) == Some(&fingerprint) {
            logout_markers.remove(marker.as_str());
            eprintln!("webui auth failure: rejected stale logged-out browser credentials");
            return Err(WebUiError::Unauthorized);
        }
    }

    let decoded = match BASE64_STANDARD.decode(encoded) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("webui auth failure: invalid base64 credentials");
            return Err(WebUiError::Unauthorized);
        }
    };

    let credentials = match String::from_utf8(decoded) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("webui auth failure: credentials were not valid UTF-8");
            return Err(WebUiError::Unauthorized);
        }
    };

    let (username, password) = match credentials.split_once(':') {
        Some(value) => value,
        None => {
            eprintln!("webui auth failure: credentials missing ':' separator");
            return Err(WebUiError::Unauthorized);
        }
    };

    let users = effective_webui_users(config);
    let user = match users.iter().find(|user| user.username == username) {
        Some(user) => user,
        None => {
            eprintln!(
                "webui auth failure: username mismatch for presented username '{}'",
                username
            );
            return Err(WebUiError::Unauthorized);
        }
    };

    if !user.enabled {
        eprintln!(
            "webui auth failure: disabled account attempted login for username '{}'",
            username
        );
        return Err(WebUiError::Unauthorized);
    }

    if verify_password_hash(&user.password_hash, password).is_err() {
        eprintln!(
            "webui auth failure: password verification failed for username '{}'",
            username
        );
        return Err(WebUiError::Unauthorized);
    }

    Ok(AuthenticatedUser {
        username: user.username.clone(),
        role: user.role.clone(),
    })
}

fn logout_marker_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let (name, value) = cookie.trim().split_once('=')?;
        if name == LOGOUT_MARKER_COOKIE_NAME {
            return Some(value.to_owned());
        }
    }
    None
}

fn authorization_fingerprint(headers: &HeaderMap) -> Option<String> {
    let header_value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    Some(hex_encode(&sha256(header_value.as_bytes())))
}

fn generate_logout_marker() -> Result<String, WebUiError> {
    let mut marker_bytes = [0_u8; 16];
    rand_bytes(&mut marker_bytes)
        .context("failed to generate logout marker")
        .map_err(internal_error)?;
    Ok(hex_encode(&marker_bytes))
}

fn build_logout_marker_cookie(marker: &str) -> String {
    format!("{LOGOUT_MARKER_COOKIE_NAME}={marker}; Path=/; HttpOnly; SameSite=Strict; Max-Age=600")
}

fn expire_logout_marker_cookie() -> String {
    format!("{LOGOUT_MARKER_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn verify_password_hash(password_hash: &str, password: &str) -> Result<(), WebUiError> {
    let parsed_hash = PasswordHash::new(password_hash).map_err(|_| {
        eprintln!("webui auth failure: configured password hash could not be parsed");
        WebUiError::Status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;

    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| WebUiError::Unauthorized)
}

fn hash_password(password: &str) -> Result<String, WebUiError> {
    let mut salt_bytes = [0_u8; 16];
    rand_bytes(&mut salt_bytes)
        .context("failed to generate password salt")
        .map_err(internal_error)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|error| {
        WebUiError::Message(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode password salt: {error}"),
        )
    })?;

    let hash = argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| {
            WebUiError::Message(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to hash password: {error}"),
            )
        })?;

    Ok(hash.to_string())
}

fn log_webui_denied(user: &AuthenticatedUser, action: &str, detail: &str) {
    warn!(
        username = %user.username,
        role = role_label(&user.role),
        action = action,
        detail = detail,
        "webui action denied"
    );
}

fn log_webui_failure(user: Option<&AuthenticatedUser>, action: &str, detail: &str, message: &str) {
    let username = user.map_or("-", |entry| entry.username.as_str());
    let role = user.map_or("-", |entry| role_label(&entry.role));
    error!(
        username = username,
        role = role,
        action = action,
        detail = detail,
        message = message,
        "webui action failed"
    );
}

fn can_manage_users(role: &WebUiUserRole) -> bool {
    matches!(role, WebUiUserRole::SuperAdmin)
}

fn can_edit_config(role: &WebUiUserRole) -> bool {
    matches!(role, WebUiUserRole::Admin | WebUiUserRole::SuperAdmin)
}

fn can_modify_policy(role: &WebUiUserRole) -> bool {
    matches!(role, WebUiUserRole::Admin | WebUiUserRole::SuperAdmin)
}

fn can_manage_certificates(role: &WebUiUserRole) -> bool {
    matches!(role, WebUiUserRole::Admin | WebUiUserRole::SuperAdmin)
}

fn can_manage_enrollments(role: &WebUiUserRole) -> bool {
    matches!(role, WebUiUserRole::Admin | WebUiUserRole::SuperAdmin)
}

fn can_manage_systemd(role: &WebUiUserRole) -> bool {
    matches!(role, WebUiUserRole::Admin | WebUiUserRole::SuperAdmin)
}

fn is_read_only(role: &WebUiUserRole) -> bool {
    matches!(role, WebUiUserRole::Auditor)
}

fn ensure_admin(user: &AuthenticatedUser) -> Result<(), WebUiError> {
    if is_read_only(&user.role) {
        log_webui_denied(
            user,
            "admin-action",
            "read-only role attempted write operation",
        );
        return Err(WebUiError::Message(
            StatusCode::FORBIDDEN,
            "admin role is required for this action".to_owned(),
        ));
    }

    Ok(())
}

fn ensure_super_admin(user: &AuthenticatedUser) -> Result<(), WebUiError> {
    if !can_manage_users(&user.role) {
        log_webui_denied(
            user,
            "user-management",
            "non-super-admin attempted user management operation",
        );
        return Err(WebUiError::Message(
            StatusCode::FORBIDDEN,
            "super-admin role is required for user management".to_owned(),
        ));
    }

    Ok(())
}

fn ensure_super_admin_present(users: &[WebUiUser]) -> Result<(), WebUiError> {
    let has_super_admin = users
        .iter()
        .any(|user| user.enabled && user.role == WebUiUserRole::SuperAdmin);

    if !has_super_admin {
        return Err(WebUiError::Message(
            StatusCode::BAD_REQUEST,
            "at least one enabled super-admin must remain".to_owned(),
        ));
    }

    Ok(())
}

fn user_info(user: &AuthenticatedUser) -> AuthenticatedUserInfo {
    AuthenticatedUserInfo {
        username: user.username.clone(),
        role: role_label(&user.role).to_owned(),
        can_manage_users: can_manage_users(&user.role),
        can_edit_config: can_edit_config(&user.role),
        can_modify_policy: can_modify_policy(&user.role),
        can_manage_certificates: can_manage_certificates(&user.role),
        can_manage_enrollments: can_manage_enrollments(&user.role),
        can_manage_systemd: can_manage_systemd(&user.role),
        read_only: is_read_only(&user.role),
    }
}

fn role_label(role: &WebUiUserRole) -> &'static str {
    match role {
        WebUiUserRole::Auditor => "auditor",
        WebUiUserRole::Admin => "admin",
        WebUiUserRole::SuperAdmin => "super-admin",
    }
}

fn build_status(config: &ServerConfig, user: &AuthenticatedUser) -> WebUiStatus {
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
        current_user: user_info(user),
    }
}

fn query_systemd_status(unit_name: &str) -> SystemdStatus {
    SystemdStatus {
        unit_name: unit_name.to_owned(),
        description: query_systemctl_show(unit_name, "Description"),
        load_state: query_systemctl_show(unit_name, "LoadState"),
        active_state: query_systemctl_show(unit_name, "ActiveState"),
        sub_state: query_systemctl_show(unit_name, "SubState"),
        enabled_state: query_systemctl(&["is-enabled", unit_name]),
        main_pid: query_systemctl_show(unit_name, "MainPID"),
        tasks_current: query_systemctl_show(unit_name, "TasksCurrent"),
        memory_current: query_systemctl_show(unit_name, "MemoryCurrent"),
        recent_journal: query_journal_lines(unit_name, 20),
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

fn query_systemctl_show(unit_name: &str, property: &str) -> String {
    match Command::new("systemctl")
        .args(["show", unit_name, "--property", property, "--value"])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

            if !stdout.is_empty() {
                stdout
            } else if !stderr.is_empty() {
                stderr
            } else {
                "unknown".to_owned()
            }
        }
        Err(error) => format!("unavailable: {error}"),
    }
}

fn query_journal_lines(unit_name: &str, line_count: usize) -> Vec<String> {
    match Command::new("journalctl")
        .args([
            "--no-pager",
            "--output",
            "short-iso",
            "--unit",
            unit_name,
            "--lines",
            &line_count.to_string(),
        ])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let content = if !stdout.trim().is_empty() {
                stdout.as_ref()
            } else {
                stderr.as_ref()
            };

            content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        }
        Err(error) => vec![format!("journal unavailable: {error}")],
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

fn internal_error(error: anyhow::Error) -> WebUiError {
    let message = error.context("webui operation failed").to_string();
    WebUiError::Message(StatusCode::INTERNAL_SERVER_ERROR, message)
}
