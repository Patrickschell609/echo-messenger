use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use super::{authenticate_device, ApiError, AppState};

#[derive(Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub bio: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileResponse {
    pub device_id: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
}

/// POST /v1/profile/update (authenticated) — set your display name and/or bio.
pub async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateProfileRequest>,
) -> Result<Json<ProfileResponse>, ApiError> {
    let device_id = authenticate_device(
        &headers,
        "POST",
        "/v1/profile/update",
        &state.db,
        &state.redis,
    )
    .await?;

    // Sanitize: strip control chars, limit length
    let display_name = body.display_name.map(|n| sanitize_text(&n, 64));
    let bio = body.bio.map(|b| sanitize_text(&b, 256));

    sqlx::query(
        "UPDATE devices SET display_name = COALESCE($1, display_name), bio = COALESCE($2, bio) WHERE id = $3",
    )
    .bind(&display_name)
    .bind(&bio)
    .bind(device_id)
    .execute(&state.db)
    .await?;

    let row: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT display_name, bio FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(&state.db)
            .await?;

    Ok(Json(ProfileResponse {
        device_id: device_id.to_string(),
        display_name: row.0,
        bio: row.1,
    }))
}

/// GET /v1/profile/{device_id} (authenticated) — fetch profile for a device.
pub async fn get_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(target_device_id): Path<uuid::Uuid>,
) -> Result<Json<ProfileResponse>, ApiError> {
    // Authenticate caller (prevents anonymous enumeration)
    let auth_path = format!("/v1/profile/{}", target_device_id);
    authenticate_device(&headers, "GET", &auth_path, &state.db, &state.redis).await?;

    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT display_name, bio FROM devices WHERE id = $1")
            .bind(target_device_id)
            .fetch_optional(&state.db)
            .await?;

    match row {
        Some((display_name, bio)) => Ok(Json(ProfileResponse {
            device_id: target_device_id.to_string(),
            display_name,
            bio,
        })),
        None => Err(ApiError::NotFound("device not found".into())),
    }
}

/// Response for short code lookup.
#[derive(Serialize)]
pub struct LookupResponse {
    pub device_id: String,
    pub display_name: Option<String>,
    pub short_code: String,
}

/// GET /v1/lookup/{code} (authenticated) — resolve a short code to a device.
pub async fn lookup_by_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Result<Json<LookupResponse>, ApiError> {
    // Authenticate caller (prevents anonymous enumeration)
    let normalized = code.replace('-', "").to_uppercase();
    let auth_path = format!("/v1/lookup/{}", code);
    authenticate_device(&headers, "GET", &auth_path, &state.db, &state.redis).await?;

    // Validate format: 8 alphanumeric chars from unambiguous alphabet
    if normalized.len() != 8 || !normalized.chars().all(|c| "ABCDEFGHJKMNPQRSTUVWXYZ23456789".contains(c)) {
        return Err(ApiError::BadRequest("invalid short code format".into()));
    }

    let row: Option<(uuid::Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, display_name, short_code FROM devices WHERE UPPER(short_code) = $1"
    )
    .bind(&normalized)
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some((device_id, display_name, short_code)) => Ok(Json(LookupResponse {
            device_id: device_id.to_string(),
            display_name,
            short_code: short_code.unwrap_or(normalized),
        })),
        None => Err(ApiError::NotFound("device not found".into())),
    }
}

/// Strip control characters and limit length.
fn sanitize_text(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}
