use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{authenticate_device, ApiError, AppState};

// ─── Create Group ───

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub member_device_ids: Vec<Uuid>,
}

#[derive(Serialize, Clone)]
pub struct GroupResponse {
    pub group_id: String,
    pub name: String,
    pub member_count: i64,
}

pub async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>, ApiError> {
    let device_id = authenticate_device(&headers, "POST", "/v1/groups", &state.db).await?;

    let name = req.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(ApiError::BadRequest("group name must be 1-128 chars".into()));
    }
    if req.member_device_ids.len() > 256 {
        return Err(ApiError::BadRequest("max 256 members".into()));
    }

    let group_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO groups (id, name, creator_device_id, created_at) VALUES ($1, $2, $3, NOW())",
    )
    .bind(group_id)
    .bind(name)
    .bind(device_id)
    .execute(&state.db)
    .await?;

    // Add creator as admin (role=1)
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, role, joined_epoch) VALUES ($1, $2, 1, 0)",
    )
    .bind(group_id)
    .bind(device_id)
    .execute(&state.db)
    .await?;

    // Add other members
    let mut added = 1i64;
    for &mid in &req.member_device_ids {
        if mid == device_id {
            continue;
        }
        let exists: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM devices WHERE id = $1")
                .bind(mid)
                .fetch_optional(&state.db)
                .await?;
        if exists.is_some() {
            sqlx::query(
                "INSERT INTO group_members (group_id, device_id, role, joined_epoch) VALUES ($1, $2, 0, 0) ON CONFLICT DO NOTHING",
            )
            .bind(group_id)
            .bind(mid)
            .execute(&state.db)
            .await?;
            added += 1;
        }
    }

    Ok(Json(GroupResponse {
        group_id: group_id.to_string(),
        name: name.to_string(),
        member_count: added,
    }))
}

// ─── List Groups ───

pub async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<GroupResponse>>, ApiError> {
    let device_id = authenticate_device(&headers, "GET", "/v1/groups", &state.db).await?;

    let rows: Vec<(Uuid, Option<String>, i64)> = sqlx::query_as(
        r#"
        SELECT g.id, g.name, (SELECT COUNT(*) FROM group_members WHERE group_id = g.id)
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.device_id = $1
        ORDER BY g.created_at DESC
        "#,
    )
    .bind(device_id)
    .fetch_all(&state.db)
    .await?;

    let groups = rows
        .into_iter()
        .map(|(id, name, count)| GroupResponse {
            group_id: id.to_string(),
            name: name.unwrap_or_default(),
            member_count: count,
        })
        .collect();

    Ok(Json(groups))
}

// ─── Send Group Message ───

#[derive(Deserialize)]
pub struct SendGroupMessageRequest {
    pub payload: String, // hex-encoded GroupMessage
}

#[derive(Serialize)]
pub struct SendGroupMessageResponse {
    pub id: i64,
}

pub async fn send_group_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Json(req): Json<SendGroupMessageRequest>,
) -> Result<Json<SendGroupMessageResponse>, ApiError> {
    let path = format!("/v1/groups/{}/send", group_id);
    let device_id = authenticate_device(&headers, "POST", &path, &state.db).await?;

    // Verify sender is a member
    let member: Option<(i16,)> = sqlx::query_as(
        "SELECT role FROM group_members WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;

    if member.is_none() {
        return Err(ApiError::Unauthorized);
    }

    let payload = hex::decode(&req.payload)
        .map_err(|_| ApiError::BadRequest("invalid payload hex".into()))?;

    if payload.len() > 65536 {
        return Err(ApiError::PayloadTooLarge("payload too large".into()));
    }

    let (msg_id,): (i64,) = sqlx::query_as(
        "INSERT INTO group_messages (group_id, sender_device_id, payload) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(group_id)
    .bind(device_id)
    .bind(&payload)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(SendGroupMessageResponse { id: msg_id }))
}

// ─── Receive Group Messages ───

#[derive(Serialize)]
pub struct GroupQueuedMessage {
    pub id: i64,
    pub sender_device_id: String,
    pub payload: String,
    pub queued_at: i64,
}

pub async fn receive_group_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<GroupQueuedMessage>>, ApiError> {
    let path = format!("/v1/groups/{}/messages", group_id);
    let device_id = authenticate_device(&headers, "GET", &path, &state.db).await?;

    // Verify membership
    let member: Option<(i16,)> = sqlx::query_as(
        "SELECT role FROM group_members WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;

    if member.is_none() {
        return Err(ApiError::Unauthorized);
    }

    // Get cursor
    let cursor: i64 = sqlx::query_as::<_, (i64,)>(
        "SELECT last_read_id FROM group_read_cursors WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?
    .map(|(id,)| id)
    .unwrap_or(0);

    let rows: Vec<(i64, Uuid, Vec<u8>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
        SELECT id, sender_device_id, payload, queued_at
        FROM group_messages
        WHERE group_id = $1 AND id > $2
        ORDER BY id ASC
        LIMIT 100
        "#,
    )
    .bind(group_id)
    .bind(cursor)
    .fetch_all(&state.db)
    .await?;

    // Update cursor
    if let Some(last) = rows.last() {
        sqlx::query(
            "INSERT INTO group_read_cursors (group_id, device_id, last_read_id) VALUES ($1, $2, $3)
             ON CONFLICT (group_id, device_id) DO UPDATE SET last_read_id = $3",
        )
        .bind(group_id)
        .bind(device_id)
        .bind(last.0)
        .execute(&state.db)
        .await?;
    }

    let messages = rows
        .into_iter()
        .map(|(id, sender, payload, queued_at)| GroupQueuedMessage {
            id,
            sender_device_id: sender.to_string(),
            payload: hex::encode(&payload),
            queued_at: queued_at.timestamp(),
        })
        .collect();

    Ok(Json(messages))
}

// ─── Add Member ───

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub device_id: Uuid,
}

pub async fn add_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let path = format!("/v1/groups/{}/members", group_id);
    let device_id = authenticate_device(&headers, "POST", &path, &state.db).await?;

    // Verify caller is admin
    let role: Option<(i16,)> = sqlx::query_as(
        "SELECT role FROM group_members WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;

    match role {
        Some((1,)) => {}
        _ => return Err(ApiError::Unauthorized),
    }

    let exists: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM devices WHERE id = $1")
            .bind(req.device_id)
            .fetch_optional(&state.db)
            .await?;

    if exists.is_none() {
        return Err(ApiError::NotFound("device not found".into()));
    }

    let (epoch,): (i32,) = sqlx::query_as("SELECT epoch FROM groups WHERE id = $1")
        .bind(group_id)
        .fetch_one(&state.db)
        .await?;

    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, role, joined_epoch) VALUES ($1, $2, 0, $3) ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(req.device_id)
    .bind(epoch)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ─── Leave Group ───

pub async fn leave_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let path = format!("/v1/groups/{}/leave", group_id);
    let device_id = authenticate_device(&headers, "POST", &path, &state.db).await?;

    sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND device_id = $2")
        .bind(group_id)
        .bind(device_id)
        .execute(&state.db)
        .await?;

    sqlx::query("DELETE FROM group_read_cursors WHERE group_id = $1 AND device_id = $2")
        .bind(group_id)
        .bind(device_id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ─── Get Group Members ───

#[derive(Serialize)]
pub struct GroupMemberInfo {
    pub device_id: String,
    pub role: i16,
}

pub async fn get_group_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<GroupMemberInfo>>, ApiError> {
    let path = format!("/v1/groups/{}/members", group_id);
    let device_id = authenticate_device(&headers, "GET", &path, &state.db).await?;

    let member: Option<(i16,)> = sqlx::query_as(
        "SELECT role FROM group_members WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;

    if member.is_none() {
        return Err(ApiError::Unauthorized);
    }

    let rows: Vec<(Uuid, i16)> = sqlx::query_as(
        "SELECT device_id, role FROM group_members WHERE group_id = $1 ORDER BY role DESC, device_id",
    )
    .bind(group_id)
    .fetch_all(&state.db)
    .await?;

    let members = rows
        .into_iter()
        .map(|(id, role)| GroupMemberInfo {
            device_id: id.to_string(),
            role,
        })
        .collect();

    Ok(Json(members))
}
