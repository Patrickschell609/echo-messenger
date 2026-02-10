/// Tauri event names used for frontend communication.
pub const EVENT_NEW_MESSAGE: &str = "new_message";
pub const EVENT_SESSION_ESTABLISHED: &str = "session_established";
pub const EVENT_SIGNED_IN: &str = "signed_in";
pub const EVENT_SIGNED_OUT: &str = "signed_out";
pub const EVENT_ERROR: &str = "echo_error";
/// Emitted when a queued message fails processing (AV-12: no silent drops).
pub const EVENT_MESSAGE_ERROR: &str = "message_error";
/// Emitted when connection mode changes: "live" (WebSocket) or "polling" (fallback).
pub const EVENT_CONNECTION_STATE: &str = "connection_state";
/// Emitted when a peer is typing (device_id string payload).
pub const EVENT_TYPING: &str = "typing";
/// Emitted when sent messages are confirmed delivered (payload: { peer_id, up_to_timestamp }).
pub const EVENT_DELIVERED: &str = "delivered";
/// Emitted when sent messages are confirmed read (payload: { peer_id, up_to_timestamp }).
pub const EVENT_READ: &str = "read";
/// Emitted when a queued outbox message is successfully sent (payload: { msg_id, peer_id }).
pub const EVENT_MESSAGE_SENT: &str = "message_sent";
/// Emitted when a new group message arrives (payload: GroupChatMessage).
pub const EVENT_GROUP_MESSAGE: &str = "group_message";
/// Emitted when group list changes.
pub const EVENT_GROUPS_UPDATED: &str = "groups_updated";
/// Emitted when auto-delete timer changes (payload: { peer_id, duration_secs }).
pub const EVENT_TIMER_CHANGED: &str = "timer_changed";
/// Emitted when a message is edited by the peer (payload: { peer_id, msg_id, new_text }).
pub const EVENT_MESSAGE_EDITED: &str = "message_edited";
/// Emitted when a message is deleted by the peer (payload: { peer_id, msg_id }).
pub const EVENT_MESSAGE_DELETED: &str = "message_deleted";
/// Emitted when expired messages are purged (payload: count).
pub const EVENT_MESSAGES_EXPIRED: &str = "messages_expired";
