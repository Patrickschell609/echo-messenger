// api.js — Tauri command wrappers
const { invoke } = window.__TAURI__.core;

const API = {
  vaultExists() {
    return invoke('vault_exists');
  },

  createAccount(serverUrl, passphrase, inviteCode) {
    return invoke('create_account', { serverUrl, passphrase, inviteCode });
  },

  signOn(serverUrl, passphrase) {
    return invoke('sign_on', { serverUrl, passphrase });
  },

  signOff() {
    return invoke('sign_off');
  },

  establishSession(deviceId) {
    return invoke('establish_session', { deviceId });
  },

  sendMessage(deviceId, message) {
    return invoke('send_message', { deviceId, message });
  },

  getDeviceId() {
    return invoke('get_device_id');
  },

  addBuddy(deviceId, displayName) {
    return invoke('add_buddy', { deviceId, displayName });
  },

  removeBuddy(deviceId) {
    return invoke('remove_buddy', { deviceId });
  },

  listBuddies() {
    return invoke('list_buddies');
  },

  generateInvites(count) {
    return invoke('generate_invites', { count });
  },

  loadChatHistory(deviceId, limit, beforeTimestamp) {
    return invoke('load_chat_history', { deviceId, limit, beforeTimestamp: beforeTimestamp || null });
  },

  sendTypingIndicator(deviceId) {
    return invoke('send_typing_indicator', { deviceId });
  },

  markMessagesRead(deviceId) {
    return invoke('mark_messages_read', { deviceId });
  },

  updateProfile(displayName) {
    return invoke('update_profile', { displayName });
  },

  fetchProfile(deviceId) {
    return invoke('fetch_profile', { deviceId });
  },

  sendFile(deviceId, fileData, filename, mimeType) {
    return invoke('send_file', { deviceId, fileData, filename, mimeType });
  },

  // ─── Auto-Delete & Edit/Delete ───
  setAutoDelete(deviceId, durationSecs) {
    return invoke('set_auto_delete', { deviceId, durationSecs });
  },

  getAutoDelete(deviceId) {
    return invoke('get_auto_delete', { deviceId });
  },

  editMessage(deviceId, msgId, newText) {
    return invoke('edit_message', { deviceId, msgId, newText });
  },

  deleteMessage(deviceId, msgId) {
    return invoke('delete_message_cmd', { deviceId, msgId });
  },

  // ─── Groups ───
  createGroup(name, memberIds) {
    return invoke('create_group', { name, memberIds });
  },

  listGroups() {
    return invoke('list_groups');
  },

  sendGroupMessage(groupId, message) {
    return invoke('send_group_message', { groupId, message });
  },

  loadGroupHistory(groupId, limit, beforeTimestamp) {
    return invoke('load_group_history', { groupId, limit, beforeTimestamp: beforeTimestamp || null });
  },

  leaveGroup(groupId) {
    return invoke('leave_group', { groupId });
  },
};
