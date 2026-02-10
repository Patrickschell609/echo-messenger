// events.js — Tauri event listeners with unread routing, notifications, sound
const { listen } = window.__TAURI__.event;

const Events = {
  listeners: [],

  async init() {
    this.cleanup();

    // New message — route to chat or unread counter + notify
    this.listeners.push(
      await listen('new_message', (event) => {
        const msg = event.payload;

        // Don't count our own sent messages
        if (msg.sent_by_me) return;

        const inChat = App.currentPage === 'chat' &&
                       App.currentChatDevice === msg.from_device;

        if (inChat && typeof Chat !== 'undefined') {
          Chat.onNewMessage(msg);
        } else {
          // Not viewing this chat — increment unread + notify
          App.addUnread(msg.from_device);
          App.playNotificationSound();
          App.showNotification(msg.from_device);
        }
      })
    );

    // Session established — refresh buddy list, notify chat
    this.listeners.push(
      await listen('session_established', (event) => {
        const deviceId = event.payload;

        if (typeof BuddyList !== 'undefined') {
          BuddyList.onSessionEstablished(deviceId);
        }
        if (typeof Chat !== 'undefined' && Chat.deviceId === deviceId) {
          Chat.onSessionEstablished(deviceId);
        }

        App.toastSuccess('Connected securely');
      })
    );

    // Message processing errors — flash heartbeat red
    this.listeners.push(
      await listen('message_error', (event) => {
        const detail = event.payload || 'Unknown error';
        App.toastError('Message failed: could not decrypt');
        App.setHeartbeatDanger();
        console.warn('[echo] message_error:', detail);
      })
    );

    // Typing indicators
    this.listeners.push(
      await listen('typing', (event) => {
        const senderDeviceId = event.payload;
        if (typeof Chat !== 'undefined' && Chat.deviceId === senderDeviceId) {
          Chat.onTyping(senderDeviceId);
        }
      })
    );

    // Delivery receipts — update sent message status
    this.listeners.push(
      await listen('delivered', (event) => {
        const { peer_id, up_to_timestamp } = event.payload;
        if (typeof Chat !== 'undefined' && Chat.deviceId === peer_id) {
          Chat.onStatusUpdate(up_to_timestamp, 1);
        }
      })
    );

    // Read receipts — update sent message status
    this.listeners.push(
      await listen('read', (event) => {
        const { peer_id, up_to_timestamp } = event.payload;
        if (typeof Chat !== 'undefined' && Chat.deviceId === peer_id) {
          Chat.onStatusUpdate(up_to_timestamp, 2);
        }
      })
    );

    // Outbox message sent — update queued → sent status
    this.listeners.push(
      await listen('message_sent', (event) => {
        const { msg_id, peer_id } = event.payload;
        if (typeof Chat !== 'undefined' && Chat.deviceId === peer_id) {
          Chat.onMessageSent(msg_id);
        }
      })
    );

    // Group messages
    this.listeners.push(
      await listen('group_message', (event) => {
        const msg = event.payload;
        if (msg.sent_by_me) return;

        const inGroupChat = App.currentPage === 'groupchat' &&
                            App.currentGroupId === msg.group_id;

        if (inGroupChat && typeof GroupChat !== 'undefined') {
          GroupChat.onNewGroupMessage(msg);
        } else {
          App.addUnread('grp-' + msg.group_id);
          App.playNotificationSound();
        }
      })
    );

    // Timer changed — update chat header indicator
    this.listeners.push(
      await listen('timer_changed', (event) => {
        const { peer_id, duration_secs } = event.payload;
        if (typeof Chat !== 'undefined' && Chat.deviceId === peer_id) {
          Chat.onTimerChanged(duration_secs);
        }
      })
    );

    // Message edited by peer
    this.listeners.push(
      await listen('message_edited', (event) => {
        const { peer_id, msg_id, new_text } = event.payload;
        if (typeof Chat !== 'undefined' && Chat.deviceId === peer_id) {
          Chat.onMessageEdited(msg_id, new_text);
        }
      })
    );

    // Message deleted by peer
    this.listeners.push(
      await listen('message_deleted', (event) => {
        const { peer_id, msg_id } = event.payload;
        if (typeof Chat !== 'undefined' && Chat.deviceId === peer_id) {
          Chat.onMessageDeleted(msg_id);
        }
      })
    );

    // Expired messages purged
    this.listeners.push(
      await listen('messages_expired', (event) => {
        const count = event.payload;
        if (typeof Chat !== 'undefined') {
          Chat.onMessagesExpired(count);
        }
      })
    );

    // Connection state changes (live/polling)
    this.listeners.push(
      await listen('connection_state', (event) => {
        const mode = event.payload;
        if (typeof BuddyList !== 'undefined') {
          BuddyList.updateConnectionStatus(mode);
        }
      })
    );

    // Signed out
    this.listeners.push(
      await listen('signed_out', () => {
        App.navigate('signon');
      })
    );
  },

  cleanup() {
    this.listeners.forEach(unlisten => unlisten());
    this.listeners = [];
  }
};
