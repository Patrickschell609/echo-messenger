// app.js — Router, global state, toast system, unread tracking, notifications
const App = {
  currentPage: null,
  currentChatDevice: null,
  currentGroupId: null,
  deviceId: null,
  unread: {},
  buddyNames: {},
  muted: false,
  _lastSoundTime: 0,
  _audioCtx: null,

  async init() {
    this.ensureToastContainer();
    this.muted = localStorage.getItem('echo-muted') === 'true';
    this.requestNotificationPermission();
    try {
      await Events.init();
    } catch (e) {
      console.error('[echo] Events.init failed:', e);
    }
    this.navigate('signon');
  },

  navigate(page, context) {
    this.currentPage = page;

    switch (page) {
      case 'signon':
        this.currentChatDevice = null;
        this.currentGroupId = null;
        SignOn.render();
        break;
      case 'buddylist':
        this.currentChatDevice = null;
        this.currentGroupId = null;
        BuddyList.render();
        break;
      case 'chat':
        if (context) {
          this.currentChatDevice = context.deviceId;
          delete this.unread[context.deviceId];
          Chat.open(context.deviceId, context.displayName);
        }
        break;
      case 'groupchat':
        this.currentChatDevice = null;
        if (context) {
          this.currentGroupId = context.groupId;
          delete this.unread['grp-' + context.groupId];
          GroupChat.open(context.groupId, context.groupName);
        }
        break;
      default:
        SignOn.render();
    }
  },

  // ─── Unread Tracking ───
  addUnread(deviceId) {
    this.unread[deviceId] = (this.unread[deviceId] || 0) + 1;
    if (this.currentPage === 'buddylist') {
      BuddyList.renderList();
    }
  },

  getUnread(deviceId) {
    return this.unread[deviceId] || 0;
  },

  clearUnread(deviceId) {
    delete this.unread[deviceId];
  },

  // ─── Buddy Name Cache (for notifications) ───
  cacheBuddyName(deviceId, name) {
    this.buddyNames[deviceId] = name;
  },

  getBuddyName(deviceId) {
    return this.buddyNames[deviceId] || deviceId.substring(0, 8) + '...';
  },

  // ─── Notifications ───
  requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  },

  showNotification(senderDeviceId) {
    if (this.muted) return;
    const name = this.getBuddyName(senderDeviceId);
    // Never include message content — sealed sender principle
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification('Echo', { body: 'New message from ' + name });
    }
  },

  // ─── Notification Sound (Web Audio API, synthesized) ───
  playNotificationSound() {
    if (this.muted) return;

    // Rate limit: max 1 beep per second
    const now = Date.now();
    if (now - this._lastSoundTime < 1000) return;
    this._lastSoundTime = now;

    try {
      const ctx = this._audioCtx || new (window.AudioContext || window.webkitAudioContext)();
      this._audioCtx = ctx;

      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.frequency.value = 440;
      osc.type = 'sine';
      gain.gain.setValueAtTime(0.3, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.1);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.1);
    } catch (e) {
      // Audio not available — silent fail
    }
  },

  // ─── Heartbeat Security Indicator ───
  setHeartbeatDanger() {
    const hb = document.getElementById('heartbeat') || document.getElementById('chatHeartbeat');
    if (hb) hb.className = 'heartbeat danger';
  },

  setHeartbeatSafe() {
    const hb = document.getElementById('heartbeat') || document.getElementById('chatHeartbeat');
    if (hb) hb.className = 'heartbeat';
  },

  // ─── Mute Toggle ───
  toggleMute() {
    this.muted = !this.muted;
    localStorage.setItem('echo-muted', this.muted);
    return this.muted;
  },

  // ─── Toast System ───
  ensureToastContainer() {
    if (!document.getElementById('toastContainer')) {
      const container = document.createElement('div');
      container.className = 'toast-container';
      container.id = 'toastContainer';
      document.body.appendChild(container);
    }
  },

  toast(message, type) {
    type = type || 'info';
    this.ensureToastContainer();
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('leaving');
      setTimeout(() => toast.remove(), 200);
    }, 2500);
  },

  toastSuccess(msg) { this.toast(msg, 'success'); },
  toastError(msg) { this.toast(msg, 'error'); },
  toastInfo(msg) { this.toast(msg, 'info'); },
};

// HTML escape helper — escapes &, <, >, ", and ' for safe use in attributes
function esc(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Boot
window.addEventListener('DOMContentLoaded', () => {
  App.init();
});
