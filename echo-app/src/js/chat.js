// chat.js — Chat with auto-session, message animations, smart scroll, history
const Chat = {
  deviceId: null,
  displayName: null,
  messages: [],
  hasSession: false,
  establishing: false,
  loadingMore: false,
  allHistoryLoaded: false,
  _lastTypingSent: 0,
  _typingTimeout: null,
  _timerSecs: 0,

  async open(deviceId, displayName) {
    this.deviceId = deviceId;
    this.displayName = displayName || deviceId.substring(0, 8) + '...';
    this.messages = [];
    this.hasSession = false;
    this.establishing = false;
    this.loadingMore = false;
    this.allHistoryLoaded = false;
    this._timerSecs = 0;

    // Check session status
    try {
      const buddies = await API.listBuddies();
      const buddy = buddies.find(b => b.device_id === deviceId);
      if (buddy) this.hasSession = buddy.has_session;
    } catch (e) {}

    // Load timer setting
    try {
      this._timerSecs = await API.getAutoDelete(deviceId);
    } catch (e) {}

    // Load history from encrypted SQLite
    try {
      const history = await API.loadChatHistory(deviceId, 50, null);
      this.messages = history;
    } catch (e) {}

    this.render();

    // Mark messages as read when opening chat
    if (this.hasSession) {
      API.markMessagesRead(deviceId).catch(() => {});
    }

    // Auto-establish if no session
    if (!this.hasSession) {
      this.autoEstablish();
    }
  },

  timerLabel(secs) {
    if (!secs || secs === 0) return '';
    if (secs < 3600) return Math.round(secs / 60) + 'm';
    if (secs < 86400) return Math.round(secs / 3600) + 'h';
    return Math.round(secs / 86400) + 'd';
  },

  render() {
    const app = document.getElementById('app');
    const timerDisplay = this._timerSecs > 0
      ? `<span class="chat-timer" id="chatTimer" title="Auto-delete: ${this.timerLabel(this._timerSecs)}">&#9203; ${this.timerLabel(this._timerSecs)}</span>`
      : '';

    app.innerHTML = `
      <div class="chat-container">
        <div class="chat-header">
          <span class="chat-back" id="chatBack">&#9664; Back</span>
          <span class="chat-peer-name">${esc(this.displayName)}</span>
          ${timerDisplay}
          <button class="btn-timer-toggle" id="btnTimerToggle" title="Auto-delete timer">&#9203;</button>
          <div class="heartbeat ${this.hasSession ? '' : 'danger'}" id="chatHeartbeat"></div>
        </div>

        <div class="timer-menu" id="timerMenu" style="display:none">
          <div class="timer-option" data-secs="0">Off</div>
          <div class="timer-option" data-secs="300">5 minutes</div>
          <div class="timer-option" data-secs="3600">1 hour</div>
          <div class="timer-option" data-secs="86400">24 hours</div>
          <div class="timer-option" data-secs="604800">7 days</div>
        </div>

        <div class="chat-messages" id="chatMessages">
          <div class="date-separator">Today</div>
          ${this.establishing ? `
            <div class="establishing-msg">Connecting...</div>
          ` : ''}
          ${this.hasSession ? `
            <div class="message-system">Connected securely</div>
          ` : ''}
        </div>

        <div class="chat-input-row">
          <button class="btn-attach" id="btnAttach" ${!this.hasSession ? 'disabled' : ''} title="Attach file">&#128206;</button>
          <input type="file" id="fileInput" accept="image/*,.pdf,.doc,.docx,.txt" style="display:none">
          <input type="text" class="input-field" id="chatInput"
            placeholder="${this.hasSession ? 'Type a message...' : 'Connecting...'}"
            ${!this.hasSession ? 'disabled' : ''}>
          <button class="btn btn-primary" id="btnSend" ${!this.hasSession ? 'disabled' : ''}>Send</button>
        </div>
      </div>

      <div class="msg-context-menu" id="msgContextMenu" style="display:none">
        <div class="msg-menu-item" id="ctxEdit">Edit</div>
        <div class="msg-menu-item msg-menu-danger" id="ctxDelete">Delete</div>
      </div>
    `;

    this.bindChat();

    // Re-render existing messages (from history or current session)
    for (const msg of this.messages) {
      this.appendMessage(msg, true);
    }

    if (this.hasSession) {
      const input = document.getElementById('chatInput');
      if (input) input.focus();
    }

    this.scrollBottom();
  },

  bindChat() {
    document.getElementById('chatBack').addEventListener('click', () => {
      App.navigate('buddylist');
    });

    document.getElementById('btnSend').addEventListener('click', () => this.doSend());

    document.getElementById('chatInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.doSend();
      } else if (this.hasSession) {
        this.sendTyping();
      }
    });

    document.getElementById('btnAttach').addEventListener('click', () => {
      document.getElementById('fileInput').click();
    });

    document.getElementById('fileInput').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) this.doSendFile(file);
      e.target.value = '';
    });

    // Timer toggle button
    document.getElementById('btnTimerToggle').addEventListener('click', (e) => {
      e.stopPropagation();
      const menu = document.getElementById('timerMenu');
      menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
    });

    // Timer option clicks
    document.querySelectorAll('.timer-option').forEach(opt => {
      opt.addEventListener('click', async () => {
        const secs = parseInt(opt.dataset.secs, 10);
        document.getElementById('timerMenu').style.display = 'none';
        try {
          await API.setAutoDelete(this.deviceId, secs);
          this._timerSecs = secs;
          this.updateTimerDisplay();
          const label = secs === 0 ? 'off' : this.timerLabel(secs);
          this.addSystemMessage('Auto-delete set to ' + label);
        } catch (e) {
          App.toastError('Failed to set timer');
        }
      });
    });

    // Close menus on click outside
    document.addEventListener('click', (e) => {
      const timerMenu = document.getElementById('timerMenu');
      if (timerMenu) timerMenu.style.display = 'none';
      const ctxMenu = document.getElementById('msgContextMenu');
      if (ctxMenu) ctxMenu.style.display = 'none';
    });

    // Context menu on sent messages
    const chatMessages = document.getElementById('chatMessages');
    chatMessages.addEventListener('contextmenu', (e) => {
      const bubble = e.target.closest('.message-sent');
      if (!bubble) return;
      e.preventDefault();
      this._ctxMsgId = bubble.dataset.msgId;
      this._ctxBubble = bubble;
      const menu = document.getElementById('msgContextMenu');
      menu.style.display = 'block';
      menu.style.left = Math.min(e.clientX, window.innerWidth - 120) + 'px';
      menu.style.top = Math.min(e.clientY, window.innerHeight - 80) + 'px';
    });

    // Context menu actions
    document.getElementById('ctxEdit').addEventListener('click', (e) => {
      e.stopPropagation();
      document.getElementById('msgContextMenu').style.display = 'none';
      if (this._ctxMsgId && this._ctxBubble) {
        this.startInlineEdit(this._ctxMsgId, this._ctxBubble);
      }
    });

    document.getElementById('ctxDelete').addEventListener('click', async (e) => {
      e.stopPropagation();
      document.getElementById('msgContextMenu').style.display = 'none';
      if (this._ctxMsgId) {
        try {
          await API.deleteMessage(this.deviceId, this._ctxMsgId);
        } catch (err) {
          App.toastError('Delete failed');
        }
      }
    });

    // Scroll-to-load-more: load older messages when scrolled to top
    chatMessages.addEventListener('scroll', () => {
      if (chatMessages.scrollTop === 0 && this.messages.length > 0 && !this.allHistoryLoaded) {
        this.loadMore();
      }
    });
  },

  updateTimerDisplay() {
    const existing = document.getElementById('chatTimer');
    if (this._timerSecs > 0) {
      if (existing) {
        existing.innerHTML = '&#9203; ' + this.timerLabel(this._timerSecs);
        existing.title = 'Auto-delete: ' + this.timerLabel(this._timerSecs);
      } else {
        const header = document.querySelector('.chat-header');
        const btn = document.getElementById('btnTimerToggle');
        if (header && btn) {
          const span = document.createElement('span');
          span.className = 'chat-timer';
          span.id = 'chatTimer';
          span.title = 'Auto-delete: ' + this.timerLabel(this._timerSecs);
          span.innerHTML = '&#9203; ' + this.timerLabel(this._timerSecs);
          header.insertBefore(span, btn);
        }
      }
    } else if (existing) {
      existing.remove();
    }
  },

  startInlineEdit(msgId, bubble) {
    // Find the message text (skip media)
    const msg = this.messages.find(m => m.id === msgId);
    if (!msg || msg.media_url) return;

    const origText = msg.text;
    bubble.innerHTML = `
      <input type="text" class="msg-edit-input" id="editInput" value="${esc(origText)}">
      <button class="msg-edit-save" id="editSave">Save</button>
    `;

    const input = document.getElementById('editInput');
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);

    const doSave = async () => {
      const newText = input.value.trim();
      if (!newText || newText === origText) {
        // Cancel: restore original
        this.restoreBubble(bubble, msg);
        return;
      }
      try {
        await API.editMessage(this.deviceId, msgId, newText);
      } catch (err) {
        App.toastError('Edit failed');
        this.restoreBubble(bubble, msg);
      }
    };

    document.getElementById('editSave').addEventListener('click', doSave);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') doSave();
      if (e.key === 'Escape') this.restoreBubble(bubble, msg);
    });
  },

  restoreBubble(bubble, msg) {
    const time = new Date(msg.timestamp * 1000).toLocaleTimeString([], {
      hour: 'numeric', minute: '2-digit'
    });
    const editedLabel = msg.edited ? ' <span class="msg-edited">(edited)</span>' : '';
    bubble.innerHTML = `${esc(msg.text)}${editedLabel}<div class="message-time">${esc(time)} ${this.statusIcon(msg.status || 0)}</div>`;
  },

  async loadMore() {
    if (this.loadingMore || !this.messages.length || this.allHistoryLoaded) return;
    this.loadingMore = true;

    const oldest = this.messages[0];
    try {
      const older = await API.loadChatHistory(this.deviceId, 50, oldest.timestamp);
      if (older.length === 0) {
        this.allHistoryLoaded = true;
        this.loadingMore = false;
        return;
      }

      // Prepend to messages array
      this.messages = [...older, ...this.messages];

      // Prepend to DOM, maintaining scroll position
      const container = document.getElementById('chatMessages');
      const prevHeight = container.scrollHeight;

      // Insert older messages at the top (after date separator)
      const firstChild = container.querySelector('.message-bubble, .message-system, .establishing-msg');
      for (const msg of older) {
        const el = this.createMessageElement(msg);
        el.style.animation = 'none';
        if (firstChild) {
          container.insertBefore(el, firstChild);
        } else {
          container.appendChild(el);
        }
      }

      // Restore scroll position so view doesn't jump
      container.scrollTop = container.scrollHeight - prevHeight;
    } catch (e) {}

    this.loadingMore = false;
  },

  async autoEstablish() {
    this.establishing = true;
    this.updateBadge();

    // Show establishing message
    const container = document.getElementById('chatMessages');
    if (container && !container.querySelector('.establishing-msg')) {
      const div = document.createElement('div');
      div.className = 'establishing-msg';
      div.textContent = 'Connecting...';
      container.appendChild(div);
    }

    try {
      const result = await API.establishSession(this.deviceId);
      // Guard: event listener may have already handled this
      if (!this.hasSession) {
        this.hasSession = true;
        this.establishing = false;
        this.onSessionReady(result);
      }
    } catch (e) {
      this.establishing = false;
      const msg = typeof e === 'string' ? e : e.message || 'Session failed';
      console.error('[ECHO] establish_session failed:', msg, e);

      // Remove the pulsing "establishing" message
      const est = document.querySelector('.establishing-msg');
      if (est) est.remove();

      // Show specific error with retry button
      let userMsg = 'Could not connect';
      if (msg.includes('Transparency')) userMsg = 'Key verification failed';
      else if (msg.includes('Not signed in') || msg.includes('Not connected')) userMsg = 'Not signed in';
      else if (msg.includes('fetch') || msg.includes('network') || msg.includes('timeout')) userMsg = 'Network error';

      const container = document.getElementById('chatMessages');
      if (container) {
        const div = document.createElement('div');
        div.className = 'message-system';
        div.innerHTML = `${esc(userMsg)}. <span class="retry-link" id="retrySession">Try again</span>`;
        container.appendChild(div);

        document.getElementById('retrySession').addEventListener('click', () => {
          div.remove();
          this.autoEstablish();
        });
      }

      this.updateBadge();
    }
  },

  onSessionReady(result) {
    // Remove establishing message
    const est = document.querySelector('.establishing-msg');
    if (est) est.remove();

    // Update badge
    this.updateBadge();

    // Add session message
    this.addSystemMessage('Connected securely');

    // Enable input
    const input = document.getElementById('chatInput');
    const sendBtn = document.getElementById('btnSend');
    if (input) {
      input.disabled = false;
      input.placeholder = 'Type a message...';
      input.focus();
    }
    if (sendBtn) sendBtn.disabled = false;
  },

  onSessionEstablished(deviceId) {
    if (this.deviceId === deviceId && !this.hasSession) {
      this.hasSession = true;
      this.establishing = false;
      this.onSessionReady({ verified: true });
    }
  },

  updateBadge() {
    const hb = document.getElementById('chatHeartbeat');
    if (!hb) return;
    if (this.hasSession) {
      hb.className = 'heartbeat';
    } else {
      hb.className = 'heartbeat danger';
    }
  },

  async doSend() {
    const input = document.getElementById('chatInput');
    const sendBtn = document.getElementById('btnSend');
    const text = input.value.trim();
    if (!text || !this.hasSession) return;

    // Disable while sending
    input.disabled = true;
    sendBtn.disabled = true;

    try {
      const msg = await API.sendMessage(this.deviceId, text);
      input.value = '';
      this.messages.push(msg);
      this.appendMessage(msg);
      this.scrollBottom();
    } catch (e) {
      // Keep text in input so user can retry
      const errMsg = typeof e === 'string' ? e : e.message || 'Send failed';
      App.toastError('Could not send. Try again.');
    } finally {
      input.disabled = false;
      sendBtn.disabled = false;
      input.focus();
    }
  },

  async doSendFile(file) {
    if (file.size > 5 * 1024 * 1024) {
      App.toastError('File too large (max 5MB)');
      return;
    }

    const reader = new FileReader();
    reader.onload = async () => {
      const base64 = reader.result.split(',')[1];
      try {
        const msg = await API.sendFile(
          this.deviceId, base64, file.name,
          file.type || 'application/octet-stream'
        );
        this.messages.push(msg);
        this.appendMessage(msg);
        this.scrollBottom();
      } catch (e) {
        App.toastError('Send file failed');
      }
    };
    reader.readAsDataURL(file);
  },

  onNewMessage(msg) {
    if (this.deviceId && msg.from_device === this.deviceId) {
      this.messages.push(msg);
      this.appendMessage(msg);
      this.smartScroll();

      // Send read receipt immediately since we're viewing this chat
      if (!msg.sent_by_me) {
        API.markMessagesRead(this.deviceId).catch(() => {});
      }
    }
  },

  // Update status indicators for sent messages (called by delivered/read events)
  onStatusUpdate(upToTimestamp, newStatus) {
    const container = document.getElementById('chatMessages');
    if (!container) return;

    const bubbles = container.querySelectorAll('.message-sent');
    for (const bubble of bubbles) {
      const ts = parseInt(bubble.dataset.timestamp, 10);
      if (ts && ts <= upToTimestamp) {
        const statusEl = bubble.querySelector('.msg-status');
        if (statusEl) {
          if (newStatus >= 2) {
            statusEl.className = 'msg-status msg-read';
            statusEl.innerHTML = '&#10003;&#10003;';
          } else if (newStatus >= 1) {
            statusEl.className = 'msg-status msg-delivered';
            statusEl.innerHTML = '&#10003;&#10003;';
          }
        }
      }
    }

    // Update in-memory message statuses too
    for (const msg of this.messages) {
      if (msg.sent_by_me && msg.timestamp <= upToTimestamp && (msg.status || 0) < newStatus) {
        msg.status = newStatus;
      }
    }
  },

  // Called when an outbox message is successfully sent (queued -> sent)
  onMessageSent(msgId) {
    const container = document.getElementById('chatMessages');
    if (!container) return;

    // Find the bubble by msg_id and update status (CSS.escape prevents selector injection)
    const bubble = container.querySelector(`.message-sent[data-msg-id="${CSS.escape(msgId)}"]`);
    if (bubble) {
      const statusEl = bubble.querySelector('.msg-status');
      if (statusEl) {
        statusEl.className = 'msg-status msg-sent';
        statusEl.innerHTML = '&#10003;';
      }
    }

    // Update in-memory
    for (const msg of this.messages) {
      if (msg.id === msgId) {
        msg.status = 0;
        break;
      }
    }
  },

  // ─── Control Message Event Handlers ───

  onTimerChanged(durationSecs) {
    this._timerSecs = durationSecs;
    this.updateTimerDisplay();
    const label = durationSecs === 0 ? 'off' : this.timerLabel(durationSecs);
    this.addSystemMessage('Auto-delete set to ' + label);
  },

  onMessageEdited(msgId, newText) {
    // Update in-memory
    for (const msg of this.messages) {
      if (msg.id === msgId) {
        msg.text = newText;
        msg.edited = true;
        break;
      }
    }

    // Update DOM (CSS.escape prevents selector injection)
    const container = document.getElementById('chatMessages');
    if (!container) return;
    const bubble = container.querySelector(`[data-msg-id="${CSS.escape(msgId)}"]`);
    if (bubble) {
      const time = bubble.querySelector('.message-time');
      const timeHtml = time ? time.outerHTML : '';
      const editedLabel = '<span class="msg-edited">(edited)</span>';
      if (bubble.classList.contains('message-sent')) {
        bubble.innerHTML = `${esc(newText)} ${editedLabel}${timeHtml}`;
      } else {
        bubble.innerHTML = `${esc(newText)} ${editedLabel}${timeHtml}`;
      }
    }
  },

  onMessageDeleted(msgId) {
    // Remove from in-memory
    this.messages = this.messages.filter(m => m.id !== msgId);

    // Remove from DOM (CSS.escape prevents selector injection)
    const container = document.getElementById('chatMessages');
    if (!container) return;
    const bubble = container.querySelector(`[data-msg-id="${CSS.escape(msgId)}"]`);
    if (bubble) bubble.remove();
  },

  onMessagesExpired(count) {
    // Reload the chat to reflect deletions
    if (this.deviceId && count > 0) {
      this.reloadHistory();
    }
  },

  async reloadHistory() {
    try {
      const history = await API.loadChatHistory(this.deviceId, 50, null);
      this.messages = history;
      // Re-render messages area
      const container = document.getElementById('chatMessages');
      if (!container) return;
      // Remove all message bubbles but keep system messages
      container.querySelectorAll('.message-bubble').forEach(el => el.remove());
      for (const msg of this.messages) {
        this.appendMessage(msg, true);
      }
    } catch (e) {}
  },

  statusIcon(status) {
    // 0=sent (single check), 1=delivered (double check), 2=read (double check blue), 3=queued (clock)
    if (status >= 3) return '<span class="msg-status msg-queued">&#9201;</span>';
    if (status >= 2) return '<span class="msg-status msg-read">&#10003;&#10003;</span>';
    if (status >= 1) return '<span class="msg-status msg-delivered">&#10003;&#10003;</span>';
    return '<span class="msg-status msg-sent">&#10003;</span>';
  },

  createMessageElement(msg) {
    const time = new Date(msg.timestamp * 1000).toLocaleTimeString([], {
      hour: 'numeric', minute: '2-digit'
    });

    const div = document.createElement('div');
    div.dataset.timestamp = msg.timestamp;
    if (msg.id) div.dataset.msgId = msg.id;

    let content = '';
    if (msg.media_url && msg.media_mime && msg.media_mime.startsWith('image/')) {
      content = `<img class="message-image" src="${msg.media_url}" alt="${esc(msg.media_filename || 'Image')}">`;
    } else if (msg.media_filename) {
      content = `<span class="message-file">&#128206; ${esc(msg.media_filename)}</span>`;
    } else {
      content = esc(msg.text);
    }

    const editedLabel = msg.edited ? ' <span class="msg-edited">(edited)</span>' : '';

    if (msg.sent_by_me) {
      div.className = 'message-bubble message-sent';
      div.innerHTML = `${content}${editedLabel}<div class="message-time">${esc(time)} ${this.statusIcon(msg.status || 0)}</div>`;
    } else {
      div.className = 'message-bubble message-recv';
      div.innerHTML = `${content}${editedLabel}<div class="message-time">${esc(time)}</div>`;
    }
    return div;
  },

  appendMessage(msg, noAnimate) {
    const container = document.getElementById('chatMessages');
    if (!container) return;

    const div = this.createMessageElement(msg);
    if (noAnimate) {
      div.style.animation = 'none';
    }

    container.appendChild(div);
  },

  addSystemMessage(text) {
    const container = document.getElementById('chatMessages');
    if (!container) return;

    const div = document.createElement('div');
    div.className = 'message-system';
    div.textContent = text;
    container.appendChild(div);
    this.smartScroll();
  },

  // ─── Typing Indicators ───
  sendTyping() {
    // Debounce: max once per 3 seconds
    const now = Date.now();
    if (now - this._lastTypingSent < 3000) return;
    this._lastTypingSent = now;
    API.sendTypingIndicator(this.deviceId).catch(() => {});
  },

  onTyping() {
    this.showTypingIndicator();
    // Auto-hide after 4 seconds
    if (this._typingTimeout) clearTimeout(this._typingTimeout);
    this._typingTimeout = setTimeout(() => this.hideTypingIndicator(), 4000);
  },

  showTypingIndicator() {
    const container = document.getElementById('chatMessages');
    if (!container) return;
    let el = container.querySelector('.typing-indicator');
    if (!el) {
      el = document.createElement('div');
      el.className = 'typing-indicator';
      el.innerHTML = '<span></span><span></span><span></span>';
      container.appendChild(el);
      this.smartScroll();
    }
  },

  hideTypingIndicator() {
    const el = document.querySelector('.typing-indicator');
    if (el) el.remove();
  },

  // Smart scroll: only auto-scroll if user is near the bottom
  smartScroll() {
    const container = document.getElementById('chatMessages');
    if (!container) return;
    const threshold = 80;
    const isNearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < threshold;
    if (isNearBottom) {
      container.scrollTop = container.scrollHeight;
    }
  },

  scrollBottom() {
    const container = document.getElementById('chatMessages');
    if (container) {
      container.scrollTop = container.scrollHeight;
    }
  },
};
