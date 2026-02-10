// groupchat.js — Group Chat UI (Sender Keys encrypted)
const GroupChat = {
  groupId: null,
  groupName: null,
  messages: [],
  loadingMore: false,
  allHistoryLoaded: false,

  async open(groupId, groupName) {
    this.groupId = groupId;
    this.groupName = groupName || 'Group';
    this.messages = [];
    this.loadingMore = false;
    this.allHistoryLoaded = false;

    // Load history
    try {
      const history = await API.loadGroupHistory(groupId, 50, null);
      this.messages = history;
    } catch (e) {}

    this.render();
  },

  render() {
    const app = document.getElementById('app');

    app.innerHTML = `
      <div class="chat-container">
        <div class="chat-header">
          <span class="chat-back" id="chatBack">&#9664; Back</span>
          <span class="chat-peer-name">${esc(this.groupName)}</span>
          <div class="heartbeat" id="chatHeartbeat"></div>
        </div>

        <div class="chat-messages" id="chatMessages">
          <div class="date-separator">Today</div>
        </div>

        <div class="chat-input-row">
          <input type="text" class="input-field" id="chatInput"
            placeholder="Message ${esc(this.groupName)}...">
          <button class="btn btn-primary" id="btnSend">Send</button>
        </div>
      </div>
    `;

    this.bindChat();

    for (const msg of this.messages) {
      this.appendMessage(msg, true);
    }

    const input = document.getElementById('chatInput');
    if (input) input.focus();

    this.scrollBottom();
  },

  bindChat() {
    document.getElementById('chatBack').addEventListener('click', () => {
      App.navigate('buddylist');
    });

    document.getElementById('btnSend').addEventListener('click', () => this.doSend());

    document.getElementById('chatInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.doSend();
    });

    // Scroll-to-load-more
    const chatMessages = document.getElementById('chatMessages');
    chatMessages.addEventListener('scroll', () => {
      if (chatMessages.scrollTop === 0 && this.messages.length > 0 && !this.allHistoryLoaded) {
        this.loadMore();
      }
    });
  },

  async loadMore() {
    if (this.loadingMore || !this.messages.length || this.allHistoryLoaded) return;
    this.loadingMore = true;

    const oldest = this.messages[0];
    try {
      const older = await API.loadGroupHistory(this.groupId, 50, oldest.timestamp);
      if (older.length === 0) {
        this.allHistoryLoaded = true;
        this.loadingMore = false;
        return;
      }

      this.messages = [...older, ...this.messages];

      const container = document.getElementById('chatMessages');
      const prevHeight = container.scrollHeight;

      const firstChild = container.querySelector('.message-bubble, .message-system');
      for (const msg of older) {
        const el = this.createMessageElement(msg);
        el.style.animation = 'none';
        if (firstChild) {
          container.insertBefore(el, firstChild);
        } else {
          container.appendChild(el);
        }
      }

      container.scrollTop = container.scrollHeight - prevHeight;
    } catch (e) {}

    this.loadingMore = false;
  },

  async doSend() {
    const input = document.getElementById('chatInput');
    const sendBtn = document.getElementById('btnSend');
    const text = input.value.trim();
    if (!text) return;

    input.disabled = true;
    sendBtn.disabled = true;

    try {
      const msg = await API.sendGroupMessage(this.groupId, text);
      input.value = '';
      this.messages.push(msg);
      this.appendMessage(msg);
      this.scrollBottom();
    } catch (e) {
      const errMsg = typeof e === 'string' ? e : e.message || 'Send failed';
      App.toastError(errMsg);
    } finally {
      input.disabled = false;
      sendBtn.disabled = false;
      input.focus();
    }
  },

  onNewGroupMessage(msg) {
    if (this.groupId && msg.group_id === this.groupId) {
      this.messages.push(msg);
      this.appendMessage(msg);
      this.smartScroll();
    }
  },

  createMessageElement(msg) {
    const time = new Date(msg.timestamp * 1000).toLocaleTimeString([], {
      hour: 'numeric', minute: '2-digit'
    });

    const div = document.createElement('div');
    div.dataset.timestamp = msg.timestamp;

    const senderName = App.getBuddyName(msg.from_device);
    const content = esc(msg.text);

    if (msg.sent_by_me) {
      div.className = 'message-bubble message-sent';
      div.innerHTML = `${content}<div class="message-time">${esc(time)}</div>`;
    } else {
      div.className = 'message-bubble message-recv';
      div.innerHTML = `<span class="group-sender-name">${esc(senderName)}</span><br>${content}<div class="message-time">${esc(time)}</div>`;
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
