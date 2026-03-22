// buddylist.js — Buddy List with QR, collapsible add, auto-establish, unread badges, profiles, groups
const BuddyList = {
  buddies: [],
  groups: [],
  refreshTimer: null,
  addFormOpen: false,
  createGroupOpen: false,
  profileCache: {},       // device_id -> { display_name, bio }
  _lastProfileFetch: 0,  // timestamp of last profile sync
  _shortCode: null,       // own short code (e.g. "A7X2KM9P")

  async render() {
    // Stop any existing timer
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }

    this.addFormOpen = false;

    // Load short code and screen name if not already cached
    if (!this._shortCode) {
      try { this._shortCode = await API.getShortCode(); } catch (_) {}
    }
    if (!this._screenName) {
      try { this._screenName = await API.getScreenName(); } catch (_) {}
    }

    const app = document.getElementById('app');
    const deviceId = App.deviceId || '...';
    const shortId = deviceId.length > 12 ? deviceId.substring(0, 12) + '...' : deviceId;

    app.innerHTML = `
      <div class="buddylist-container">
        <div class="buddylist-header">
          <h1>Echo</h1>
          <div class="heartbeat" id="heartbeat" title="Secure"></div>
        </div>

        <div class="my-id-section">
          <span class="my-id-name" id="myDisplayName" title="Click to edit">${esc(this._screenName || this.profileCache[deviceId]?.display_name || shortId)}</span>
          <span class="my-short-code" id="myShortCode">${this._shortCode ? this._formatCode(this._shortCode) : ''}</span>
          <button class="my-id-btn" id="btnEditName">Edit</button>
          <button class="my-id-btn" id="btnQR">QR</button>
          <button class="my-id-btn" id="btnCopy">${this._screenName ? 'Copy Name' : (this._shortCode ? 'Copy Code' : 'Copy ID')}</button>
          <button class="my-id-btn" id="btnInvite">Invite</button>
        </div>

        <div class="add-buddy-toggle">
          <button class="add-buddy-btn" id="btnToggleAdd">+ Add Buddy</button>
        </div>

        <div class="add-buddy-form" id="addBuddyForm">
          <div class="input-row">
            <input type="text" class="input-field" id="addBuddyId" placeholder="Screen name or short code">
            <button class="btn btn-primary" id="btnAddBuddy">Add</button>
          </div>
          <div class="add-buddy-name-row">
            <input type="text" class="input-field" id="addBuddyName" placeholder="Display name (optional)">
          </div>
        </div>

        <div class="buddy-list" id="buddyListItems"></div>

        <div class="groups-section">
          <div class="groups-header">
            <span class="groups-label">Groups</span>
            <button class="my-id-btn" id="btnNewGroup">+ New</button>
          </div>
          <div class="create-group-form" id="createGroupForm">
            <input type="text" class="input-field" id="newGroupName" placeholder="Group name...">
            <button class="btn btn-primary" id="btnCreateGroup">Create</button>
          </div>
          <div class="group-list" id="groupListItems"></div>
        </div>

        <div class="buddylist-footer">
          <div class="connection-status">
            <div class="dot"></div>
            Connected
          </div>
          <button class="btn btn-mute" id="btnMute">${App.muted ? 'Unmute' : 'Mute'}</button>
          <button class="btn btn-secondary" id="btnSignOut">Sign Off</button>
        </div>
      </div>
    `;

    this.bind();
    await this.refresh();

    this.refreshTimer = setInterval(() => this.refresh(), 5000);
  },

  bind() {
    document.getElementById('btnQR').addEventListener('click', () => {
      const code = this._shortCode ? this._formatCode(this._shortCode) : App.deviceId;
      QRCode.showModal(code, this._shortCode ? 'My Code' : undefined);
    });

    document.getElementById('btnCopy').addEventListener('click', () => {
      const text = this._screenName || (this._shortCode ? this._formatCode(this._shortCode) : App.deviceId);
      navigator.clipboard.writeText(text).catch(() => {});
      App.toastSuccess('Copied to clipboard');
    });

    document.getElementById('btnInvite').addEventListener('click', () => this.doGenerateInvite());

    document.getElementById('btnEditName').addEventListener('click', () => this.editDisplayName());

    document.getElementById('btnToggleAdd').addEventListener('click', () => {
      this.addFormOpen = !this.addFormOpen;
      const form = document.getElementById('addBuddyForm');
      if (this.addFormOpen) {
        form.classList.add('open');
        setTimeout(() => document.getElementById('addBuddyId')?.focus(), 100);
      } else {
        form.classList.remove('open');
      }
    });

    document.getElementById('btnAddBuddy').addEventListener('click', () => this.doAddBuddy());

    document.getElementById('addBuddyId').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.doAddBuddy();
    });

    document.getElementById('btnMute').addEventListener('click', () => {
      const muted = App.toggleMute();
      document.getElementById('btnMute').textContent = muted ? 'Unmute' : 'Mute';
    });

    document.getElementById('btnSignOut').addEventListener('click', () => this.doSignOut());

    document.getElementById('btnNewGroup').addEventListener('click', () => {
      this.createGroupOpen = !this.createGroupOpen;
      const form = document.getElementById('createGroupForm');
      if (this.createGroupOpen) {
        form.classList.add('open');
        setTimeout(() => document.getElementById('newGroupName')?.focus(), 100);
      } else {
        form.classList.remove('open');
      }
    });

    document.getElementById('btnCreateGroup').addEventListener('click', () => this.doCreateGroup());
    document.getElementById('newGroupName').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.doCreateGroup();
    });
  },

  async refresh() {
    try {
      this.buddies = await API.listBuddies();

      // Fetch profiles every 5 minutes
      const now = Date.now();
      if (now - this._lastProfileFetch > 300000) {
        this._lastProfileFetch = now;
        this.fetchProfiles();
      }

      // Use screen_name > display_name > local name > truncated UUID
      for (const b of this.buddies) {
        const cached = this.profileCache[b.device_id];
        const name = (cached && cached.screen_name) || (cached && cached.display_name) || b.display_name || b.device_id.substring(0, 8) + '...';
        App.cacheBuddyName(b.device_id, name);
      }
    } catch (e) {
      this.buddies = [];
    }

    // Fetch groups
    try {
      this.groups = await API.listGroups();
    } catch (e) {
      this.groups = [];
    }

    this.renderList();
    this.renderGroups();
  },

  async fetchProfiles() {
    for (const b of this.buddies) {
      try {
        const profile = await API.fetchProfile(b.device_id);
        this.profileCache[b.device_id] = profile;
      } catch (e) {
        // Cached profile or local name will be used
      }
    }
    // Re-render with updated names
    this.renderList();
  },

  renderList() {
    const container = document.getElementById('buddyListItems');
    if (!container) return;

    if (this.buddies.length === 0) {
      container.innerHTML = `
        <div class="empty-list">
          No friends here yet.<br>
          Tap QR to share your code and start chatting.
        </div>
      `;
      return;
    }

    const avatarColors = ['#ff6b6b','#4a9eff','#34c759','#ff9f43','#a55eea','#2ed573','#ff4757','#1e90ff'];
    container.innerHTML = this.buddies.map((b, i) => {
      const unread = App.getUnread(b.device_id);
      const cached = this.profileCache[b.device_id];
      const name = (cached && cached.screen_name) || (cached && cached.display_name) || b.display_name || b.device_id.substring(0, 8) + '...';
      const initial = name.charAt(0).toUpperCase();
      const colorIdx = b.device_id.charCodeAt(0) % 8;
      const avatarColor = avatarColors[colorIdx];
      return `
        <div class="buddy-item" style="animation-delay: ${i * 50}ms"
          data-device="${esc(b.device_id)}" data-name="${esc(name)}">
          <div class="buddy-avatar" style="background: ${avatarColor}">
            ${esc(initial)}
            <div class="status-dot ${b.has_session ? 'online' : 'offline'}"></div>
          </div>
          <div class="buddy-info">
            <div class="buddy-name">${esc(name)}</div>
          </div>
          ${unread > 0 ? `<div class="unread-badge">${unread}</div>` : ''}
          <span class="buddy-remove" data-remove="${esc(b.device_id)}">\u00d7</span>
        </div>
      `;
    }).join('');

    // Event delegation: buddy click → open chat, remove click → remove buddy
    container.addEventListener('click', (e) => {
      const removeBtn = e.target.closest('[data-remove]');
      if (removeBtn) {
        e.stopPropagation();
        BuddyList.removeBuddy(removeBtn.dataset.remove);
        return;
      }
      const item = e.target.closest('.buddy-item');
      if (item) {
        BuddyList.openChat(item.dataset.device, item.dataset.name);
      }
    });
  },

  _isShortCode(value) {
    // Short code: 8-9 chars (with optional hyphen), from unambiguous alphabet
    const stripped = value.replace(/-/g, '').toUpperCase();
    return stripped.length === 8 && /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]+$/.test(stripped);
  },

  _isUuid(value) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
  },

  _formatCode(code) {
    // Format 8-char code as XXXX-XXXX
    const clean = code.replace(/-/g, '').toUpperCase();
    if (clean.length === 8) return clean.substring(0, 4) + '-' + clean.substring(4);
    return code;
  },

  async doAddBuddy() {
    const input = document.getElementById('addBuddyId');
    const nameInput = document.getElementById('addBuddyName');
    const value = input.value.trim();
    const displayName = nameInput?.value?.trim() || '';

    if (!value) {
      App.toastError('Enter a screen name, short code, or device UUID');
      return;
    }

    try {
      let deviceId = value;
      let resolvedName = displayName;

      if (this._isUuid(value)) {
        // Direct UUID -- use as-is
      } else {
        // Could be a short code or screen name -- server detects the type
        const lookup = await API.lookupCode(value);
        deviceId = lookup.device_id;
        if (!resolvedName) {
          resolvedName = lookup.screen_name || lookup.display_name || '';
        }
      }

      await API.addBuddy(deviceId, resolvedName);
      input.value = '';
      if (nameInput) nameInput.value = '';

      // Collapse the add form
      this.addFormOpen = false;
      document.getElementById('addBuddyForm')?.classList.remove('open');

      await this.refresh();
      App.toastSuccess('Buddy added');

      // Auto-establish session in background
      this.autoEstablish(deviceId);
    } catch (e) {
      App.toastError(typeof e === 'string' ? e : e.message || 'Failed to add buddy');
    }
  },

  async autoEstablish(deviceId) {
    try {
      const ourDeviceId = await API.getDeviceId();
      console.log('[ECHO] autoEstablish: our=' + ourDeviceId + ' peer=' + deviceId);
      // Always try to establish -- the Rust side handles dedup via session_exists check
      console.log('[ECHO] Initiating session on buddy add');
      await API.establishSession(deviceId);
      await this.refresh();
    } catch (e) {
      console.error('[ECHO] autoEstablish failed:', e);
      // Session will establish later via polling — not an error
    }
  },

  async removeBuddy(deviceId) {
    try {
      await API.removeBuddy(deviceId);
      await this.refresh();
      App.toastInfo('Buddy removed');
    } catch (e) {
      App.toastError('Remove failed');
    }
  },

  openChat(deviceId, displayName) {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    App.navigate('chat', { deviceId, displayName });
  },

  onSessionEstablished(deviceId) {
    this.refresh();
  },

  updateConnectionStatus(mode) {
    const statusEl = document.querySelector('.connection-status');
    const hb = document.getElementById('heartbeat');
    if (!statusEl) return;

    if (mode === 'live') {
      statusEl.innerHTML = '<div class="dot dot-live"></div> Connected';
      statusEl.style.color = 'var(--green)';
      if (hb) hb.className = 'heartbeat';
    } else if (mode === 'danger') {
      statusEl.innerHTML = '<div class="dot"></div> Unsafe';
      statusEl.style.color = 'var(--red)';
      if (hb) hb.className = 'heartbeat danger';
    } else {
      statusEl.innerHTML = '<div class="dot dot-polling"></div> Connecting';
      statusEl.style.color = 'var(--blue)';
      if (hb) hb.className = 'heartbeat';
    }
  },

  async doGenerateInvite() {
    try {
      const codes = await API.generateInvites(1);
      if (codes && codes.length > 0) {
        const code = codes[0];
        navigator.clipboard.writeText(code).catch(() => {});
        QRCode.showModal(code, 'Invite Code');
        App.toastSuccess('Invite code copied');
      }
    } catch (e) {
      App.toastError(typeof e === 'string' ? e : e.message || 'Failed to generate invite');
    }
  },

  async editDisplayName() {
    const nameEl = document.getElementById('myDisplayName');
    const editBtn = document.getElementById('btnEditName');
    if (!nameEl || !editBtn) return;

    // Replace name span with an input field
    const current = nameEl.textContent;
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'input-field';
    input.value = current.includes('...') ? '' : current;
    input.placeholder = 'Display name';
    input.style.cssText = 'width: 120px; padding: 4px 8px; font-size: 11px;';

    nameEl.replaceWith(input);
    input.focus();
    input.select();

    editBtn.textContent = 'Save';
    editBtn.onclick = async () => {
      const newName = input.value.trim();
      if (!newName) {
        App.toastError('Name cannot be empty');
        return;
      }

      try {
        const profile = await API.updateProfile(newName);
        this.profileCache[App.deviceId] = profile;

        // Restore display
        const span = document.createElement('span');
        span.className = 'my-id-name';
        span.id = 'myDisplayName';
        span.title = 'Click to edit';
        span.textContent = profile.display_name || newName;
        input.replaceWith(span);

        editBtn.textContent = 'Edit';
        editBtn.onclick = () => this.editDisplayName();
        App.toastSuccess('Name updated');
      } catch (e) {
        App.toastError('Update failed');
      }
    };

    // Save on Enter, cancel on Escape
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') editBtn.click();
      if (e.key === 'Escape') {
        const span = document.createElement('span');
        span.className = 'my-id-name';
        span.id = 'myDisplayName';
        span.title = 'Click to edit';
        span.textContent = current;
        input.replaceWith(span);
        editBtn.textContent = 'Edit';
        editBtn.onclick = () => this.editDisplayName();
      }
    });
  },

  renderGroups() {
    const container = document.getElementById('groupListItems');
    if (!container) return;

    if (this.groups.length === 0) {
      container.innerHTML = '<div class="empty-groups">No groups yet. Create one above.</div>';
      return;
    }

    const groupColors = ['#ff6b6b','#4a9eff','#34c759','#ff9f43','#a55eea','#2ed573','#ff4757','#1e90ff'];
    container.innerHTML = this.groups.map((g, i) => {
      const unread = App.getUnread('grp-' + g.group_id);
      const initial = g.name.charAt(0).toUpperCase();
      const colorIdx = g.group_id.charCodeAt(0) % 8;
      return `
        <div class="group-item" style="animation-delay: ${i * 50}ms"
          data-group="${esc(g.group_id)}" data-gname="${esc(g.name)}">
          <div class="group-icon" style="background: ${groupColors[colorIdx]}">${esc(initial)}</div>
          <div class="buddy-info">
            <div class="buddy-name">${esc(g.name)}</div>
            <div class="buddy-device">${g.member_count} member${g.member_count !== 1 ? 's' : ''}</div>
          </div>
          ${unread > 0 ? `<div class="unread-badge">${unread}</div>` : ''}
        </div>
      `;
    }).join('');

    // Event delegation: group click → open group chat
    container.addEventListener('click', (e) => {
      const item = e.target.closest('.group-item');
      if (item) {
        BuddyList.openGroupChat(item.dataset.group, item.dataset.gname);
      }
    });
  },

  async doCreateGroup() {
    const nameInput = document.getElementById('newGroupName');
    const name = nameInput.value.trim();
    if (!name) {
      App.toastError('Enter a group name');
      return;
    }

    // Use current buddy list as potential members
    const memberIds = this.buddies.map(b => b.device_id);

    try {
      await API.createGroup(name, memberIds);
      nameInput.value = '';
      this.createGroupOpen = false;
      document.getElementById('createGroupForm')?.classList.remove('open');
      await this.refresh();
      App.toastSuccess('Group created');
    } catch (e) {
      App.toastError(typeof e === 'string' ? e : e.message || 'Failed to create group');
    }
  },

  openGroupChat(groupId, groupName) {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    App.navigate('groupchat', { groupId, groupName });
  },

  async doSignOut() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    try {
      await API.signOff();
    } catch (e) {
      // ignore
    }
    App.navigate('signon');
  },
};
