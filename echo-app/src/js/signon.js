// signon.js — Animated sign-on screen
const SignOn = {
  hasVault: false,
  isNewAccount: false,
  showServer: false,

  async render() {
    try {
      this.hasVault = await API.vaultExists();
    } catch (e) {
      this.hasVault = false;
    }

    // Default mode: sign on if vault exists, create if not
    this.isNewAccount = !this.hasVault;

    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="signon-container">
        <div class="signon-logo">ECHO</div>
        <div class="signon-subtitle">Post-quantum encrypted messenger</div>

        <div class="signon-form">
          <div class="input-group">
            <input type="password" class="input-field" id="passphrase"
              placeholder="Passphrase" autofocus>
          </div>

          <div class="invite-group ${this.isNewAccount ? 'visible' : ''}" id="inviteGroup">
            <div class="input-group">
              <input type="text" class="input-field" id="inviteCode"
                placeholder="Invite code">
            </div>
          </div>

          <div class="input-group" id="serverGroup" style="display: ${this.showServer ? 'flex' : 'none'}">
            <input type="text" class="input-field" id="serverUrl"
              placeholder="https://echo.biotwin.io" value="https://echo.biotwin.io">
          </div>

          <div class="btn-row" style="justify-content: center;">
            <button class="btn btn-primary" id="btnAction" style="flex:1">
              ${this.isNewAccount ? 'Create Account' : 'Sign On'}
            </button>
          </div>

          <div class="btn-row" style="justify-content: center;">
            <button class="btn btn-secondary" id="btnToggleMode" style="flex:1; font-size:11px;">
              ${this.isNewAccount ? 'I Have an Account' : 'New Account Instead'}
            </button>
          </div>

          <div class="server-toggle" id="toggleServer">
            ${this.showServer ? 'Hide server settings' : 'Server settings'}
          </div>
        </div>

        <div class="signon-version">v0.1</div>
      </div>
    `;

    this.bind();
  },

  bind() {
    const el = (id) => document.getElementById(id);

    el('passphrase').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.doAction();
    });

    el('btnAction').addEventListener('click', () => this.doAction());

    el('btnToggleMode').addEventListener('click', () => {
      this.isNewAccount = !this.isNewAccount;
      const inviteGroup = el('inviteGroup');
      const btn = el('btnAction');
      const toggle = el('btnToggleMode');

      if (this.isNewAccount) {
        inviteGroup.classList.add('visible');
        btn.textContent = 'Create Account';
        toggle.textContent = 'I Have an Account';
      } else {
        inviteGroup.classList.remove('visible');
        btn.textContent = 'Sign On';
        toggle.textContent = 'New Account Instead';
      }
    });

    el('toggleServer').addEventListener('click', () => {
      this.showServer = !this.showServer;
      el('serverGroup').style.display = this.showServer ? 'flex' : 'none';
      el('toggleServer').textContent = this.showServer ? 'Hide server settings' : 'Server settings';
    });
  },

  getServer() {
    const el = document.getElementById('serverUrl');
    return el ? el.value.trim() : 'https://echo.biotwin.io';
  },

  setLoading(loading) {
    const btn = document.getElementById('btnAction');
    if (!btn) return;
    if (loading) {
      btn.disabled = true;
      btn.classList.add('btn-loading');
    } else {
      btn.disabled = false;
      btn.classList.remove('btn-loading');
    }
  },

  doAction() {
    if (this.isNewAccount) {
      this.doCreate();
    } else {
      this.doSignOn();
    }
  },

  async doSignOn() {
    const passphrase = document.getElementById('passphrase').value;
    if (!passphrase) {
      App.toastError('Enter your passphrase');
      return;
    }

    this.setLoading(true);

    try {
      const result = await this.withTimeout(
        API.signOn(this.getServer(), passphrase), 15000
      );
      App.deviceId = result.device_id;
      App.navigate('buddylist');
    } catch (e) {
      App.toastError(typeof e === 'string' ? e : e.message || 'Sign on failed');
      this.setLoading(false);
    }
  },

  async doCreate() {
    const passphrase = document.getElementById('passphrase').value;
    const inviteCode = document.getElementById('inviteCode')?.value?.trim() || '';

    if (!passphrase) {
      App.toastError('Enter a passphrase');
      return;
    }
    if (passphrase.length < 12) {
      App.toastError('Passphrase needs at least 12 characters');
      return;
    }
    if (!inviteCode) {
      App.toastError('Enter an invite code');
      return;
    }

    this.setLoading(true);

    try {
      const result = await this.withTimeout(
        API.createAccount(this.getServer(), passphrase, inviteCode), 15000
      );
      App.deviceId = result.device_id;
      App.navigate('buddylist');
    } catch (e) {
      App.toastError(typeof e === 'string' ? e : e.message || 'Account creation failed');
      this.setLoading(false);
    }
  },

  // Wrap a promise with a timeout so users aren't stuck on a dead server
  withTimeout(promise, ms) {
    return Promise.race([
      promise,
      new Promise((_, reject) =>
        setTimeout(() => reject('Server not responding — check connection'), ms)
      ),
    ]);
  },
};
