/**
 * Bastion Audit v2.0 Enterprise - Frontend API Client
 */
const API = {
  baseUrl: window.location.origin,

  async getStatus() {
    const res = await fetch(`${this.baseUrl}/api/status`);
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async getDevices() {
    const res = await fetch(`${this.baseUrl}/api/devices`);
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async triggerScan() {
    const res = await fetch(`${this.baseUrl}/api/scan`, { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async updateDeviceStatus(mac, status) {
    const res = await fetch(`${this.baseUrl}/api/device/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, status }),
    });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async deleteDevice(mac) {
    const res = await fetch(`${this.baseUrl}/api/device/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac }),
    });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async purgeLegacy() {
    const res = await fetch(`${this.baseUrl}/api/purge-legacy`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async getAuditTrail() {
    const res = await fetch(`${this.baseUrl}/api/audit-trail`);
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async verifyAudit() {
    const res = await fetch(`${this.baseUrl}/api/verify-audit`);
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async getLogs() {
    const res = await fetch(`${this.baseUrl}/api/logs`);
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async getDefenseStatus() {
    const res = await fetch(`${this.baseUrl}/api/defense/status`);
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async blockThreat(ip, mac, reason) {
    const res = await fetch(`${this.baseUrl}/api/defense/block`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, mac, reason }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP Error: ${res.status}`);
    }
    return await res.json();
  },

  async unblockThreat(ip, mac) {
    const res = await fetch(`${this.baseUrl}/api/defense/unblock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, mac }),
    });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async lockGateway() {
    const res = await fetch(`${this.baseUrl}/api/defense/lock-gateway`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP Error: ${res.status}`);
    }
    return await res.json();
  },

  async reclassifyDevices() {
    const res = await fetch(`${this.baseUrl}/api/devices/reclassify`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async deepScanDevice(mac, ip) {
    const res = await fetch(`${this.baseUrl}/api/device/deep-scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, ip }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP Error: ${res.status}`);
    }
    return await res.json();
  },

  async handshakeDevice(mac, ip) {
    const res = await fetch(`${this.baseUrl}/api/device/handshake`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, ip }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP Error: ${res.status}`);
    }
    return await res.json();
  },

  async updateDeviceMeta(payload) {
    const res = await fetch(`${this.baseUrl}/api/device/update-meta`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP Error: ${res.status}`);
    }
    return await res.json();
  },

  async sendWakeOnLan(mac) {
    const res = await fetch(`${this.baseUrl}/api/device/wol`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP Error: ${res.status}`);
    }
    return await res.json();
  },

  async probeCamera(ip, username = 'admin', password = '') {
    const res = await fetch(`${this.baseUrl}/api/camera/probe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, username, password }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP Error: ${res.status}`);
    }
    return await res.json();
  },

  async configureHoneyport(enabled, autoBlock) {
    const res = await fetch(`${this.baseUrl}/api/defense/honeyport`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, auto_block: autoBlock }),
    });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },

  async elevateFirewallUac() {
    const res = await fetch(`${this.baseUrl}/api/defense/elevate-uac`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP Error: ${res.status}`);
    }
    return await res.json();
  },

  async clearLogs() {
    const res = await fetch(`${this.baseUrl}/api/logs/clear`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    return await res.json();
  },
};

