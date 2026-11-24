/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Frontend API Client
 */

export const api = {
  // Session & Connection
  async getSession() {
    const res = await fetch('/api/session/me', { credentials: 'include' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  // Challenges
  async sqliLogin(username, password) {
    const res = await fetch('/api/challenge/sqli/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });
    return res.json();
  },

  async verifyXss(payload) {
    const res = await fetch('/api/challenge/xss/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ payload })
    });
    return res.json();
  },

  async getIdorProfile(id) {
    const res = await fetch(`/api/challenge/idor/profile/${id}`, { credentials: 'include' });
    return res.json();
  },

  // Events & SOC
  async getEvents(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await fetch(`/api/events?${query}`, { credentials: 'include' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  async getEventDetails(id) {
    const res = await fetch(`/api/events/${id}`, { credentials: 'include' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  async getStats() {
    const res = await fetch('/api/events/stats/summary', { credentials: 'include' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  // IOC Investigation
  async getIocIndicators() {
    const res = await fetch('/api/ioc/indicators', { credentials: 'include' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  // Flags & Progress
  async submitFlag(challengeId, flagType, flag) {
    const res = await fetch('/api/flags/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ challenge_id: challengeId, flag_type: flagType, flag })
    });
    return res.json();
  },

  async getProgress() {
    const res = await fetch('/api/flags/progress', { credentials: 'include' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }
};
