/**
 * Global State Store for SOC Lab
 * Manages logs, active views, filters, and UI selection events.
 */

const STORAGE_KEY_LOGS = 'blitz_soc_logs_v1';

class Store {
  constructor() {
    this.listeners = new Map();
    this.activeTab = 'target'; // 'target' | 'siem'
    this.logs = [];
    this.selectedLog = null;
    this.searchQuery = '';
    this.activeFilterCategory = 'all';
  }

  saveLogs() {
    try {
      localStorage.setItem(STORAGE_KEY_LOGS, JSON.stringify(this.logs));
    } catch (e) {
      console.warn("Could not persist logs to localStorage", e);
    }
  }

  setTab(tab) {
    if (this.activeTab !== tab) {
      this.activeTab = tab;
      this.emit('tabChange', tab);
    }
  }

  setLogs(newLogs) {
    this.logs = newLogs;
    this.saveLogs();
    this.emit('logsUpdated', this.logs);
  }

  addLog(log) {
    this.logs.unshift(log); // Prepend newest log
    if (this.logs.length > 1000) {
      this.logs.pop();
    }
    this.saveLogs();
    this.emit('logAdded', log);
    this.emit('logsUpdated', this.logs);
  }

  selectLog(log) {
    this.selectedLog = log;
    this.emit('logSelected', log);
  }

  setSearchQuery(q) {
    this.searchQuery = q;
    this.emit('filterChanged', { query: this.searchQuery, category: this.activeFilterCategory });
  }

  setFilterCategory(cat) {
    this.activeFilterCategory = cat;
    this.emit('filterChanged', { query: this.searchQuery, category: this.activeFilterCategory });
  }

  // Event Pub/Sub
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event).push(callback);
    return () => this.off(event, callback);
  }

  off(event, callback) {
    if (!this.listeners.has(event)) return;
    const filtered = this.listeners.get(event).filter(cb => cb !== callback);
    this.listeners.set(event, filtered);
  }

  emit(event, data) {
    if (this.listeners.has(event)) {
      for (const cb of this.listeners.get(event)) {
        try {
          cb(data);
        } catch (e) {
          console.error(`Error in store listener for ${event}:`, e);
        }
      }
    }
  }
}

export const store = new Store();
