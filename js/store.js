/**
 * Global State Store for SOC Lab
 * Manages logs, user progress, scores, active views, and notification events.
 */

const STORAGE_KEY_PROGRESS = 'soc_lab_progress_v1';
const STORAGE_KEY_LOGS = 'soc_lab_logs_v1';

class Store {
  constructor() {
    this.listeners = new Map();
    this.activeTab = 'lab'; // 'lab' | 'target' | 'siem' | 'cheatsheet' | 'progress'
    this.logs = [];
    this.completedQuestions = {};
    this.totalScore = 0;
    this.maxScore = 500;
    this.selectedLog = null;
    this.searchQuery = '';
    this.activeFilterCategory = 'all';

    this.loadState();
  }

  loadState() {
    try {
      const savedProgress = localStorage.getItem(STORAGE_KEY_PROGRESS);
      if (savedProgress) {
        const parsed = JSON.parse(savedProgress);
        this.completedQuestions = parsed.completedQuestions || {};
        this.totalScore = parsed.totalScore || 0;
      }
    } catch (e) {
      console.warn("Could not load progress from localStorage", e);
    }
  }

  saveProgress() {
    try {
      localStorage.setItem(STORAGE_KEY_PROGRESS, JSON.stringify({
        completedQuestions: this.completedQuestions,
        totalScore: this.totalScore
      }));
    } catch (e) {
      console.warn("Could not save progress to localStorage", e);
    }
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
    this.logs.unshift(log); // Prepend to top
    // Cap in-memory logs to 1000 to keep browser responsive
    if (this.logs.length > 1000) {
      this.logs.pop();
    }
    this.saveLogs();
    this.emit('logAdded', log);
    this.emit('logsUpdated', this.logs);
  }

  addLogsBatch(newLogs) {
    this.logs = [...newLogs, ...this.logs];
    if (this.logs.length > 1000) {
      this.logs = this.logs.slice(0, 1000);
    }
    this.saveLogs();
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

  recordAnswer(questionId, points = 50) {
    if (!this.completedQuestions[questionId]) {
      this.completedQuestions[questionId] = {
        completedAt: new Date().toISOString(),
        pointsAwarded: points
      };
      this.totalScore += points;
      this.saveProgress();
      this.emit('progressUpdated', {
        completedQuestions: this.completedQuestions,
        totalScore: this.totalScore
      });
      return true;
    }
    return false;
  }

  resetProgress() {
    this.completedQuestions = {};
    this.totalScore = 0;
    this.saveProgress();
    this.emit('progressUpdated', {
      completedQuestions: this.completedQuestions,
      totalScore: this.totalScore
    });
  }

  // Pub/Sub
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
