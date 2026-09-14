/**
 * storage/audit.js
 * 
 * Manages privacy-first local audit logging using IndexedDB.
 * Stores prompt submissions and file attachment governance logs strictly on the local device.
 * No raw prompt or file text is ever transmitted off the device.
 */

const DB_NAME = 'AIGovernanceDB';
const DB_VERSION = 3; // Incremented for SHA-256 file deduplication cache store
const STORE_NAME = 'AuditLogs';
const CACHE_STORE_NAME = 'fileHashCache';

/**
 * Initializes and upgrades the IndexedDB database instance.
 * @returns {Promise<IDBDatabase>}
 */
function initAuditDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      let store;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        store = db.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
      } else {
        store = event.target.transaction.objectStore(STORE_NAME);
      }

      if (!store.indexNames.contains('timestamp')) {
        store.createIndex('timestamp', 'timestamp', { unique: false });
      }
      if (!store.indexNames.contains('decision')) {
        store.createIndex('decision', 'decision', { unique: false });
      }
      if (!store.indexNames.contains('riskScore')) {
        store.createIndex('riskScore', 'riskScore', { unique: false });
      }
      if (!store.indexNames.contains('destinationDomain')) {
        store.createIndex('destinationDomain', 'destinationDomain', { unique: false });
      }
      if (!store.indexNames.contains('fileName')) {
        store.createIndex('fileName', 'fileName', { unique: false });
      }

      // Non-destructive creation of fileHashCache for SHA-256 deduplication
      if (!db.objectStoreNames.contains(CACHE_STORE_NAME)) {
        db.createObjectStore(CACHE_STORE_NAME, { keyPath: 'hash' });
      }
    };

    request.onsuccess = (event) => {
      resolve(event.target.result);
    };

    request.onerror = (event) => {
      console.error('[AI Governance] IndexedDB initialization error:', event.target.error);
      reject(event.target.error);
    };
  });
}

/**
 * Retrieves a cached audit evaluation result by file SHA-256 hash.
 * @param {string} hash SHA-256 hash hex string
 * @returns {Promise<Object|null>}
 */
async function getFileHashCache(hash) {
  if (!hash || typeof hash !== 'string') return null;
  try {
    const db = await initAuditDB();
    if (!db.objectStoreNames.contains(CACHE_STORE_NAME)) return null;

    return new Promise((resolve) => {
      const transaction = db.transaction([CACHE_STORE_NAME], 'readonly');
      const store = transaction.objectStore(CACHE_STORE_NAME);
      const request = store.get(hash);

      request.onsuccess = (event) => {
        resolve(event.target.result || null);
      };
      request.onerror = () => {
        resolve(null);
      };
    });
  } catch (err) {
    console.error('[AI Governance] getFileHashCache exception:', err);
    return null;
  }
}

/**
 * Saves a file audit evaluation result indexed by SHA-256 hash.
 * @param {Object} cacheEntry Entry containing hash, decision, riskScore, timestamp, reasons, etc.
 * @returns {Promise<boolean>}
 */
async function saveFileHashCache(cacheEntry) {
  if (!cacheEntry || !cacheEntry.hash) return false;
  try {
    const db = await initAuditDB();
    if (!db.objectStoreNames.contains(CACHE_STORE_NAME)) return false;

    return new Promise((resolve) => {
      const transaction = db.transaction([CACHE_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(CACHE_STORE_NAME);

      const record = {
        hash: cacheEntry.hash,
        decision: cacheEntry.action || cacheEntry.decision || 'allow',
        riskScore: cacheEntry.riskScore || 0,
        timestamp: cacheEntry.timestamp || new Date().toISOString(),
        explanation: cacheEntry.explanation || '',
        reasons: cacheEntry.reasons || [],
        categories: cacheEntry.categories || [],
        fileName: cacheEntry.fileName || 'unknown_file',
        unscannable: Boolean(cacheEntry.unscannable),
        fixedFloorTriggered: Boolean(cacheEntry.fixedFloorTriggered),
        cached: true
      };

      const request = store.put(record);
      request.onsuccess = () => resolve(true);
      request.onerror = (err) => {
        console.error('[AI Governance] Failed to save file hash cache:', err);
        resolve(false);
      };
    });
  } catch (err) {
    console.error('[AI Governance] saveFileHashCache exception:', err);
    return false;
  }
}

/**
 * Saves a governance audit log entry to local IndexedDB.
 * @param {Object} record Entry containing timestamp, promptText, decision, riskScore, fileName, etc.
 * @returns {Promise<number>} Inserted record ID
 */
async function logAuditRecord(record) {
  try {
    const db = await initAuditDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);

      const entry = {
        timestamp: record.timestamp || new Date().toISOString(),
        promptText: record.promptText || '',
        destinationDomain: record.destinationDomain || 'unknown',
        userRole: record.userRole || 'default',
        riskScore: record.riskScore || 0,
        decision: record.decision || 'allow',
        explanation: record.explanation || '',
        reasons: record.reasons || [],
        categories: record.categories || [],
        fileName: record.fileName || null,
        fileType: record.fileType || null,
        fileSize: record.fileSize || 0,
        unscannable: Boolean(record.unscannable),
        fixedFloorTriggered: Boolean(record.fixedFloorTriggered),
        latencyMs: record.latencyMs || 0
      };

      const request = store.add(entry);

      request.onsuccess = (event) => {
        resolve(event.target.result);
      };

      request.onerror = (event) => {
        console.error('[AI Governance] Failed to insert audit record:', event.target.error);
        reject(event.target.error);
      };
    });
  } catch (err) {
    console.error('[AI Governance] logAuditRecord exception:', err);
    return null;
  }
}

/**
 * Retrieves audit log entries sorted by timestamp descending.
 * @param {number} [limit=100] Maximum number of records to retrieve
 * @returns {Promise<Array<Object>>}
 */
async function getAuditRecords(limit = 100) {
  try {
    const db = await initAuditDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const index = store.index('timestamp');

      const records = [];
      const cursorRequest = index.openCursor(null, 'prev'); // Descending order

      cursorRequest.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor && records.length < limit) {
          records.push(cursor.value);
          cursor.continue();
        } else {
          resolve(records);
        }
      };

      cursorRequest.onerror = (event) => {
        reject(event.target.error);
      };
    });
  } catch (err) {
    console.error('[AI Governance] getAuditRecords exception:', err);
    return [];
  }
}

/**
 * Clears all audit log records stored locally.
 * @returns {Promise<boolean>}
 */
async function clearAuditRecords() {
  try {
    const db = await initAuditDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.clear();

      request.onsuccess = () => resolve(true);
      request.onerror = (err) => reject(err);
    });
  } catch (err) {
    console.error('[AI Governance] clearAuditRecords exception:', err);
    return false;
  }
}

/**
 * Clears all cached file SHA-256 hash entries without deleting audit logs.
 * @returns {Promise<boolean>}
 */
async function clearFileHashCache() {
  try {
    const db = await initAuditDB();
    if (!db.objectStoreNames.contains(CACHE_STORE_NAME)) return true;
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([CACHE_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(CACHE_STORE_NAME);
      const request = store.clear();

      request.onsuccess = () => resolve(true);
      request.onerror = (err) => reject(err);
    });
  } catch (err) {
    console.error('[AI Governance] clearFileHashCache exception:', err);
    return false;
  }
}

// Support both ES Modules and script environment exports
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    initAuditDB,
    logAuditRecord,
    getAuditRecords,
    clearAuditRecords,
    getFileHashCache,
    saveFileHashCache,
    clearFileHashCache
  };
}
if (typeof globalThis !== 'undefined') {
  globalThis.initAuditDB = initAuditDB;
  globalThis.logAuditRecord = logAuditRecord;
  globalThis.getAuditRecords = getAuditRecords;
  globalThis.clearAuditRecords = clearAuditRecords;
  globalThis.getFileHashCache = getFileHashCache;
  globalThis.saveFileHashCache = saveFileHashCache;
  globalThis.clearFileHashCache = clearFileHashCache;
}
if (typeof self !== 'undefined') {
  self.initAuditDB = initAuditDB;
  self.logAuditRecord = logAuditRecord;
  self.getAuditRecords = getAuditRecords;
  self.clearAuditRecords = clearAuditRecords;
  self.getFileHashCache = getFileHashCache;
  self.saveFileHashCache = saveFileHashCache;
  self.clearFileHashCache = clearFileHashCache;
}
