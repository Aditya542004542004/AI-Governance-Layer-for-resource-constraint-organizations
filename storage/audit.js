/**
 * storage/audit.js
 * 
 * Manages privacy-first local audit logging using IndexedDB.
 * Stores prompt submissions and file attachment governance logs strictly on the local device.
 * No raw prompt or file text is ever transmitted off the device.
 */

const DB_NAME = 'AIGovernanceDB';
const DB_VERSION = 2; // Incremented for file governance index support
const STORE_NAME = 'AuditLogs';

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

// Support both ES Modules and script environment exports
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { initAuditDB, logAuditRecord, getAuditRecords, clearAuditRecords };
} else if (typeof globalThis !== 'undefined') {
  globalThis.initAuditDB = initAuditDB;
  globalThis.logAuditRecord = logAuditRecord;
  globalThis.getAuditRecords = getAuditRecords;
  globalThis.clearAuditRecords = clearAuditRecords;
}
