/**
 * popup/popup.js
 * 
 * Admin Dashboard UI Controller.
 * Manages configuration settings, detection toggles, role weights, threshold sliders,
 * local audit log viewing, search filtering, and evaluation suite launching.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const navTabs = document.querySelectorAll('.nav-tab');
  const tabPanes = document.querySelectorAll('.tab-pane');

  const toggleRegex = document.getElementById('toggle-regex');
  const toggleLLM = document.getElementById('toggle-llm');
  const toggleSync = document.getElementById('toggle-sync');
  const syncWarning = document.getElementById('sync-warning');

  const selectRole = document.getElementById('select-role');
  const sliderBlock = document.getElementById('slider-block');
  const sliderRedact = document.getElementById('slider-redact');
  const valueBlock = document.getElementById('value-block');
  const valueRedact = document.getElementById('value-redact');

  const btnSaveSettings = document.getElementById('btn-save-settings');
  const btnClearAudit = document.getElementById('btn-clear-audit');
  const btnLaunchEval = document.getElementById('btn-launch-eval');

  const auditSearch = document.getElementById('audit-search');
  const auditList = document.getElementById('audit-list');

  let loadedAuditRecords = [];

  // Default Settings Schema
  const DEFAULT_SETTINGS = {
    enableRegex: true,
    enableLLM: true,
    enableMetadataSync: false,
    userRole: 'engineering',
    blockThreshold: 75,
    redactThreshold: 45
  };

  // ==========================================
  // 1. TAB NAVIGATION
  // ==========================================
  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetTab = tab.dataset.tab;

      navTabs.forEach(t => t.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetPane = document.getElementById(`tab-${targetTab}`);
      if (targetPane) targetPane.classList.add('active');

      if (targetTab === 'audit') {
        fetchAndRenderAuditLogs();
      }
    });
  });

  // ==========================================
  // 2. SETTINGS LOAD & BINDING
  // ==========================================
  chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
    toggleRegex.checked = settings.enableRegex !== false;
    toggleLLM.checked = settings.enableLLM !== false;
    toggleSync.checked = Boolean(settings.enableMetadataSync);
    selectRole.value = settings.userRole || 'engineering';

    sliderBlock.value = settings.blockThreshold || 75;
    sliderRedact.value = settings.redactThreshold || 45;
    valueBlock.textContent = sliderBlock.value;
    valueRedact.textContent = sliderRedact.value;

    updateSyncWarningVisibility();
  });

  // Real-time Slider Value Updates
  sliderBlock.addEventListener('input', (e) => {
    valueBlock.textContent = e.target.value;
    if (parseInt(sliderRedact.value, 10) > parseInt(e.target.value, 10)) {
      sliderRedact.value = e.target.value;
      valueRedact.textContent = e.target.value;
    }
  });

  sliderRedact.addEventListener('input', (e) => {
    valueRedact.textContent = e.target.value;
    if (parseInt(sliderBlock.value, 10) < parseInt(e.target.value, 10)) {
      sliderBlock.value = e.target.value;
      valueBlock.textContent = e.target.value;
    }
  });

  toggleSync.addEventListener('change', updateSyncWarningVisibility);

  function updateSyncWarningVisibility() {
    if (toggleSync.checked) {
      syncWarning.classList.remove('hidden');
    } else {
      syncWarning.classList.add('hidden');
    }
  }

  // Save Settings Handler
  btnSaveSettings.addEventListener('click', () => {
    const newSettings = {
      enableRegex: toggleRegex.checked,
      enableLLM: toggleLLM.checked,
      enableMetadataSync: toggleSync.checked,
      userRole: selectRole.value,
      blockThreshold: parseInt(sliderBlock.value, 10),
      redactThreshold: parseInt(sliderRedact.value, 10)
    };

    chrome.storage.local.set(newSettings, () => {
      const origText = btnSaveSettings.textContent;
      btnSaveSettings.textContent = '✓ Settings Saved!';
      btnSaveSettings.style.background = '#10b981';

      setTimeout(() => {
        btnSaveSettings.textContent = origText;
        btnSaveSettings.style.background = '';
      }, 1500);
    });
  });

  // ==========================================
  // 3. LOCAL AUDIT LOG VIEWER
  // ==========================================
  function fetchAndRenderAuditLogs() {
    auditList.innerHTML = '<div class="empty-state">Loading local audit records...</div>';

    chrome.runtime.sendMessage({ type: 'GET_AUDIT_LOGS', limit: 100 }, (response) => {
      if (!response || !response.success) {
        auditList.innerHTML = '<div class="empty-state">Failed to load audit logs.</div>';
        return;
      }

      loadedAuditRecords = response.data || [];
      renderFilteredAuditLogs(auditSearch.value.trim());
    });
  }

  auditSearch.addEventListener('input', (e) => {
    renderFilteredAuditLogs(e.target.value.trim());
  });

  function renderFilteredAuditLogs(query) {
    if (!loadedAuditRecords || loadedAuditRecords.length === 0) {
      auditList.innerHTML = '<div class="empty-state">No local audit log entries recorded yet.</div>';
      return;
    }

    const filtered = loadedAuditRecords.filter(item => {
      if (!query) return true;
      const q = query.toLowerCase();
      return (
        item.promptText?.toLowerCase().includes(q) ||
        item.decision?.toLowerCase().includes(q) ||
        item.destinationDomain?.toLowerCase().includes(q) ||
        item.categories?.some(c => c.toLowerCase().includes(q))
      );
    });

    if (filtered.length === 0) {
      auditList.innerHTML = '<div class="empty-state">No logs matching search criteria.</div>';
      return;
    }

    auditList.innerHTML = filtered.map(item => {
      const dateStr = new Date(item.timestamp).toLocaleString();
      const promptSnippet = item.promptText ? (item.promptText.length > 80 ? item.promptText.substring(0, 80) + '...' : item.promptText) : '(empty)';
      const categoriesText = item.categories && item.categories.length > 0 ? item.categories.join(', ') : 'None';

      return `
        <div class="audit-item">
          <div class="audit-item-header">
            <span class="audit-badge ${item.decision}">${item.decision}</span>
            <span class="audit-time">${dateStr}</span>
          </div>
          <div class="audit-prompt">"${escapeHtml(promptSnippet)}"</div>
          <div class="audit-meta">
            <span>Risk Score: <strong>${item.riskScore}/100</strong></span>
            <span>Target: <strong>${item.destinationDomain}</strong></span>
            <span>Categories: <strong>${categoriesText}</strong></span>
          </div>
        </div>
      `;
    }).join('');
  }

  btnClearAudit.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all locally stored audit log records?')) {
      chrome.runtime.sendMessage({ type: 'CLEAR_AUDIT_LOGS' }, (response) => {
        if (response && response.success) {
          loadedAuditRecords = [];
          renderFilteredAuditLogs('');
        }
      });
    }
  });

  // ==========================================
  // 4. EVALUATION HARNESS LAUNCHER
  // ==========================================
  btnLaunchEval.addEventListener('click', () => {
    const evalUrl = chrome.runtime.getURL('eval/eval-runner.html');
    chrome.tabs.create({ url: evalUrl });
  });

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
});
