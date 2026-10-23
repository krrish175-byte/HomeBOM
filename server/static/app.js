/**
 * HomeBOM - Frontend Logic & Web Speech Client
 *
 * Implements:
 * - Web Speech API microphone input with animated feedback
 * - Fallback text input & demo phrasing chips
 * - Backend MCP client communication (/api/chat)
 * - Badges: "routed by: bedrock | keywords" and "phrasing: bedrock | template"
 * - Voice output via window.speechSynthesis with mute toggle
 * - Monitored device cards ranked by risk tier with quick actions
 * - CycloneDX 1.6 HBOM preview and JSON export
 */

(function () {
  'use strict';

  // State
  let audioOutputEnabled = true;
  let recognitionInstance = null;
  let isListening = false;
  let cachedHbom = null;

  // DOM Elements
  const micBtn = document.getElementById('mic-btn');
  const voiceStatusText = document.getElementById('voice-status-text');
  const assistantState = document.getElementById('assistant-state');
  const chatForm = document.getElementById('chat-form');
  const textInput = document.getElementById('text-input');
  const sendBtn = document.getElementById('send-btn');
  const transcriptContainer = document.getElementById('transcript-container');
  const clearTranscriptBtn = document.getElementById('clear-transcript-btn');
  const audioToggle = document.getElementById('audio-toggle');
  const iconSoundOn = audioToggle.querySelector('.icon-sound-on');
  const iconSoundOff = audioToggle.querySelector('.icon-sound-off');
  const deviceCardsGrid = document.getElementById('device-cards-grid');
  const refreshDevicesBtn = document.getElementById('refresh-devices-btn');
  const openHbomModalBtn = document.getElementById('open-hbom-modal-btn');
  const hbomModal = document.getElementById('hbom-modal');
  const closeModalBtn = document.getElementById('close-modal-btn');
  const downloadHbomBtn = document.getElementById('download-hbom-btn');
  const hbomJsonContent = document.getElementById('hbom-json-content');
  const inventorySummaryText = document.getElementById('inventory-summary-text');

  // =========================================================================
  // 1. Web Speech Synthesis (Spoken Output)
  // =========================================================================
  function speakSpokenText(text) {
    if (!audioOutputEnabled || !('speechSynthesis' in window)) return;
    try {
      window.speechSynthesis.cancel(); // Cancel any ongoing speech
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 1.0;
      utterance.pitch = 1.0;
      utterance.lang = 'en-US';
      window.speechSynthesis.speak(utterance);
    } catch (e) {
      console.warn('SpeechSynthesis error:', e);
    }
  }

  audioToggle.addEventListener('click', () => {
    audioOutputEnabled = !audioOutputEnabled;
    if (audioOutputEnabled) {
      iconSoundOn.classList.remove('hidden');
      iconSoundOff.classList.add('hidden');
      audioToggle.title = 'Voice audio output: ENABLED';
    } else {
      iconSoundOn.classList.add('hidden');
      iconSoundOff.classList.remove('hidden');
      audioToggle.title = 'Voice audio output: MUTED';
      if ('speechSynthesis' in window) window.speechSynthesis.cancel();
    }
  });

  // =========================================================================
  // 2. Web Speech API (Microphone Input)
  // =========================================================================
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

  if (SpeechRecognition) {
    recognitionInstance = new SpeechRecognition();
    recognitionInstance.continuous = false;
    recognitionInstance.interimResults = false;
    recognitionInstance.lang = 'en-US';

    recognitionInstance.onstart = () => {
      isListening = true;
      micBtn.classList.add('recording');
      voiceStatusText.textContent = 'Listening... Speak now';
      assistantState.textContent = 'Listening';
      assistantState.className = 'status-badge';
    };

    recognitionInstance.onresult = (event) => {
      const speechQuery = event.results[0][0].transcript;
      voiceStatusText.textContent = `Heard: "${speechQuery}"`;
      textInput.value = speechQuery;
      submitQuery(speechQuery);
    };

    recognitionInstance.onerror = (event) => {
      console.warn('SpeechRecognition error:', event.error);
      voiceStatusText.textContent = `Mic error: ${event.error}. Use text box.`;
      resetMicUI();
    };

    recognitionInstance.onend = () => {
      resetMicUI();
    };
  } else {
    voiceStatusText.textContent = 'Web Speech not supported in this browser. Use text box.';
  }

  function resetMicUI() {
    isListening = false;
    micBtn.classList.remove('recording');
    assistantState.textContent = 'Ready';
    assistantState.className = 'pulse-indicator-idle';
    if (!voiceStatusText.textContent.startsWith('Heard')) {
      voiceStatusText.textContent = 'Click mic to speak, or use text box below';
    }
  }

  micBtn.addEventListener('click', () => {
    if (!recognitionInstance) {
      alert('Speech Recognition is not available in this browser. Please type your query in the box below.');
      textInput.focus();
      return;
    }
    if (isListening) {
      recognitionInstance.stop();
    } else {
      try {
        recognitionInstance.start();
      } catch (e) {
        console.warn('Failed to start recognition:', e);
      }
    }
  });

  // =========================================================================
  // 3. Query Submission & Backend MCP Client Route (/api/chat)
  // =========================================================================
  async function submitQuery(queryText) {
    const q = (queryText || '').trim();
    if (!q) return;

    // Append user message to transcript
    appendUserMessage(q);
    textInput.value = '';

    // Show loading assistant indicator
    const loadingCard = appendLoadingAssistantCard();
    assistantState.textContent = 'MCP Routing';

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: q }),
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }

      const data = await res.json();
      loadingCard.remove();
      assistantState.textContent = 'Ready';

      // Append assistant card with routing badges
      appendAssistantMessage(data);

      // Play voice output
      if (data.spoken) {
        speakSpokenText(data.spoken);
      }

      // If tool was export_hbom, cache the BOM for modal view
      if (data.tool_called === 'export_hbom' && data.result && data.result.bom) {
        cachedHbom = data.result.bom;
      }

      // Refresh inventory if a tool changed devices or was a scan
      if (data.tool_called === 'scan_home' || data.tool_called === 'add_device') {
        loadDevices();
      }
    } catch (err) {
      loadingCard.remove();
      assistantState.textContent = 'Error';
      appendErrorMessage(`Failed to query MCP backend: ${err.message}`);
    }
  }

  chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    submitQuery(textInput.value);
  });

  // Demo shortcut chips
  document.querySelectorAll('.query-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const query = chip.getAttribute('data-query');
      textInput.value = query;
      submitQuery(query);
    });
  });

  // =========================================================================
  // 4. Transcript UI Builders
  // =========================================================================
  function appendUserMessage(text) {
    const card = document.createElement('div');
    card.className = 'transcript-card user-card';
    card.innerHTML = `
      <div class="card-meta">
        <span class="speaker-tag">You</span>
        <span class="badge badge-tool">query</span>
      </div>
      <div class="card-body">
        <p>${escapeHtml(text)}</p>
      </div>
    `;
    transcriptContainer.appendChild(card);
    scrollToBottom();
  }

  function appendLoadingAssistantCard() {
    const card = document.createElement('div');
    card.className = 'transcript-card assistant-card';
    card.innerHTML = `
      <div class="card-meta">
        <span class="speaker-tag">HomeBOM</span>
        <span class="badge badge-tool">calling MCP over Streamable HTTP...</span>
      </div>
      <div class="card-body">
        <div class="spinner" style="width:18px;height:18px;border-width:2px;display:inline-block;"></div>
        <span style="font-size:0.85rem;color:var(--text-muted);margin-left:8px;">Evaluating security criteria...</span>
      </div>
    `;
    transcriptContainer.appendChild(card);
    scrollToBottom();
    return card;
  }

  function appendAssistantMessage(data) {
    const card = document.createElement('div');
    card.className = 'transcript-card assistant-card';

    const toolName = data.tool_called || 'unknown_tool';
    const routedBy = data.routed_by || 'keywords';
    const phrasingSource = data.phrasing_source || 'template';
    const spoken = data.spoken || 'No spoken text returned.';

    let extraHtml = '';
    if (toolName === 'export_hbom' && data.result && data.result.bom) {
      extraHtml = `
        <div class="card-footer">
          <button class="btn-secondary" onclick="window.viewCachedHbom()">
            View CycloneDX 1.6 HBOM
          </button>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="card-meta">
        <span class="speaker-tag">HomeBOM</span>
        <span class="badge badge-tool">tool: ${escapeHtml(toolName)}</span>
        <span class="badge badge-route">routed by: ${escapeHtml(routedBy)}</span>
        <span class="badge badge-phrasing">phrasing: ${escapeHtml(phrasingSource)}</span>
      </div>
      <div class="card-body">
        <p>${escapeHtml(spoken)}</p>
      </div>
      <div class="card-footer">
        <button class="btn-speak-replay" title="Replay voice audio">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon>
            <path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path>
          </svg>
          Replay Spoken
        </button>
      </div>
      ${extraHtml}
    `;

    card.querySelector('.btn-speak-replay').addEventListener('click', () => {
      speakSpokenText(spoken);
    });

    transcriptContainer.appendChild(card);
    scrollToBottom();
  }

  function appendErrorMessage(msg) {
    const card = document.createElement('div');
    card.className = 'transcript-card assistant-card';
    card.style.borderColor = 'var(--tier-fix-now-border)';
    card.innerHTML = `
      <div class="card-meta">
        <span class="speaker-tag" style="color:var(--tier-fix-now)">Error</span>
      </div>
      <div class="card-body">
        <p style="color:#fca5a5;">${escapeHtml(msg)}</p>
      </div>
    `;
    transcriptContainer.appendChild(card);
    scrollToBottom();
  }

  clearTranscriptBtn.addEventListener('click', () => {
    transcriptContainer.innerHTML = '';
  });

  function scrollToBottom() {
    transcriptContainer.scrollTop = transcriptContainer.scrollHeight;
  }

  // =========================================================================
  // 5. Monitored Devices Cards Ranked by Tier (/api/devices)
  // =========================================================================
  async function loadDevices() {
    try {
      const res = await fetch('/api/devices');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      renderDeviceCards(data.devices, data.epss_as_of);
    } catch (err) {
      deviceCardsGrid.innerHTML = `
        <div class="loading-state">
          <p style="color:#fca5a5;">Failed to load device inventory: ${escapeHtml(err.message)}</p>
          <button class="btn-secondary" onclick="window.reloadDevices()">Retry</button>
        </div>
      `;
    }
  }

  function renderDeviceCards(devices, asOfString) {
    if (!devices || devices.length === 0) {
      deviceCardsGrid.innerHTML = '<div class="loading-state"><p>No devices registered.</p></div>';
      return;
    }

    if (inventorySummaryText && asOfString) {
      inventorySummaryText.textContent = `8 Devices Monitored (${asOfString}) • CycloneDX 1.6 VEX Ready`;
    }

    // Rank ordering definition
    const tierPriority = {
      fix_now: 1,
      fix_soon: 2,
      low: 3,
      unknown: 4,
      not_affected: 5,
    };

    // Sort: highest risk tier first, then by max_epss descending
    const sorted = [...devices].sort((a, b) => {
      const pA = tierPriority[a.tier] || 99;
      const pB = tierPriority[b.tier] || 99;
      if (pA !== pB) return pA - pB;
      return (b.max_epss || 0) - (a.max_epss || 0);
    });

    deviceCardsGrid.innerHTML = '';
    sorted.forEach((dev) => {
      const card = createDeviceCard(dev);
      deviceCardsGrid.appendChild(card);
    });
  }

  function createDeviceCard(dev) {
    const card = document.createElement('div');
    const tierClass = `card-${dev.tier.replace('_', '-')}`;
    card.className = `device-card ${tierClass}`;
    card.id = `card-${dev.device_id}`;

    let tierBadgeHtml = '';
    if (dev.tier === 'fix_now') {
      tierBadgeHtml = '<span class="tier-badge badge-fix-now">Fix Now • KEV</span>';
    } else if (dev.tier === 'fix_soon') {
      tierBadgeHtml = '<span class="tier-badge badge-fix-soon">Fix Soon</span>';
    } else if (dev.tier === 'unknown') {
      tierBadgeHtml = '<span class="tier-badge badge-unknown">Unknown</span>';
    } else {
      tierBadgeHtml = '<span class="tier-badge badge-not-affected">Not Affected</span>';
    }

    const eolHtml = dev.is_eol ? '<span class="badge-eol">DISCONTINUED / EOL</span>' : '';
    const vulnText = dev.tier === 'unknown'
      ? `${(dev.unverified_candidates || []).length} candidates`
      : `${dev.vulnerabilities_count || 0} CVE(s)`;

    card.innerHTML = `
      <div class="card-top">
        <div class="device-title-area">
          <h4>${escapeHtml(dev.name)}</h4>
          <span class="device-model-sub">${escapeHtml(dev.model)}</span>
          <div>${eolHtml}</div>
        </div>
        <div>${tierBadgeHtml}</div>
      </div>

      <div class="card-specs">
        <div class="spec-row">
          <span class="spec-label">Firmware</span>
          <span class="spec-val-mono">${escapeHtml(dev.firmware || 'N/A')}</span>
        </div>
        <div class="spec-row">
          <span class="spec-label">Max CVSS</span>
          <span class="spec-val-mono">${dev.max_cvss ? dev.max_cvss.toFixed(1) : '0.0'}</span>
        </div>
        <div class="spec-row">
          <span class="spec-label">Max EPSS</span>
          <span class="spec-val-mono">${dev.max_epss ? dev.max_epss.toFixed(4) : '0.0000'}</span>
        </div>
        <div class="spec-row">
          <span class="spec-label">Vulnerabilities</span>
          <span class="spec-val-mono">${vulnText}</span>
        </div>
      </div>

      <div class="card-actions">
        <button class="btn-secondary btn-explain" data-name="${escapeHtml(dev.name)}">
          Explain Risk
        </button>
        <button class="btn-secondary btn-fix" data-name="${escapeHtml(dev.name)}">
          Fix Steps
        </button>
      </div>
    `;

    card.querySelector('.btn-explain').addEventListener('click', () => {
      submitQuery(`tell me about my ${dev.name}`);
    });

    card.querySelector('.btn-fix').addEventListener('click', () => {
      submitQuery(`how do I fix the ${dev.name}`);
    });

    return card;
  }

  refreshDevicesBtn.addEventListener('click', () => {
    loadDevices();
  });

  // =========================================================================
  // 6. CycloneDX 1.6 HBOM Modal & Download
  // =========================================================================
  async function fetchHbomDirect() {
    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'export my home bill of materials' }),
      });
      const data = await res.json();
      if (data.result && data.result.bom) {
        cachedHbom = data.result.bom;
        return cachedHbom;
      }
      throw new Error(data.message || 'Failed to export HBOM');
    } catch (e) {
      console.error(e);
      return null;
    }
  }

  async function openHbomModal() {
    hbomModal.classList.remove('hidden');
    if (!cachedHbom) {
      hbomJsonContent.textContent = 'Generating CycloneDX 1.6 Hardware BOM with embedded VEX via MCP...';
      const bom = await fetchHbomDirect();
      if (bom) {
        cachedHbom = bom;
        hbomJsonContent.textContent = JSON.stringify(bom, null, 2);
      } else {
        hbomJsonContent.textContent = 'Error loading CycloneDX BOM.';
      }
    } else {
      hbomJsonContent.textContent = JSON.stringify(cachedHbom, null, 2);
    }
  }

  function closeHbomModal() {
    hbomModal.classList.add('hidden');
  }

  openHbomModalBtn.addEventListener('click', openHbomModal);
  closeModalBtn.addEventListener('click', closeHbomModal);
  hbomModal.addEventListener('click', (e) => {
    if (e.target === hbomModal) closeHbomModal();
  });

  downloadHbomBtn.addEventListener('click', async () => {
    let bom = cachedHbom;
    if (!bom) {
      bom = await fetchHbomDirect();
    }
    if (!bom) return;

    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(bom, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `homebom-cyclonedx-1.6.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  });

  // Global helper for inline card buttons
  window.viewCachedHbom = () => {
    openHbomModal();
  };
  window.reloadDevices = () => {
    loadDevices();
  };

  // Utilities
  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Initial load
  loadDevices();
})();
