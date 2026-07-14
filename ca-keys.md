---
layout: toolpage
title: CA Public Keys
permalink: /ca-keys/
---

# Payment Network CA Public Keys

<p>Browse the EMV Certificate Authority (CA) Public Keys used by the validators on this site. These are the public keys published by payment networks for validating Issuer Public Key Certificates. Source: <code>/assets/ca_public_keys.json</code>.</p>

<div class="ca-keys-container">
  <div class="ca-keys-controls">
    <div class="form-group" style="display:inline-block; margin-right:16px;">
      <label for="caKeyFilter" class="form-label">Filter by Network:</label>
      <select id="caKeyFilter" class="tool-select-md">
        <option value="">All</option>
      </select>
    </div>
    <div class="form-group" style="display:inline-block;">
      <label for="caKeySearch" class="form-label">Search (RID, index, SHA-1):</label>
      <input id="caKeySearch" class="tool-textarea input-lg" placeholder="e.g. A000000003 or 09" />
    </div>
  </div>

  <div id="caKeysSummary" class="info-display" style="margin-top:12px;"></div>

  <div id="caKeysList" style="margin-top:16px;"></div>
</div>

<script>
(async function() {
  const listEl = document.getElementById('caKeysList');
  const filterEl = document.getElementById('caKeyFilter');
  const searchEl = document.getElementById('caKeySearch');
  const summaryEl = document.getElementById('caKeysSummary');

  let allKeys = [];

  try {
    const resp = await fetch('{{ site.baseurl }}/assets/ca_public_keys.json');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    allKeys = await resp.json();
  } catch (err) {
    listEl.innerHTML = `<div class="error-message">Failed to load CA keys: ${err.message}</div>`;
    return;
  }

  const networks = [...new Set(allKeys.map(k => k.network))].sort();
  networks.forEach(n => {
    const opt = document.createElement('option');
    opt.value = n;
    opt.textContent = n;
    filterEl.appendChild(opt);
  });

  function chunkHex(hex, size) {
    const out = [];
    for (let i = 0; i < hex.length; i += size) out.push(hex.substring(i, i + size));
    return out.join(' ');
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  }

  async function copyToClipboard(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      const original = btn.textContent;
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1500);
    } catch (e) {
      btn.textContent = 'Copy failed';
    }
  }

  function render() {
    const network = filterEl.value;
    const search = searchEl.value.trim().toLowerCase();

    const filtered = allKeys.filter(k => {
      if (network && k.network !== network) return false;
      if (search) {
        const haystack = [k.network, k.rid, k.index, k.exponent, k.sha1, String(k.size)].join(' ').toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      return true;
    });

    summaryEl.textContent = `Showing ${filtered.length} of ${allKeys.length} CA keys` +
      (network ? ` (network: ${network})` : '') +
      (search ? ` (matching "${searchEl.value}")` : '');

    if (filtered.length === 0) {
      listEl.innerHTML = '<p style="opacity:0.7;">No keys match the current filter.</p>';
      return;
    }

    // Group by network
    const groups = {};
    filtered.forEach(k => { (groups[k.network] = groups[k.network] || []).push(k); });

    let html = '';
    for (const net of Object.keys(groups).sort()) {
      html += `<h3 class="ca-network-heading">${escapeHtml(net)} <span class="ca-count">(${groups[net].length} keys)</span></h3>`;
      // Sort by index, then size
      groups[net].sort((a, b) => (a.index || '').localeCompare(b.index || '') || a.size - b.size);
      for (const k of groups[net]) {
        const modId = `mod-${net}-${k.index}-${k.size}`.replace(/[^a-zA-Z0-9_-]/g, '_');
        html += `
          <div class="ca-key-card">
            <div class="ca-key-header">
              <strong>${escapeHtml(k.network)}</strong> &mdash; Index <code>${escapeHtml(k.index)}</code> &mdash; ${k.size} bit
            </div>
            <table class="summary-table" style="margin-top:8px;">
              <tbody>
                <tr><td>RID</td><td><code>${escapeHtml(k.rid)}</code></td></tr>
                <tr><td>Index</td><td><code>${escapeHtml(k.index)}</code></td></tr>
                <tr><td>Key Size</td><td>${k.size} bits (${k.size / 8} bytes)</td></tr>
                <tr><td>Exponent</td><td><code>${escapeHtml(k.exponent)}</code></td></tr>
                <tr><td>SHA-1 Hash</td><td><code class="ca-mono-wrap">${escapeHtml(k.sha1)}</code> <button class="ca-copy-btn" data-copy="${escapeHtml(k.sha1)}">Copy</button></td></tr>
                <tr>
                  <td>Modulus</td>
                  <td>
                    <details>
                      <summary>Show ${k.size / 8}-byte modulus</summary>
                      <pre id="${modId}" class="ca-modulus">${chunkHex(k.modulus, 32)}</pre>
                      <button class="ca-copy-btn" data-copy="${escapeHtml(k.modulus)}">Copy modulus</button>
                    </details>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>`;
      }
    }
    listEl.innerHTML = html;

    listEl.querySelectorAll('.ca-copy-btn').forEach(btn => {
      btn.addEventListener('click', () => copyToClipboard(btn.getAttribute('data-copy'), btn));
    });
  }

  filterEl.addEventListener('change', render);
  searchEl.addEventListener('input', render);
  render();
})();
</script>
