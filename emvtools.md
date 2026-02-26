---
layout: toolpage
title: EMV Tools
permalink: /emvtools/
---

# EMV Tools

<div class="tab-container">
  <div class="tab-nav">
    <button class="tab-button active" onclick="openTool(event, 'symmetric')">Symmetric Crypto</button>
    <button class="tab-button" onclick="openTool(event, 'rsa')">RSA</button>
    <button class="tab-button" onclick="openTool(event, 'hex')">Hex Manipulator</button>
    <button class="tab-button" onclick="openTool(event, 'cps')">CPS Parser</button>
    <button class="tab-button" onclick="openTool(event, 'hash')">Hash</button>
    <button class="tab-button" onclick="openTool(event, 'emvcerts')">EMV Certificates</button>
    <button class="tab-button" onclick="openTool(event, 'emvcalcs')">EMV Calcs</button>
  </div>

  <div id="symmetric" class="tab-content" style="display:block;">
    <h2>Symmetric Crypto</h2>
    <p>Tools for symmetric key cryptography (e.g., AES, DES). Provide input fields for plaintext/ciphertext, key, IV, and options for algorithm, mode, and padding.</p>
    <!-- UI for Symmetric Crypto will go here -->
  </div>

  <div id="rsa" class="tab-content">
    <h2>RSA</h2>
    <p>Perform raw RSA operations. All inputs and outputs are ASCII HEX. Ensure your data, when converted to a number, is less than the modulus.</p>

    <div class="form-group">
      <label for="rsaModulus" class="form-label">Modulus (N - HEX):</label>
      <textarea id="rsaModulus" rows="3" class="tool-textarea"></textarea>
    </div>

    <div class="form-group">
      <label for="rsaPublicExponent" class="form-label">Public Exponent (e - HEX):</label>
      <textarea id="rsaPublicExponent" rows="2" class="tool-textarea" placeholder="e.g., 03 or 010001"></textarea>
    </div>

    <div class="form-group">
      <label for="rsaPrivateExponent" class="form-label">Private Exponent (d - HEX):</label>
      <textarea id="rsaPrivateExponent" rows="3" class="tool-textarea"></textarea>
    </div>

    <div class="form-group">
      <label for="rsaData" class="form-label">Data (Input - HEX):</label>
      <textarea id="rsaData" rows="4" class="tool-textarea"></textarea>
    </div>

    <button id="rsaPublicOpBtn" class="tool-btn tool-btn-spaced">Perform Public Operation (e)</button>
    <button id="rsaPrivateOpBtn" class="tool-btn">Perform Private Operation (d)</button>

    <div class="result-section">
      <label for="rsaResult" class="form-label">Result (Output - HEX):</label>
      <textarea id="rsaResult" rows="4" class="tool-textarea tool-textarea-readonly" readonly></textarea>
    </div>
    <div id="rsaError" class="error-message"></div>
    <div id="rsaWarning" class="error-message" style="color: #f59e0b;"></div>

  </div>

  <div id="hex" class="tab-content">
    <h2>Hex Manipulator</h2>
    <p>Upload a binary file to view its content as a continuous block of ASCII HEX. Click inside the text area to see cursor offsets. You can edit the text to add formatting (spaces, newlines).</p>
    <div class="form-group">
      <input type="file" id="hexFile">
    </div>
    <textarea id="hexOutput" class="tool-textarea hex-output"></textarea>
    <div class="button-row">
      <button id="addSpacesBtn" type="button" class="tool-btn">Add spaces between bytes</button>
      <button id="removeWhitespaceBtn" type="button" class="tool-btn">Remove all whitespace</button>
      <label class="parity-label">Parity:
        <select id="parityTypeSelect" class="parity-select">
          <option value="even">Even</option>
          <option value="odd">Odd</option>
        </select>
      </label>
      <button id="changeParityBtn" type="button" class="tool-btn" disabled>Change Parity</button>
    </div>
    <div id="hexOffsetInfo" class="info-display">
      Cursor: Char 0 | Byte 0
    </div>
    <div id="hexSelectionInfo" class="info-display-sm">
      Selected: 0 Chars | 0 Bytes
    </div>
  </div>

  <div id="cps" class="tab-content">
    <h2>CPS Parser</h2>
    <p>Extract and parse EMV CPS DGI data from personalization files. This tool locates binary card data between configurable ASCII delimiters and formats it for easy analysis.</p>

    <div class="config-panel">
      <h4>File Configuration</h4>
      <div class="form-group">
        <label class="form-label">Start Delimiter:</label>
        <input type="text" id="cpsStartDelimiter" value="#SMC#1[" class="input-md">
      </div>
      <div class="form-group">
        <label class="form-label">End Delimiter:</label>
        <input type="text" id="cpsEndDelimiter" value="#END#" class="input-sm">
      </div>
      <div class="form-group">
        <label for="cpsFile" class="form-label">Select CPS Personalization File:</label>
        <input type="file" id="cpsFile">
      </div>
      <button id="extractCpsBtn" type="button" class="tool-btn-primary">Extract & Parse CPS Data</button>
      <div id="cpsError" class="info-display" style="font-weight: bold;"></div>
    </div>

    <div class="form-group">
      <label for="cpsOutput" class="form-label">Parsed CPS Data:</label>
      <textarea id="cpsOutput" class="tool-textarea cps-output" readonly></textarea>
    </div>

    <div class="button-row">
      <button id="cpsCopyToHexBtn" type="button" class="tool-btn tool-btn-spaced">Copy to Hex Manipulator</button>
      <button id="cpsDownloadBtn" type="button" class="tool-btn" disabled>Download Binary Data</button>
    </div>
  </div>

  <div id="hash" class="tab-content">
    <h2>Hash Calculation</h2>
    <p>Calculate cryptographic hashes. Input data as ASCII HEX.</p>

    <div class="form-group">
      <label for="hashAlgorithm" class="form-label">Select Hash Algorithm:</label>
      <select id="hashAlgorithm" class="tool-select">
        <option value="sha1">SHA-1</option>
        <option value="sha256">SHA-256</option>
      </select>
    </div>

    <div class="form-group">
      <label for="hashInput" class="form-label">Input Data (HEX):</label>
      <textarea id="hashInput" rows="4" class="tool-textarea"></textarea>
    </div>

    <button id="calculateHashBtn" class="tool-btn">Calculate Hash</button>

    <div class="result-section">
      <label for="hashResult" class="form-label">Hash Result (HEX):</label>
      <textarea id="hashResult" rows="3" class="tool-textarea tool-textarea-readonly" readonly></textarea>
    </div>
    <div id="hashError" class="error-message"></div>

  </div>

  <div id="emvcerts" class="tab-content">
    <h2>EMV Certificates</h2>
    <label for="emvCertSelect" class="form-label">Select Certificate Tool:</label>
    <select id="emvCertSelect" class="tool-select-md">
      <option value="parseIssuerCert" selected>Parse Issuer Certificate</option>
      <option value="validateIssuerCert">Validate Issuer Certificate</option>
      <option value="validateCsrResponse">Validate CSR Response</option>
      <option value="parseIccCert">Parse ICC Certificate (TBD)</option>
      <option value="keysetValidation">Keyset Validation</option>
    </select>

    <div id="parseIssuerCertTool" class="emv-tool-section">
      <h3>Parse Issuer Certificate</h3>
      <p>Parse an already "opened" (RSA-decrypted) Issuer Public Key Certificate. Paste the recovered certificate data including header (6A) and trailer (BC).</p>

      <div class="form-group">
        <label for="openedIssuerCert" class="form-label">Opened Certificate Data (HEX):</label>
        <textarea id="openedIssuerCert" rows="5" class="tool-textarea" placeholder="6A02...BC"></textarea>
      </div>

      <div class="form-group">
        <label for="issuerPkRemainder" class="form-label">Issuer Public Key Remainder (HEX, optional):</label>
        <textarea id="issuerPkRemainder" rows="2" class="tool-textarea" placeholder="Optional - if public key exceeds certificate capacity"></textarea>
      </div>

      <div class="form-group">
        <label for="issuerPkExponent" class="form-label">Issuer Public Key Exponent (HEX, optional):</label>
        <input id="issuerPkExponent" class="tool-textarea input-lg" value="03" />
      </div>

      <button id="parseIssuerCertBtn" type="button" class="tool-btn-primary">Parse Certificate</button>

      <div class="result-section">
        <h4>Parsed Certificate Fields:</h4>
        <table id="issuerCertParsedTable" class="summary-table">
          <tbody>
            <tr><td>Header</td><td id="parsedHeader">-</td></tr>
            <tr><td>Certificate Format</td><td id="parsedCertFormat">-</td></tr>
            <tr><td>Issuer Identifier</td><td id="parsedIssuerId">-</td></tr>
            <tr><td>Certificate Expiration (MMYY)</td><td id="parsedExpDate">-</td></tr>
            <tr><td>Certificate Serial Number</td><td id="parsedSerial">-</td></tr>
            <tr><td>Hash Algorithm</td><td id="parsedHashAlg">-</td></tr>
            <tr><td>Public Key Algorithm</td><td id="parsedPkAlg">-</td></tr>
            <tr><td>Public Key Length</td><td id="parsedPkLen">-</td></tr>
            <tr><td>Public Key Exponent Length</td><td id="parsedExpLen">-</td></tr>
            <tr><td>Issuer Public Key (from cert)</td><td id="parsedPkData">-</td></tr>
            <tr><td>Padding</td><td id="parsedPadding">-</td></tr>
            <tr><td>Hash Result (from cert)</td><td id="parsedHash">-</td></tr>
            <tr><td>Trailer</td><td id="parsedTrailer">-</td></tr>
          </tbody>
        </table>

        <h4>Reconstructed Issuer Public Key:</h4>
        <textarea id="reconstructedPk" rows="3" class="tool-textarea tool-textarea-readonly" readonly></textarea>

        <h4>Hash Verification:</h4>
        <div id="hashVerificationResult" class="info-display"></div>
      </div>
      <div id="parseIssuerCertError" class="error-message"></div>
    </div>

    <div id="validateIssuerCertTool" class="emv-tool-section">
      <h3>Validate Issuer Certificate</h3>
      <p>Validate an Issuer Public Key Certificate by performing RSA recovery using the CA Public Key.</p>
      <div class="form-group">
        <label><input type="checkbox" id="autoDetectCaKey" checked /> Auto-detect CA Public Key</label>
      </div>
      <div id="manualCaKeySection" style="display:none;">
        <div class="form-group">
          <label for="caKeySelect" class="form-label">Select CA Public Key:</label>
          <select id="caKeySelect" class="tool-select">
            <option value="">-- Manual Entry --</option>
          </select>
        </div>
        <div class="form-group">
          <label for="manualCaExp" class="form-label">CA Exponent (HEX):</label>
          <input id="manualCaExp" class="tool-textarea input-lg" value="03" />
        </div>
        <div class="form-group">
          <label for="manualCaModulus" class="form-label">CA Modulus (HEX):</label>
          <textarea id="manualCaModulus" class="tool-textarea" rows="3"></textarea>
        </div>
      </div>
      <div class="form-group">
        <label for="issuerCert" class="form-label">Issuer Certificate (HEX):</label>
        <textarea id="issuerCert" class="tool-textarea" rows="4"></textarea>
      </div>
      <div id="detectedCaKeySection">
        <div class="form-group">
          <label for="detectedCaKey" class="form-label">Detected CA Key:</label>
          <input id="detectedCaKey" class="tool-textarea" readonly />
        </div>
      </div>
      <div class="form-group">
        <label for="issuerRemainder" class="form-label">Issuer Public Key Remainder (HEX, optional):</label>
        <input id="issuerRemainder" class="tool-textarea" />
      </div>
      <div class="form-group">
        <label for="issuerExp" class="form-label">Issuer Public Key Exponent (HEX):</label>
        <input id="issuerExp" class="tool-textarea input-lg" value="03" />
      </div>
      <button id="validateIssuerCertBtn" type="button" class="tool-btn-primary">Validate Certificate</button>
      <div class="form-group result-section">
        <label for="issuerCertResults" class="form-label">Results:</label>
        <textarea id="issuerCertResults" class="tool-textarea tool-textarea-readonly" rows="12" readonly></textarea>
      </div>
    </div>

    <div id="validateCsrResponseTool" class="emv-tool-section">
      <h3>Validate CSR Response</h3>
      <p>Upload a Mastercard CSR response file (.cEF) to extract and validate the Issuer Public Key Certificate.</p>
      <div class="form-group">
        <label for="csrResponseFile" class="form-label">Upload CSR Response File (.c** where ** is the CA Key Index):</label>
        <input type="file" id="csrResponseFile" class="input-full">
      </div>
      <div id="csrFileInfo" class="info-display" style="display:none;">
        <h4>CSR Response File Info:</h4>
        <table class="summary-table">
          <tbody>
            <tr><td>BIN</td><td id="csrBin">-</td></tr>
            <tr><td>File ID</td><td id="csrFileId">-</td></tr>
            <tr><td>CA Key Index</td><td id="csrCaIndex">-</td></tr>
            <tr><td>Exponent</td><td id="csrExponent">-</td></tr>
            <tr><td>Certificate Size</td><td id="csrCertSize">-</td></tr>
          </tbody>
        </table>
        <div class="form-group">
          <label for="csrIssuerCertHex" class="form-label">Issuer Certificate (Tag 90):</label>
          <textarea id="csrIssuerCertHex" rows="4" class="tool-textarea tool-textarea-readonly" readonly></textarea>
        </div>
      </div>
      <button id="validateCsrBtn" type="button" class="tool-btn-primary" disabled>Validate Certificate</button>

      <div id="csrCertSummary" class="result-section" style="display:none;">
        <h4>Certificate Summary:</h4>
        <table class="summary-table">
          <tbody>
            <tr><td>Header</td><td id="csrParsedHeader">-</td></tr>
            <tr><td>Certificate Format</td><td id="csrParsedFormat">-</td></tr>
            <tr><td>Issuer Identifier</td><td id="csrParsedIssuerId">-</td></tr>
            <tr><td>Expiration (MMYY)</td><td id="csrParsedExpDate">-</td></tr>
            <tr><td>Serial Number</td><td id="csrParsedSerial">-</td></tr>
            <tr><td>Hash Algorithm</td><td id="csrParsedHashAlg">-</td></tr>
            <tr><td>PK Algorithm</td><td id="csrParsedPkAlg">-</td></tr>
            <tr><td>PK Length</td><td id="csrParsedPkLen">-</td></tr>
            <tr><td>PK Exponent Length</td><td id="csrParsedExpLen">-</td></tr>
            <tr><td>Trailer</td><td id="csrParsedTrailer">-</td></tr>
          </tbody>
        </table>
        <h4>Hash Verification:</h4>
        <div id="csrHashVerification" class="info-display"></div>
      </div>

      <div class="form-group result-section">
        <label for="csrValidationResults" class="form-label">Detailed Log:</label>
        <textarea id="csrValidationResults" class="tool-textarea tool-textarea-readonly" rows="14" readonly></textarea>
      </div>
      <div id="csrError" class="error-message"></div>
    </div>

    <div id="parseIccCertTool" class="emv-tool-section">
      <h3>Parse ICC Certificate (TBD)</h3>
      <p>Coming soon...</p>
    </div>

    <div id="keysetValidationTool" class="emv-tool-section">
      <h3>Keyset Validation</h3>
      <p>Upload a keysets JSON file to validate certificate expiration dates. Each certificate is recovered using the matching CA Public Key, and the expiration date embedded in the certificate is compared against the <code>CertificateExpirationDate</code> field in the JSON.</p>

      <div class="form-group">
        <label for="keysetFile" class="form-label">Upload Keysets JSON File:</label>
        <input type="file" id="keysetFile" accept=".json">
      </div>

      <button id="validateKeysetsBtn" type="button" class="tool-btn-primary" disabled>Validate Keysets</button>

      <div id="keysetProgress" class="info-display" style="display:none;"></div>

      <div id="keysetReportSection" class="result-section" style="display:none;">
        <h4>Validation Report:</h4>
        <div id="keysetSummary" class="info-display" style="margin-bottom:12px;"></div>
        <table id="keysetReportTable" class="summary-table">
          <thead>
            <tr>
              <th>BIN</th>
              <th>Keyset Name</th>
              <th>CA Index</th>
              <th>JSON Expiration</th>
              <th>Certificate Expiration</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="form-group result-section">
        <label for="keysetDetailedLog" class="form-label">Detailed Log:</label>
        <textarea id="keysetDetailedLog" class="tool-textarea tool-textarea-readonly" rows="12" readonly></textarea>
      </div>
      <div id="keysetError" class="error-message"></div>
    </div>
  </div>

  <div id="emvcalcs" class="tab-content">
    <h2>Other EMV Calculations</h2>
    <label for="emvCalcSelect" class="form-label">Select EMV Calculation Tool:</label>
    <select id="emvCalcSelect" class="tool-select-md">
      <option value="eloParser" selected>ELO Request Parser</option>
      <option value="pinBlock">PIN Block (TBD)</option>
      <option value="arqc">ARQC (TBD)</option>
    </select>

    <div id="eloParserTool" class="emv-tool-section">
      <h3>ELO Request Parser</h3>
      <p>Load an ELO binary file (<code>.req</code> extension) to parse and extract certificate information.</p>
      <div class="form-group">
        <label for="eloReqFile" class="form-label">Upload ELO Request File (.req):</label>
        <input type="file" id="eloReqFile" accept=".req" class="input-full">
      </div>
      <button id="downloadModulusBtn" type="button" class="tool-btn tool-btn-top" disabled>Download Modulus (.bin)</button>

      <h4>Certificate Summary:</h4>
      <table id="eloCertSummaryTable" class="summary-table">
        <thead>
          <tr><th colspan="2">Key Certificate Details</th></tr>
        </thead>
        <tbody>
          <tr><td>IIN/BIN</td><td id="summaryIinBin">-</td></tr>
          <tr><td>Issuer Key Index</td><td id="summaryKeyIndex">-</td></tr>
          <tr><td>Expiration Date</td><td id="summaryExpDate">-</td></tr>
          <tr><td>Key Size</td><td id="summaryKeySize">-</td></tr>
          <tr><td>Public Exponent</td><td id="summaryExponent">-</td></tr>
        </tbody>
      </table>

      <div class="result-section">
        <label for="eloReqOutput" class="form-label">Detailed Parsing Output:</label>
        <textarea id="eloReqOutput" rows="10" class="tool-textarea elo-output" readonly></textarea>
      </div>
      <div id="eloReqError" class="error-message"></div>
    </div>

    <div id="pinBlockTool" class="emv-tool-section">
      <h3>PIN Block (TBD)</h3>
      <p>Coming soon...</p>
    </div>
    <div id="arqcTool" class="emv-tool-section">
      <h3>ARQC (TBD)</h3>
      <p>Coming soon...</p>
    </div>

  </div>
</div>

<script>
function openTool(evt, toolName) {
  var i, tabcontent, tabbuttons;
  tabcontent = document.getElementsByClassName("tab-content");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }
  tabbuttons = document.getElementsByClassName("tab-button");
  for (i = 0; i < tabbuttons.length; i++) {
    tabbuttons[i].className = tabbuttons[i].className.replace(" active", "");
  }
  document.getElementById(toolName).style.display = "block";
  if (evt && evt.currentTarget) evt.currentTarget.className += " active";
}

// ===== Shared Utility Functions =====
function emvHexToBytes(hex) {
  hex = hex.replace(/\s+/g, '');
  if (hex.startsWith('0x')) hex = hex.substring(2);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function emvBytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function emvHexToBigInt(hex) {
  hex = hex.replace(/\s+/g, '');
  if (hex.startsWith('0x')) hex = hex.substring(2);
  if (hex.length === 0) return BigInt(0);
  return BigInt('0x' + hex);
}

function emvBigIntToHex(bigIntValue) {
  return bigIntValue.toString(16).toUpperCase();
}

function emvModPow(base, exp, mod) {
  let result = BigInt(1);
  base = base % mod;
  while (exp > BigInt(0)) {
    if (exp % BigInt(2) === BigInt(1)) result = (result * base) % mod;
    base = (base * base) % mod;
    exp = exp / BigInt(2);
  }
  return result;
}

async function emvCalcSHA1(dataBytes) {
  if (!window.crypto || !window.crypto.subtle) return null;
  const hashBuf = await window.crypto.subtle.digest('SHA-1', dataBytes);
  return new Uint8Array(hashBuf);
}

// Hex Manipulator Logic
let currentByteArray = null;
const hexFileInput = document.getElementById('hexFile');
const hexOutputTextarea = document.getElementById('hexOutput');
const addSpacesBtn = document.getElementById('addSpacesBtn');
const removeWhitespaceBtn = document.getElementById('removeWhitespaceBtn');
const hexOffsetInfo = document.getElementById('hexOffsetInfo');
const hexSelectionInfo = document.getElementById('hexSelectionInfo');
const changeParityBtn = document.getElementById('changeParityBtn');
const parityTypeSelect = document.getElementById('parityTypeSelect');

// Helper function to count actual hex bytes in a string, ignoring non-hex chars
function countHexBytesInString(str) {
  let byteCount = 0;
  let hexPairBuffer = '';
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (/[0-9a-fA-F]/.test(char)) {
      hexPairBuffer += char;
      if (hexPairBuffer.length === 2) {
        byteCount++;
        hexPairBuffer = '';
      }
    }
  }
  return byteCount;
}

function renderHex(byteArray, addSpaces) {
  if (!byteArray || !hexOutputTextarea) return;
  let hexString = '';
  for (let i = 0; i < byteArray.length; i++) {
    hexString += byteArray[i].toString(16).padStart(2, '0').toUpperCase();
    if (addSpaces && i < byteArray.length - 1) {
      hexString += ' ';
    }
  }
  hexOutputTextarea.value = hexString;
  updateOffsetInfo(); // Update offset info after rendering
}

function updateOffsetInfo() {
  if (!hexOutputTextarea || !hexOffsetInfo || !hexSelectionInfo) return;
  
  const cursorPos = hexOutputTextarea.selectionStart;
  const selectionEnd = hexOutputTextarea.selectionEnd;
  const textBeforeCursor = hexOutputTextarea.value.substring(0, cursorPos);
  
  const cursorByteOffset = countHexBytesInString(textBeforeCursor);
  const cursorByteOffsetHex = cursorByteOffset.toString(16).toUpperCase();
  hexOffsetInfo.textContent = `Cursor: Char ${cursorPos} | Byte ${cursorByteOffset} (0x${cursorByteOffsetHex})`;

  if (cursorPos !== selectionEnd) {
    const selectedText = hexOutputTextarea.value.substring(cursorPos, selectionEnd);
    const selectedCharCount = selectedText.length;
    const selectedByteCount = countHexBytesInString(selectedText);
    const selectedByteCountHex = selectedByteCount.toString(16).toUpperCase();
    hexSelectionInfo.textContent = `Selected: ${selectedCharCount} Chars | ${selectedByteCount} Bytes (0x${selectedByteCountHex})`;
  } else {
    hexSelectionInfo.textContent = 'Selected: 0 Chars | 0 Bytes (0x0)'; // Also show hex for zero selection
  }
}

hexFileInput?.addEventListener('change', function(event) {
  const file = event.target.files[0];
  if (!file || !hexOutputTextarea) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    currentByteArray = new Uint8Array(e.target.result);
    renderHex(currentByteArray, false);
  };
  reader.onerror = function() {
    hexOutputTextarea.value = 'Error reading file.';
    currentByteArray = null;
  };
  reader.readAsArrayBuffer(file);
});

function addSpacesBetweenBytesToText(text) {
  // Remove all whitespace
  const hex = text.replace(/\s+/g, '');
  // Add a space every two hex digits
  return hex.replace(/([0-9a-fA-F]{2})(?=[0-9a-fA-F])/g, '$1 ').trim();
}

function removeAllWhitespaceFromText(text) {
  return text.replace(/\s+/g, '');
}

addSpacesBtn?.addEventListener('click', function() {
  if (!hexOutputTextarea) return;
  const start = hexOutputTextarea.selectionStart;
  const end = hexOutputTextarea.selectionEnd;
  let value = hexOutputTextarea.value;
  if (start !== end) {
    // Operate only on the selected text
    const before = value.substring(0, start);
    const selected = value.substring(start, end);
    const after = value.substring(end);
    const newSelected = addSpacesBetweenBytesToText(selected);
    hexOutputTextarea.value = before + newSelected + after;
    // Reselect the modified text
    hexOutputTextarea.setSelectionRange(start, start + newSelected.length);
  } else {
    // Operate on the whole textarea
    const newValue = addSpacesBetweenBytesToText(value);
    hexOutputTextarea.value = newValue;
    hexOutputTextarea.setSelectionRange(0, newValue.length);
  }
  updateOffsetInfo();
});

removeWhitespaceBtn?.addEventListener('click', function() {
  if (!hexOutputTextarea) return;
  const start = hexOutputTextarea.selectionStart;
  const end = hexOutputTextarea.selectionEnd;
  let value = hexOutputTextarea.value;
  if (start !== end) {
    // Operate only on the selected text
    const before = value.substring(0, start);
    const selected = value.substring(start, end);
    const after = value.substring(end);
    const newSelected = removeAllWhitespaceFromText(selected);
    hexOutputTextarea.value = before + newSelected + after;
    // Reselect the modified text
    hexOutputTextarea.setSelectionRange(start, start + newSelected.length);
  } else {
    // Operate on the whole textarea
    const newValue = removeAllWhitespaceFromText(value);
    hexOutputTextarea.value = newValue;
    hexOutputTextarea.setSelectionRange(0, newValue.length);
  }
  updateOffsetInfo();
});

hexOutputTextarea?.addEventListener('click', updateOffsetInfo);
hexOutputTextarea?.addEventListener('keyup', updateOffsetInfo);
hexOutputTextarea?.addEventListener('input', updateOffsetInfo);

document.addEventListener('selectionchange', function() {
  if (document.activeElement === hexOutputTextarea) {
    updateOffsetInfo();
  }
});

function isFullByteSelection(text) {
  // Remove whitespace and check if at least 2 hex digits
  return text.replace(/\s+/g, '').length >= 2;
}

function setParity(byte, parityType) {
  // Count number of 1-bits in the upper 7 bits
  let bits = byte >> 1;
  let ones = 0;
  for (let i = 0; i < 7; i++) {
    if (bits & (1 << i)) ones++;
  }
  let lsb = byte & 1;
  let totalOnes = ones + lsb;
  if (parityType === 'even') {
    // Set LSB so total ones is even
    if (totalOnes % 2 !== 0) {
      byte ^= 1; // flip LSB
    }
  } else {
    // Set LSB so total ones is odd
    if (totalOnes % 2 === 0) {
      byte ^= 1; // flip LSB
    }
  }
  return byte;
}

function changeParityOfHexString(hex, parityType) {
  // Remove whitespace
  hex = hex.replace(/\s+/g, '');
  let out = '';
  for (let i = 0; i < hex.length; i += 2) {
    if (i + 2 > hex.length) break;
    let byte = parseInt(hex.substr(i, 2), 16);
    let newByte = setParity(byte, parityType);
    out += newByte.toString(16).padStart(2, '0').toUpperCase();
  }
  return out;
}

hexOutputTextarea?.addEventListener('select', function() {
  const start = hexOutputTextarea.selectionStart;
  const end = hexOutputTextarea.selectionEnd;
  const selected = hexOutputTextarea.value.substring(start, end);
  changeParityBtn.disabled = !isFullByteSelection(selected);
});
hexOutputTextarea?.addEventListener('keyup', function() {
  const start = hexOutputTextarea.selectionStart;
  const end = hexOutputTextarea.selectionEnd;
  const selected = hexOutputTextarea.value.substring(start, end);
  changeParityBtn.disabled = !isFullByteSelection(selected);
});
hexOutputTextarea?.addEventListener('input', function() {
  const start = hexOutputTextarea.selectionStart;
  const end = hexOutputTextarea.selectionEnd;
  const selected = hexOutputTextarea.value.substring(start, end);
  changeParityBtn.disabled = !isFullByteSelection(selected);
});

changeParityBtn?.addEventListener('click', function() {
  if (!hexOutputTextarea) return;
  const start = hexOutputTextarea.selectionStart;
  const end = hexOutputTextarea.selectionEnd;
  let value = hexOutputTextarea.value;
  if (start === end) return;
  const before = value.substring(0, start);
  const selected = value.substring(start, end);
  const after = value.substring(end);
  const parityType = parityTypeSelect.value;
  // Only operate on full bytes
  let changed = changeParityOfHexString(selected, parityType);
  // Add spaces if original selection had spaces between bytes
  if (/\s/.test(selected)) {
    changed = addSpacesBetweenBytesToText(changed);
  }
  hexOutputTextarea.value = before + changed + after;
  // Reselect the modified text
  hexOutputTextarea.setSelectionRange(start, start + changed.length);
  updateOffsetInfo();
});

// CPS Data Extractor Logic
const cpsFileInput = document.getElementById('cpsFile');
const extractCpsBtn = document.getElementById('extractCpsBtn');
const cpsStartDelimiterInput = document.getElementById('cpsStartDelimiter');
const cpsEndDelimiterInput = document.getElementById('cpsEndDelimiter');
const cpsErrorEl = document.getElementById('cpsError');
const cpsOutputTextarea = document.getElementById('cpsOutput');
const cpsCopyToHexBtn = document.getElementById('cpsCopyToHexBtn');
const cpsDownloadBtn = document.getElementById('cpsDownloadBtn');

let currentCpsBinaryData = null;

function formatCpsDataAsHex(binaryData) {
  if (!binaryData || binaryData.length === 0) return '';
  
  let formattedHex = '';
  let offset = 0;
  
  // Helper function to get bytes and format them
  function getBytes(count) {
    const bytes = binaryData.slice(offset, offset + count);
    offset += count;
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
  }
  
  // Helper function to get 2-byte length as number
  function getLength() {
    if (offset + 2 > binaryData.length) return 0;
    const lengthBytes = binaryData.slice(offset, offset + 2);
    offset += 2;
    return (lengthBytes[0] << 8) | lengthBytes[1];
  }
  
  try {
    formattedHex += `// CPS Data Structure (Total Length: ${binaryData.length} bytes)\n\n`;
    
    let appCount = 0;
    
    while (offset < binaryData.length) {
      appCount++;
      formattedHex += `// ===== Application ${appCount} =====\n`;
      
      // Header (10 bytes)
      if (offset + 10 > binaryData.length) break;
      const header = getBytes(10);
      formattedHex += `// Header (10 bytes):\n${header}\n\n`;
      
      // Key ID (8 bytes)
      if (offset + 8 > binaryData.length) break;
      const keyId = getBytes(8);
      formattedHex += `// Key ID (8 bytes):\n${keyId}\n\n`;
      
      // Application data length (2 bytes)
      if (offset + 2 > binaryData.length) break;
      const appDataLength = getLength();
      formattedHex += `// Application Data Length: ${appDataLength} bytes\n`;
      formattedHex += `${(appDataLength >> 8).toString(16).padStart(2, '0').toUpperCase()} ${(appDataLength & 0xFF).toString(16).padStart(2, '0').toUpperCase()}\n\n`;
      
      const appDataStart = offset;
      const appDataEnd = Math.min(offset + appDataLength, binaryData.length);
      
      // Parse application data
      formattedHex += `// Application Data (${appDataLength} bytes):\n`;
      
      // AID TLV (should start with 84)
      if (offset < appDataEnd && binaryData[offset] === 0x84) {
        const tag = getBytes(1);
        const aidLength = binaryData[offset];
        offset++;
        const aidLengthHex = aidLength.toString(16).padStart(2, '0').toUpperCase();
        const aid = getBytes(aidLength);
        formattedHex += `// AID TLV:\n${tag} ${aidLengthHex} ${aid}\n\n`;
      }
      
      // DGIs
      let dgiCount = 0;
      while (offset < appDataEnd - 12) { // Leave space for 12-byte trailer
        // Look for DGI marker 8802
        if (offset + 1 < binaryData.length && 
            binaryData[offset] === 0x88 && binaryData[offset + 1] === 0x02) {
          
          dgiCount++;
          const marker = getBytes(2); // 8802
          
          if (offset + 3 > binaryData.length) break;
          const dgiTag = getBytes(2);
          const dgiLength = binaryData[offset];
          offset++;
          const dgiLengthHex = dgiLength.toString(16).padStart(2, '0').toUpperCase();
          
          formattedHex += `// DGI ${dgiCount} (Tag: ${dgiTag}, Length: ${dgiLength}):\n`;
          formattedHex += `${marker} ${dgiTag} ${dgiLengthHex}`;
          
          if (dgiLength > 0 && offset + dgiLength <= binaryData.length) {
            const dgiData = getBytes(dgiLength);
            formattedHex += ` ${dgiData}`;
          }
          formattedHex += '\n\n';
        } else {
          // Skip unknown byte
          offset++;
        }
      }
      
      // Skip to end of application data and read trailing 12 bytes
      offset = appDataEnd - 12;
      if (offset >= 0 && offset + 12 <= binaryData.length) {
        const trailer = getBytes(12);
        formattedHex += `// Trailing 12 bytes (hash/padding):\n${trailer}\n\n`;
      }
      
      offset = appDataEnd;
    }
    
    return formattedHex;
    
  } catch (error) {
    return `// Error parsing CPS data: ${error.message}\n\n` + 
           Array.from(binaryData).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
  }
}

extractCpsBtn?.addEventListener('click', function() {
  const file = cpsFileInput.files[0];
  if (!file) {
    cpsErrorEl.textContent = 'Please select a file first.';
    return;
  }
  
  cpsErrorEl.textContent = '';
  
  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      // Read file as text first to find delimiters
      const textData = new TextDecoder('utf-8').decode(e.target.result);
      const startDelimiter = cpsStartDelimiterInput.value || '#SMC#1[';
      const endDelimiter = cpsEndDelimiterInput.value || '#END#';
      
      // Find first occurrence of start delimiter
      const startIndex = textData.indexOf(startDelimiter);
      if (startIndex === -1) {
        cpsErrorEl.textContent = `Start delimiter "${startDelimiter}" not found in file.`;
        return;
      }
      
      // Find first occurrence of end delimiter after start
      const endIndex = textData.indexOf(endDelimiter, startIndex + startDelimiter.length);
      if (endIndex === -1) {
        cpsErrorEl.textContent = `End delimiter "${endDelimiter}" not found after start delimiter.`;
        return;
      }
      
      // Extract the content between delimiters
      const delimiterContent = textData.substring(startIndex + startDelimiter.length, endIndex);
      
      // First 6 characters should be the decimal length
      if (delimiterContent.length < 6) {
        cpsErrorEl.textContent = 'Content between delimiters is too short to contain length field.';
        return;
      }
      
      const lengthStr = delimiterContent.substring(0, 6);
      const expectedLength = parseInt(lengthStr, 10);
      
      if (isNaN(expectedLength)) {
        cpsErrorEl.textContent = `Invalid length field: "${lengthStr}" (should be 6 decimal digits).`;
        return;
      }
      
      // Convert the file content to bytes for binary extraction
      const fileBytes = new Uint8Array(e.target.result);
      
      // Find binary data start position (after length field)
      const binaryStartInText = startIndex + startDelimiter.length + 6;
      const binaryStartInBytes = new TextEncoder().encode(textData.substring(0, binaryStartInText)).length;
      
      // Extract binary data
      const binaryData = fileBytes.slice(binaryStartInBytes, binaryStartInBytes + expectedLength);
      
      if (binaryData.length !== expectedLength) {
        cpsErrorEl.textContent = `Binary data length mismatch. Expected: ${expectedLength}, Found: ${binaryData.length}`;
        return;
      }
      
             // Store binary data for download
       currentCpsBinaryData = binaryData;
       
       // Format and display the data
       const formattedHex = formatCpsDataAsHex(binaryData);
       if (cpsOutputTextarea) {
         cpsOutputTextarea.value = formattedHex;
       }
       
       // Enable download button
       if (cpsDownloadBtn) {
         cpsDownloadBtn.disabled = false;
       }
       
       cpsErrorEl.style.color = '#22c55e';
       cpsErrorEl.textContent = `Successfully extracted ${expectedLength} bytes of CPS data with ${formattedHex.split('Application').length - 1} applications.`;
      
    } catch (error) {
      cpsErrorEl.textContent = `Error processing file: ${error.message}`;
      console.error('CPS extraction error:', error);
    }
  };
  
  reader.onerror = function() {
    cpsErrorEl.textContent = 'Error reading file.';
  };
  
  reader.readAsArrayBuffer(file);
});

// Copy CPS data to Hex Manipulator
cpsCopyToHexBtn?.addEventListener('click', function() {
  if (!cpsOutputTextarea || !hexOutputTextarea) {
    if (cpsErrorEl) {
      cpsErrorEl.style.color = '#ef4444';
      cpsErrorEl.textContent = 'Error: Unable to access hex manipulator.';
    }
    return;
  }
  
  if (!cpsOutputTextarea.value) {
    if (cpsErrorEl) {
      cpsErrorEl.style.color = '#ef4444';
      cpsErrorEl.textContent = 'No CPS data to copy. Please extract data first.';
    }
    return;
  }
  
  // Copy the formatted data to hex manipulator
  hexOutputTextarea.value = cpsOutputTextarea.value;
  updateOffsetInfo();
  
  // Switch to hex manipulator tab
  openTool(null, 'hex');
  
  if (cpsErrorEl) {
    cpsErrorEl.style.color = '#22c55e';
    cpsErrorEl.textContent = 'CPS data copied to Hex Manipulator successfully!';
  }
});

// Download binary CPS data
cpsDownloadBtn?.addEventListener('click', function() {
  if (!currentCpsBinaryData) {
    if (cpsErrorEl) {
      cpsErrorEl.style.color = '#ef4444';
      cpsErrorEl.textContent = 'No binary data available. Please extract CPS data first.';
    }
    return;
  }
  
  try {
    const blob = new Blob([currentCpsBinaryData], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cps_data.bin';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    if (cpsErrorEl) {
      cpsErrorEl.style.color = '#22c55e';
      cpsErrorEl.textContent = 'Binary data downloaded successfully!';
    }
  } catch (error) {
    if (cpsErrorEl) {
      cpsErrorEl.style.color = '#ef4444';
      cpsErrorEl.textContent = `Download failed: ${error.message}`;
    }
  }
});

// RSA Tool Logic
const rsaModulusEl = document.getElementById('rsaModulus');
const rsaPublicExponentEl = document.getElementById('rsaPublicExponent');
const rsaPrivateExponentEl = document.getElementById('rsaPrivateExponent');
const rsaDataEl = document.getElementById('rsaData');
const rsaResultEl = document.getElementById('rsaResult');
const rsaPublicOpBtn = document.getElementById('rsaPublicOpBtn');
const rsaPrivateOpBtn = document.getElementById('rsaPrivateOpBtn');
const rsaErrorEl = document.getElementById('rsaError');
const rsaWarningEl = document.getElementById('rsaWarning');

// RSA uses shared utility functions (emvHexToBigInt, emvBigIntToHex, emvModPow)

function performRsaOperation(operationType) {
  rsaErrorEl.textContent = '';
  rsaWarningEl.textContent = '';
  rsaResultEl.value = '';
  try {
    const modulusHex = rsaModulusEl.value.trim().replace(/\s+/g, '');
    const dataHex = rsaDataEl.value.trim().replace(/\s+/g, '');
    let exponentHex = '';

    if (operationType === 'public') {
      exponentHex = rsaPublicExponentEl.value.trim().replace(/\s+/g, '');
    } else if (operationType === 'private') {
      exponentHex = rsaPrivateExponentEl.value.trim().replace(/\s+/g, '');
    } else {
      rsaErrorEl.textContent = 'Invalid operation type.';
      return;
    }

    if (!modulusHex || !dataHex) {
      rsaErrorEl.textContent = 'Modulus and Data fields cannot be empty.';
      return;
    }

    if (!exponentHex) {
      rsaErrorEl.textContent = `${operationType === 'public' ? 'Public' : 'Private'} Exponent cannot be empty.`;
      return;
    }

    if (!/^[0-9a-fA-F]+$/.test(exponentHex.replace(/^0x/, '')) ||
        !/^[0-9a-fA-F]+$/.test(modulusHex.replace(/^0x/, '')) ||
        !/^[0-9a-fA-F]+$/.test(dataHex.replace(/^0x/, ''))) {
      rsaErrorEl.textContent = 'Inputs must be valid HEX strings (0-9, A-F).';
      return;
    }

    const exponent = emvHexToBigInt(exponentHex);
    const modulus = emvHexToBigInt(modulusHex);
    const data = emvHexToBigInt(dataHex);

    if (modulus <= BigInt(0)) {
      rsaErrorEl.textContent = 'Modulus must be positive.';
      return;
    }
    if (data >= modulus) {
      rsaWarningEl.textContent = 'Warning: Data is greater than or equal to the modulus. This is not standard RSA usage.';
    }

    const resultBigInt = emvModPow(data, exponent, modulus);
    rsaResultEl.value = emvBigIntToHex(resultBigInt);

  } catch (e) {
    rsaErrorEl.textContent = 'Error: ' + e.message;
    console.error("RSA Error:", e);
  }
}

rsaPublicOpBtn?.addEventListener('click', function() { performRsaOperation('public'); });
rsaPrivateOpBtn?.addEventListener('click', function() { performRsaOperation('private'); });

// Hash Tool Logic (using SubtleCrypto)
const hashAlgorithmEl = document.getElementById('hashAlgorithm');
const hashInputEl = document.getElementById('hashInput');
const calculateHashBtn = document.getElementById('calculateHashBtn');
const hashResultEl = document.getElementById('hashResult');
const hashErrorEl = document.getElementById('hashError');

// Hash tool uses shared emvHexToBytes/emvBytesToHex

async function performHashCalculation() { // Now an async function
  hashErrorEl.textContent = '';
  hashResultEl.value = '';

  if (!window.crypto || !window.crypto.subtle) {
    hashErrorEl.textContent = 'Web Crypto API (SubtleCrypto) is not available in this browser.';
    console.error("SubtleCrypto not available.");
    return;
  }

  try {
    const selectedAlgorithm = hashAlgorithmEl.value;
    // Strip whitespace before validation!
    let hexInput = hashInputEl.value.trim().replace(/\s+/g, '');

    if (hexInput.length === 0) { // Allow empty string input for hashing
        // Some APIs might produce a hash for an empty input, some might not. 
        // SubtleCrypto does produce a hash for an empty ArrayBuffer.
    } else if (!/^[0-9a-fA-F]+$/.test(hexInput) || hexInput.length % 2 !== 0) {
      hashErrorEl.textContent = 'Input Data must be a valid HEX string with an even number of characters (full bytes).';
      return;
    }

    const dataBuffer = emvHexToBytes(hexInput).buffer;
    let algorithmName = '';

    switch (selectedAlgorithm) {
      case 'sha1':
        algorithmName = 'SHA-1';
        break;
      case 'sha256':
        algorithmName = 'SHA-256';
        break;
      // Add more cases for other algorithms like SHA-384, SHA-512 if needed
      // e.g., case 'sha384': algorithmName = 'SHA-384'; break;
      default:
        hashErrorEl.textContent = 'Invalid hash algorithm selected.';
        return;
    }

    const hashBuffer = await window.crypto.subtle.digest(algorithmName, dataBuffer);
    hashResultEl.value = emvBytesToHex(new Uint8Array(hashBuffer));

  } catch (e) {
    hashErrorEl.textContent = 'Error: ' + e.message;
    console.error("Hash Calculation Error:", e);
  }
}

calculateHashBtn?.addEventListener('click', performHashCalculation);

// ELO Request Parser Logic
const eloReqFileInput = document.getElementById('eloReqFile');
const eloReqOutputTextarea = document.getElementById('eloReqOutput');
const eloReqErrorEl = document.getElementById('eloReqError');
const downloadModulusBtn = document.getElementById('downloadModulusBtn');

// Summary Table Cell IDs
const summaryFields = {
    iinBin: document.getElementById('summaryIinBin'),
    keyIndex: document.getElementById('summaryKeyIndex'),
    expDate: document.getElementById('summaryExpDate'),
    keySize: document.getElementById('summaryKeySize'),
    exponent: document.getElementById('summaryExponent')
};

let currentModulusBytes = null;
let currentFileNameBase = 'key';

function resetSummaryTable() {
    for (const key in summaryFields) {
        if (summaryFields[key]) summaryFields[key].textContent = '-';
    }
    if (summaryFields.iinBin) summaryFields.iinBin.textContent = 'N/A - File specific';
}

function bcdToDec(val) {
  return (val >> 4) * 10 + (val & 0x0F);
}

// ELO parser uses shared emvBytesToHex

eloReqFileInput?.addEventListener('change', function(event) {
  const file = event.target.files[0];
  currentModulusBytes = null;
  if (downloadModulusBtn) downloadModulusBtn.disabled = true;
  resetSummaryTable();

  if (!file || !eloReqOutputTextarea || !eloReqErrorEl) return;

  currentFileNameBase = file.name.split('.').slice(0, -1).join('.') || 'key';
  eloReqOutputTextarea.value = 'Processing...';

  if (!file.name.toLowerCase().endsWith('.req')) {
    eloReqErrorEl.textContent = 'Invalid file type. Please upload a .req file.';
    eloReqFileInput.value = ''; 
    eloReqOutputTextarea.value = '';
    return;
  }

  const reader = new FileReader();
  reader.onload = function(e) {
    let output = `File: ${file.name} (${file.size} bytes)\n\n`;
    const errors = [];
    try {
      const fileBytes = new Uint8Array(e.target.result);
      const dataView = new DataView(fileBytes.buffer);
      let offset = 0;

      if (fileBytes.byteLength < 30) { // Minimum plausible length check
        throw new Error('File is too short to be a valid ELO request.');
      }

      // 1. Certificate format header (1 byte)
      const certFormatHeader = dataView.getUint8(offset);
      offset += 1;
      output += `Certificate Format Header: 0x${certFormatHeader.toString(16).padStart(2, '0').toUpperCase()}\n`;
      if (certFormatHeader !== 0x20) {
        errors.push("Warning: Certificate Format Header is not 0x20.");
      }

      // 2. IIN/BIN (4 bytes)
      if (offset + 4 > fileBytes.byteLength) throw new Error("File too short for IIN/BIN.");
      const iinBinBytes = new Uint8Array(fileBytes.buffer, offset, 4);
      offset += 4;
      const iinBinHex = emvBytesToHex(iinBinBytes);
      output += `IIN/BIN: ${iinBinHex}\n`;
      if (summaryFields.iinBin) summaryFields.iinBin.textContent = iinBinHex;

      // 3. Issuer Key Index (3 bytes)
      if (offset + 3 > fileBytes.byteLength) throw new Error("File too short for Issuer Key Index.");
      const issuerKeyIndexBytes = new Uint8Array(fileBytes.buffer, offset, 3);
      offset += 3;
      const issuerKeyIndexHex = emvBytesToHex(issuerKeyIndexBytes);
      output += `Issuer Key Index: ${issuerKeyIndexHex}\n`;
      if (summaryFields.keyIndex) summaryFields.keyIndex.textContent = issuerKeyIndexHex;

      // 4. Exp Date (2 bytes - MMYY in file)
      if (offset + 2 > fileBytes.byteLength) throw new Error("File too short for Expiry Date.");
      const expMonthBcdByte = dataView.getUint8(offset); // MM byte from file
      const expYearBcdByte = dataView.getUint8(offset + 1); // YY byte from file
      offset += 2;
      
      const actualMonth = bcdToDec(expMonthBcdByte);
      const actualYear = bcdToDec(expYearBcdByte);

      const expMonthStr = actualMonth.toString().padStart(2,'0'); 
      const expYearStr = actualYear.toString().padStart(2,'0'); 
      const formattedExpDate = `${expMonthStr}/20${expYearStr}`;
      // Display raw hex bytes as they appear in file (MM then YY) for MMYY_raw_bytes part
      output += `Expiry Date (MMYY_raw_bytes): ${expMonthBcdByte.toString(16).padStart(2,'0').toUpperCase()}${expYearBcdByte.toString(16).padStart(2,'0').toUpperCase()} (Interpreted MM/YYYY: ${formattedExpDate})\n`;
      if (summaryFields.expDate) summaryFields.expDate.textContent = formattedExpDate;

      // 5. Hash Format (1 byte)
      if (offset + 1 > fileBytes.byteLength) throw new Error("File too short for Hash Format.");
      const hashFormat = dataView.getUint8(offset);
      offset += 1;
      output += `Hash Format: 0x${hashFormat.toString(16).padStart(2, '0').toUpperCase()}`;
      if (hashFormat === 0x01) {
        output += " (SHA-1)\n";
      } else {
        output += " (Unknown/Invalid)\n";
        errors.push("Warning: Hash Format is not 0x01 (SHA-1).");
      }

      // 6. Key Type (1 byte)
      if (offset + 1 > fileBytes.byteLength) throw new Error("File too short for Key Type.");
      const keyType = dataView.getUint8(offset);
      offset += 1;
      output += `Key Type: 0x${keyType.toString(16).padStart(2, '0').toUpperCase()}`;
      if (keyType === 0x01) {
        output += " (RSA)\n";
      } else {
        output += " (Unknown/Invalid)\n";
        errors.push("Warning: Key Type is not 0x01 (RSA).");
      }

      // 7. Length of Modulus (LM - 1 byte)
      if (offset + 1 > fileBytes.byteLength) throw new Error("File too short for Modulus Length.");
      const modulusLength = dataView.getUint8(offset);
      offset += 1;
      const modulusLengthBits = modulusLength * 8;
      output += `Length of Modulus (LM): ${modulusLength} bytes (0x${modulusLength.toString(16).padStart(2, '0').toUpperCase()}) (${modulusLengthBits} bits)\n`;
      if (summaryFields.keySize) summaryFields.keySize.textContent = `${modulusLength} bytes / ${modulusLengthBits} bits`;

      // 8. Modulus (LM bytes)
      if (offset + modulusLength > fileBytes.byteLength) throw new Error("File too short for Modulus.");
      const modulusBytes = new Uint8Array(fileBytes.buffer, offset, modulusLength);
      currentModulusBytes = modulusBytes; // Store for download
      const modulusHex = emvBytesToHex(modulusBytes);
      offset += modulusLength; // <<< CRITICAL FIX: Advance offset by modulus length
      output += `Modulus (N):\n${modulusHex}\n`;

      // 9. Length of Exponent (LE - 1 byte)
      if (offset + 1 > fileBytes.byteLength) throw new Error("File too short for Exponent Length.");
      const exponentLength = dataView.getUint8(offset);
      offset += 1;
      output += `Length of Exponent (LE): ${exponentLength} (0x${exponentLength.toString(16).padStart(2, '0').toUpperCase()})\n`;

      // 10. Exponent (LE bytes)
      if (offset + exponentLength > fileBytes.byteLength) throw new Error("File too short for Exponent.");
      const exponentBytes = new Uint8Array(fileBytes.buffer, offset, exponentLength);
      const exponentHex = emvBytesToHex(exponentBytes);
      offset += exponentLength;
      output += `Exponent (e): ${exponentHex}\n`;
      if (summaryFields.exponent) summaryFields.exponent.textContent = exponentHex.startsWith('0') && exponentHex.length > 1 ? exponentHex.substring(1) : exponentHex; // Remove leading 0 if present, like 03 -> 3

      // 11. HASH (20 bytes of SHA1 hash)
      if (offset + 20 > fileBytes.byteLength) throw new Error("File too short for HASH.");
      const hashBytes = new Uint8Array(fileBytes.buffer, offset, 20);
      const providedHashHex = emvBytesToHex(hashBytes);
      offset += 20;
      output += `Provided HASH (SHA-1):\n${providedHashHex}\n`;

      // 12. SelfSignedCertificate (LM bytes)
      if (offset + modulusLength > fileBytes.byteLength) throw new Error("File too short for SelfSignedCertificate.");
      const selfSignedCertificateBytes = new Uint8Array(fileBytes.buffer, offset, modulusLength);
      const selfSignedCertificateHex = emvBytesToHex(selfSignedCertificateBytes);
      offset += modulusLength;
      output += `SelfSignedCertificate (Encrypted/Signed Data Block):\n${selfSignedCertificateHex}\n`;

      output += "\n--- RSA Decryption/Recovery of SelfSignedCertificate ---\n";
      try {
        const N_rsa = emvHexToBigInt(modulusHex);
        const e_rsa = emvHexToBigInt(exponentHex);
        const C_rsa = emvHexToBigInt(selfSignedCertificateHex);

        if (N_rsa <= BigInt(0)) throw new Error("Modulus must be positive for RSA.");
        if (e_rsa <= BigInt(0)) throw new Error("Exponent must be positive for RSA.");
        if (C_rsa >= N_rsa) errors.push("Warning: SelfSignedCertificate data is numerically >= Modulus. This is unusual for RSA encrypted/signed blocks.");

        const openedDataBigInt = emvModPow(C_rsa, e_rsa, N_rsa); // emvModPow(base, exp, mod)
        let openedDataHex = emvBigIntToHex(openedDataBigInt);
        // Pad to ensure it represents the full modulus length
        if (openedDataHex.length < modulusLength * 2) {
          openedDataHex = openedDataHex.padStart(modulusLength * 2, '0');
        }
        output += `Opened/Recovered Data (SelfSignedCertificate ^ Exponent mod Modulus):\n${openedDataHex.toUpperCase()}\n`;
        output += `\nVerification Steps (Placeholder based on common EMV patterns):
`;
        output += `1. The 'Opened/Recovered Data' above should be parsed according to its own internal format.
`;
        output += `2. Typically, this internal format includes: a header byte (e.g., 0x6A), certificate format, various data fields, an *embedded* HASH (e.g., 20 bytes SHA-1), and a trailer byte (e.g., 0xBC).
`;
        output += `3. The *embedded* HASH should be the SHA-1 of a concatenation of preceding data fields within the 'Opened/Recovered Data' (and potentially other linked data like public key components if they were split).
`;
        output += `4. Compare the calculated hash (from step 3) with the *embedded* HASH. They must match for integrity.
`;
        output += `5. The 'Provided HASH' (${providedHashHex}) from the input file needs its role clarified. It might be identical to the *embedded* HASH, or a hash of the data that *formed* the SelfSignedCertificate block before the RSA operation. Further specification is needed for full verification against this 'Provided HASH'.\n`;

      } catch (rsaErr) {
        output += `Error during RSA operation: ${rsaErr.message}\n`;
        errors.push(`RSA Operation Error: ${rsaErr.message}`);
      }

      if (offset < fileBytes.byteLength) {
        output += `\nWarning: ${fileBytes.byteLength - offset} trailing bytes found in the file after parsing all expected fields.\n`;
        errors.push(`Warning: ${fileBytes.byteLength - offset} trailing bytes found.`);
      } else if (offset > fileBytes.byteLength) {
        throw new Error("Offset exceeded file length during parsing. Logic error or malformed file.");
      }

      eloReqOutputTextarea.value = output;
      if (errors.length > 0) {
        eloReqErrorEl.textContent = errors.join("\n");
      } else {
        eloReqErrorEl.textContent = "Parsing and RSA operation successful.";
        if (downloadModulusBtn && currentModulusBytes) downloadModulusBtn.disabled = false;
      }

    } catch (parseErr) {
      eloReqOutputTextarea.value = output + `\n\nCritical Error: ${parseErr.message}`;
      eloReqErrorEl.textContent = `Error: ${parseErr.message}`;
      console.error('ELO Request Parser Error:', parseErr);
    }
  };
  reader.onerror = function() {
    eloReqErrorEl.textContent = 'Error reading file.';
    eloReqOutputTextarea.value = 'Error reading file.';
  };
  reader.readAsArrayBuffer(file);
});

downloadModulusBtn?.addEventListener('click', function() {
    if (currentModulusBytes && currentModulusBytes.length > 0) {
        const blob = new Blob([currentModulusBytes], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${currentFileNameBase}.bin`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } else {
        eloReqErrorEl.textContent = 'No modulus data available to download.';
    }
});

// Open the first tab by default on page load
document.addEventListener('DOMContentLoaded', function() {
  var firstTabButton = document.querySelector('.tab-button.active'); 
  if (!firstTabButton) firstTabButton = document.querySelector('.tab-button'); // Fallback to the first tab button if none are active
  
  if (firstTabButton) {
    const toolName = firstTabButton.getAttribute('onclick').match(/openTool\(event, '([^']*)'\)/)[1];
    if (toolName) {
        openTool(null, toolName); // Open the tool content
        if (!firstTabButton.classList.contains('active')) { // Ensure the button is marked active
            firstTabButton.className += ' active';
        }
    }
  }

  // Initialize visibility for EMV Calc sub-tools based on the <select> default
  const emvCalcSelectInitial = document.getElementById('emvCalcSelect');
  const eloParserToolInitial = document.getElementById('eloParserTool');
  const pinBlockToolInitial = document.getElementById('pinBlockTool');
  const arqcToolInitial = document.getElementById('arqcTool');

  if (emvCalcSelectInitial) {
    const selectedValue = emvCalcSelectInitial.value;
    if(eloParserToolInitial) eloParserToolInitial.style.display = selectedValue === 'eloParser' ? 'block' : 'none';
    if(pinBlockToolInitial) pinBlockToolInitial.style.display = selectedValue === 'pinBlock' ? 'block' : 'none';
    if(arqcToolInitial) arqcToolInitial.style.display = selectedValue === 'arqc' ? 'block' : 'none';
  }

  // Initialize visibility for EMV Certificates sub-tools
  const emvCertSelectInitial = document.getElementById('emvCertSelect');
  const parseIssuerCertToolInitial = document.getElementById('parseIssuerCertTool');
  const validateIssuerCertToolInitial = document.getElementById('validateIssuerCertTool');
  const validateCsrResponseToolInitial = document.getElementById('validateCsrResponseTool');
  const parseIccCertToolInitial = document.getElementById('parseIccCertTool');
  const keysetValidationToolInitial = document.getElementById('keysetValidationTool');

  if (emvCertSelectInitial) {
    const selectedCertValue = emvCertSelectInitial.value;
    if(parseIssuerCertToolInitial) parseIssuerCertToolInitial.style.display = selectedCertValue === 'parseIssuerCert' ? 'block' : 'none';
    if(validateIssuerCertToolInitial) validateIssuerCertToolInitial.style.display = selectedCertValue === 'validateIssuerCert' ? 'block' : 'none';
    if(validateCsrResponseToolInitial) validateCsrResponseToolInitial.style.display = selectedCertValue === 'validateCsrResponse' ? 'block' : 'none';
    if(parseIccCertToolInitial) parseIccCertToolInitial.style.display = selectedCertValue === 'parseIccCert' ? 'block' : 'none';
    if(keysetValidationToolInitial) keysetValidationToolInitial.style.display = selectedCertValue === 'keysetValidation' ? 'block' : 'none';
  }
}); // End of DOMContentLoaded

// Add EMV Calcs tool selection logic
const emvCalcSelect = document.getElementById('emvCalcSelect');
const eloParserTool = document.getElementById('eloParserTool');
const pinBlockTool = document.getElementById('pinBlockTool');
const arqcTool = document.getElementById('arqcTool');

emvCalcSelect?.addEventListener('change', function() {
  const selectedValue = this.value;
  if(eloParserTool) eloParserTool.style.display = selectedValue === 'eloParser' ? 'block' : 'none';
  if(pinBlockTool) pinBlockTool.style.display = selectedValue === 'pinBlock' ? 'block' : 'none';
  if(arqcTool) arqcTool.style.display = selectedValue === 'arqc' ? 'block' : 'none';
});

// EMV Certificates tool selection logic
const emvCertSelect = document.getElementById('emvCertSelect');
const parseIssuerCertTool = document.getElementById('parseIssuerCertTool');
const validateIssuerCertTool = document.getElementById('validateIssuerCertTool');
const validateCsrResponseTool = document.getElementById('validateCsrResponseTool');
const parseIccCertTool = document.getElementById('parseIccCertTool');
const keysetValidationTool = document.getElementById('keysetValidationTool');

emvCertSelect?.addEventListener('change', function() {
  const selectedValue = this.value;
  if(parseIssuerCertTool) parseIssuerCertTool.style.display = selectedValue === 'parseIssuerCert' ? 'block' : 'none';
  if(validateIssuerCertTool) validateIssuerCertTool.style.display = selectedValue === 'validateIssuerCert' ? 'block' : 'none';
  if(validateCsrResponseTool) validateCsrResponseTool.style.display = selectedValue === 'validateCsrResponse' ? 'block' : 'none';
  if(parseIccCertTool) parseIccCertTool.style.display = selectedValue === 'parseIccCert' ? 'block' : 'none';
  if(keysetValidationTool) keysetValidationTool.style.display = selectedValue === 'keysetValidation' ? 'block' : 'none';
});

// Parse Issuer Certificate logic
const parseIssuerCertBtn = document.getElementById('parseIssuerCertBtn');
const openedIssuerCertEl = document.getElementById('openedIssuerCert');
const issuerPkRemainderEl = document.getElementById('issuerPkRemainder');
const issuerPkExponentEl = document.getElementById('issuerPkExponent');
const parseIssuerCertErrorEl = document.getElementById('parseIssuerCertError');

// Parsed field elements
const parsedFields = {
  header: document.getElementById('parsedHeader'),
  certFormat: document.getElementById('parsedCertFormat'),
  issuerId: document.getElementById('parsedIssuerId'),
  expDate: document.getElementById('parsedExpDate'),
  serial: document.getElementById('parsedSerial'),
  hashAlg: document.getElementById('parsedHashAlg'),
  pkAlg: document.getElementById('parsedPkAlg'),
  pkLen: document.getElementById('parsedPkLen'),
  expLen: document.getElementById('parsedExpLen'),
  pkData: document.getElementById('parsedPkData'),
  padding: document.getElementById('parsedPadding'),
  hash: document.getElementById('parsedHash'),
  trailer: document.getElementById('parsedTrailer')
};
const reconstructedPkEl = document.getElementById('reconstructedPk');
const hashVerificationResultEl = document.getElementById('hashVerificationResult');

function resetParsedFields() {
  for (const key in parsedFields) {
    if (parsedFields[key]) parsedFields[key].textContent = '-';
  }
  if (reconstructedPkEl) reconstructedPkEl.value = '';
  if (hashVerificationResultEl) hashVerificationResultEl.textContent = '';
  if (hashVerificationResultEl) hashVerificationResultEl.style.color = '';
}

// Certificate parsing uses shared emvHexToBytes/emvBytesToHex/emvCalcSHA1

parseIssuerCertBtn?.addEventListener('click', async function() {
  resetParsedFields();
  if (parseIssuerCertErrorEl) {
    parseIssuerCertErrorEl.textContent = '';
    parseIssuerCertErrorEl.style.color = '#ef4444';
  }

  const certHex = openedIssuerCertEl?.value.trim().replace(/\s+/g, '') || '';
  const remainderHex = issuerPkRemainderEl?.value.trim().replace(/\s+/g, '') || '';
  const exponentHex = issuerPkExponentEl?.value.trim().replace(/\s+/g, '') || '';

  if (!certHex) {
    parseIssuerCertErrorEl.textContent = 'Please enter the opened certificate data.';
    return;
  }

  if (!/^[0-9a-fA-F]+$/.test(certHex)) {
    parseIssuerCertErrorEl.textContent = 'Certificate data must be valid HEX.';
    return;
  }

  if (certHex.length < 48) { // Minimum: header(2) + format(2) + issuer(8) + exp(4) + serial(6) + hash_alg(2) + pk_alg(2) + pk_len(2) + exp_len(2) + hash(40) + trailer(2) = 72 chars minimum
    parseIssuerCertErrorEl.textContent = 'Certificate data is too short.';
    return;
  }

  try {
    const certBytes = emvHexToBytes(certHex);
    let pos = 0;

    function getField(len) {
      const out = certBytes.slice(pos, pos + len);
      pos += len;
      return out;
    }

    // Parse header
    const header = getField(1)[0];
    if (parsedFields.header) {
      parsedFields.header.textContent = header.toString(16).padStart(2, '0').toUpperCase();
      if (header !== 0x6A) {
        parsedFields.header.textContent += ' (INVALID - expected 6A)';
      } else {
        parsedFields.header.textContent += ' (Valid)';
      }
    }

    // Certificate Format
    const certFormat = getField(1)[0];
    if (parsedFields.certFormat) {
      let formatDesc = '';
      if (certFormat === 0x02) formatDesc = ' (Issuer Public Key Certificate)';
      else if (certFormat === 0x04) formatDesc = ' (ICC Public Key Certificate)';
      else formatDesc = ' (Unknown)';
      parsedFields.certFormat.textContent = certFormat.toString(16).padStart(2, '0').toUpperCase() + formatDesc;
    }

    // Issuer Identifier (4 bytes)
    const issuerId = getField(4);
    if (parsedFields.issuerId) {
      parsedFields.issuerId.textContent = emvBytesToHex(issuerId);
    }

    // Certificate Expiration Date (2 bytes - MMYY)
    const expDateBytes = getField(2);
    if (parsedFields.expDate) {
      const expHex = emvBytesToHex(expDateBytes);
      const mm = expHex.substring(0, 2);
      const yy = expHex.substring(2, 4);
      parsedFields.expDate.textContent = `${expHex} (${mm}/20${yy})`;
    }

    // Certificate Serial Number (3 bytes)
    const serial = getField(3);
    if (parsedFields.serial) {
      parsedFields.serial.textContent = emvBytesToHex(serial);
    }

    // Hash Algorithm Indicator (1 byte)
    const hashAlgInd = getField(1)[0];
    if (parsedFields.hashAlg) {
      let hashAlgDesc = '';
      if (hashAlgInd === 0x01) hashAlgDesc = ' (SHA-1)';
      else hashAlgDesc = ' (Unknown)';
      parsedFields.hashAlg.textContent = hashAlgInd.toString(16).padStart(2, '0').toUpperCase() + hashAlgDesc;
    }

    // Issuer Public Key Algorithm Indicator (1 byte)
    const pkAlgInd = getField(1)[0];
    if (parsedFields.pkAlg) {
      let pkAlgDesc = '';
      if (pkAlgInd === 0x01) pkAlgDesc = ' (RSA)';
      else pkAlgDesc = ' (Unknown)';
      parsedFields.pkAlg.textContent = pkAlgInd.toString(16).padStart(2, '0').toUpperCase() + pkAlgDesc;
    }

    // Issuer Public Key Length (1 byte)
    const pkLen = getField(1)[0];
    if (parsedFields.pkLen) {
      parsedFields.pkLen.textContent = `${pkLen} bytes (0x${pkLen.toString(16).toUpperCase()})`;
    }

    // Issuer Public Key Exponent Length (1 byte)
    const expLenVal = getField(1)[0];
    if (parsedFields.expLen) {
      parsedFields.expLen.textContent = `${expLenVal} bytes`;
    }

    // Calculate remaining bytes: total - header(1) - format(1) - issuerId(4) - exp(2) - serial(3) - hashAlg(1) - pkAlg(1) - pkLen(1) - expLen(1) - hash(20) - trailer(1) = total - 36
    const pkDataLen = certBytes.length - pos - 21; // 20 hash + 1 trailer

    // Issuer Public Key or Leftmost Digits
    const pkData = getField(pkDataLen);

    // Separate actual key data from padding (BB bytes)
    let actualPkData = [];
    let paddingBytes = [];
    let foundPadding = false;

    for (let i = 0; i < pkData.length; i++) {
      if (!foundPadding && pkData[i] === 0xBB) {
        // Check if rest is all BB
        let allBB = true;
        for (let j = i; j < pkData.length; j++) {
          if (pkData[j] !== 0xBB) {
            allBB = false;
            break;
          }
        }
        if (allBB) {
          foundPadding = true;
          paddingBytes = pkData.slice(i);
          break;
        }
      }
      actualPkData.push(pkData[i]);
    }

    if (parsedFields.pkData) {
      const pkDataHex = emvBytesToHex(new Uint8Array(actualPkData));
      // Show truncated if too long
      if (pkDataHex.length > 80) {
        parsedFields.pkData.textContent = pkDataHex.substring(0, 40) + '...' + pkDataHex.substring(pkDataHex.length - 40) + ` (${actualPkData.length} bytes)`;
      } else {
        parsedFields.pkData.textContent = pkDataHex + ` (${actualPkData.length} bytes)`;
      }
    }

    if (parsedFields.padding) {
      if (paddingBytes.length > 0) {
        parsedFields.padding.textContent = `${paddingBytes.length} bytes of BB padding`;
      } else {
        parsedFields.padding.textContent = 'None';
      }
    }

    // Hash Result (20 bytes)
    const hashResult = getField(20);
    if (parsedFields.hash) {
      parsedFields.hash.textContent = emvBytesToHex(hashResult);
    }

    // Trailer (1 byte)
    const trailer = getField(1)[0];
    if (parsedFields.trailer) {
      parsedFields.trailer.textContent = trailer.toString(16).padStart(2, '0').toUpperCase();
      if (trailer !== 0xBC) {
        parsedFields.trailer.textContent += ' (INVALID - expected BC)';
      } else {
        parsedFields.trailer.textContent += ' (Valid)';
      }
    }

    // Reconstruct the full Issuer Public Key
    let fullPkBytes = [...actualPkData];
    if (remainderHex) {
      const remainderBytes = emvHexToBytes(remainderHex);
      fullPkBytes = fullPkBytes.concat(Array.from(remainderBytes));
    }

    if (reconstructedPkEl) {
      const fullPkHex = emvBytesToHex(new Uint8Array(fullPkBytes));
      reconstructedPkEl.value = fullPkHex;
      if (fullPkBytes.length !== pkLen) {
        reconstructedPkEl.value += `\n\nNote: Reconstructed key is ${fullPkBytes.length} bytes, expected ${pkLen} bytes.`;
        if (!remainderHex && fullPkBytes.length < pkLen) {
          reconstructedPkEl.value += ' You may need to provide the Issuer Public Key Remainder.';
        }
      }
    }

    // Hash Verification
    // Build hash input: Format || Issuer ID || Exp Date || Serial || Hash Alg || PK Alg || PK Len || Exp Len || Leftmost Digits (INCLUDING BB padding) || Remainder || Exponent
    // Per EMV Book 2: hash is over the full "Issuer Public Key or Leftmost Digits" field, which includes padding
    let hashInput = [
      certFormat,
      ...issuerId,
      ...expDateBytes,
      ...serial,
      hashAlgInd,
      pkAlgInd,
      pkLen,
      expLenVal,
      ...pkData  // Full field INCLUDING BB padding
    ];

    if (remainderHex) {
      hashInput = hashInput.concat(Array.from(emvHexToBytes(remainderHex)));
    }
    if (exponentHex) {
      hashInput = hashInput.concat(Array.from(emvHexToBytes(exponentHex)));
    }

    const hashInputBytes = new Uint8Array(hashInput);
    const calculatedHash = await emvCalcSHA1(hashInputBytes);

    if (hashVerificationResultEl && calculatedHash) {
      const calcHashHex = emvBytesToHex(calculatedHash);
      const certHashHex = emvBytesToHex(hashResult);

      hashVerificationResultEl.innerHTML = `<strong>Hash Input:</strong> ${emvBytesToHex(hashInputBytes)}<br><br>`;
      hashVerificationResultEl.innerHTML += `<strong>Calculated SHA-1:</strong> ${calcHashHex}<br>`;
      hashVerificationResultEl.innerHTML += `<strong>Certificate Hash:</strong> ${certHashHex}<br><br>`;

      if (calcHashHex === certHashHex) {
        hashVerificationResultEl.innerHTML += '<strong style="color: #22c55e;">Hash MATCHES - Certificate is valid!</strong>';
      } else {
        hashVerificationResultEl.innerHTML += '<strong style="color: #f59e0b;">Hash does NOT match.</strong>';
        if (!exponentHex) {
          hashVerificationResultEl.innerHTML += '<br>Note: You may need to provide the Issuer Public Key Exponent for hash verification.';
        }
        if (!remainderHex && actualPkData.length < pkLen) {
          hashVerificationResultEl.innerHTML += '<br>Note: You may need to provide the Issuer Public Key Remainder for hash verification.';
        }
      }
    }

    parseIssuerCertErrorEl.style.color = '#22c55e';
    parseIssuerCertErrorEl.textContent = 'Certificate parsed successfully.';

  } catch (error) {
    parseIssuerCertErrorEl.textContent = `Error parsing certificate: ${error.message}`;
    console.error('Parse Issuer Certificate Error:', error);
  }
});

// Load CA Public Keys and populate dropdown
let caPublicKeys = [];

fetch('{{ site.baseurl }}/assets/ca_public_keys.json')
  .then(response => response.json())
  .then(keys => {
    caPublicKeys = keys;
    const caKeySelectEl = document.getElementById('caKeySelect');
    keys.forEach((key, index) => {
      const option = document.createElement('option');
      option.value = index;
      option.textContent = `${key.network} - Index ${key.index} (${key.size} bit)`;
      caKeySelectEl?.appendChild(option);
    });
  })
  .catch(err => console.error('Failed to load CA keys:', err));

// Toggle auto-detect mode
document.getElementById('autoDetectCaKey')?.addEventListener('change', function() {
  const manualSection = document.getElementById('manualCaKeySection');
  const detectedSection = document.getElementById('detectedCaKeySection');
  if (this.checked) {
    if (manualSection) manualSection.style.display = 'none';
    if (detectedSection) detectedSection.style.display = 'block';
  } else {
    if (manualSection) manualSection.style.display = 'block';
    if (detectedSection) detectedSection.style.display = 'none';
  }
});

document.getElementById('caKeySelect')?.addEventListener('change', function() {
  const idx = this.value;
  if (idx !== '' && caPublicKeys[idx]) {
    const key = caPublicKeys[idx];
    const expEl = document.getElementById('manualCaExp');
    const modEl = document.getElementById('manualCaModulus');
    if (expEl) expEl.value = key.exponent;
    if (modEl) modEl.value = key.modulus;
  }
});

// Issuer Certificate Validation logic with auto-detection
const validateIssuerCertBtn = document.getElementById('validateIssuerCertBtn');
const issuerCertResults = document.getElementById('issuerCertResults');
const issuerRemainder = document.getElementById('issuerRemainder');
const issuerExp = document.getElementById('issuerExp');
const detectedCaKey = document.getElementById('detectedCaKey');
const issuerCert = document.getElementById('issuerCert');

// Validation tools use shared emvHexToBytes/emvBytesToHex/emvHexToBigInt/emvModPow

// Try to recover certificate with a given CA key
function tryRecoverCert(certHex, caModulus, caExp) {
  try {
    const modulus = emvHexToBigInt(caModulus);
    const exponent = emvHexToBigInt(caExp);
    const certInt = emvHexToBigInt(certHex);

    const recoveredInt = emvModPow(certInt, exponent, modulus);
    let recoveredHex = recoveredInt.toString(16).toUpperCase();
    recoveredHex = recoveredHex.padStart(certHex.length, '0');

    // Check header and trailer
    if (recoveredHex.startsWith('6A') && recoveredHex.endsWith('BC')) {
      return recoveredHex;
    }
  } catch (e) {
    // Recovery failed
  }
  return null;
}

validateIssuerCertBtn?.addEventListener('click', function() {
  const resultsEl = document.getElementById('issuerCertResults');
  const detectedEl = document.getElementById('detectedCaKey');
  const remainderEl = document.getElementById('issuerRemainder');
  const expEl = document.getElementById('issuerExp');
  const certEl = document.getElementById('issuerCert');
  const autoDetectEl = document.getElementById('autoDetectCaKey');
  const manualExpEl = document.getElementById('manualCaExp');
  const manualModEl = document.getElementById('manualCaModulus');

  if (resultsEl) resultsEl.value = '';
  if (detectedEl) detectedEl.value = '';

  function log(msg) {
    if (resultsEl) resultsEl.value += msg + '\n';
  }

  const certHex = certEl?.value.trim().replace(/\s+/g, '').toUpperCase() || '';
  const remainderHex = remainderEl?.value.trim().replace(/\s+/g, '').toUpperCase() || '';
  const issuerExpHex = expEl?.value.trim().replace(/\s+/g, '').toUpperCase() || '';
  const autoDetect = autoDetectEl?.checked ?? true;

  if (!certHex) {
    log('Error: Please enter the Issuer Certificate.');
    return;
  }

  if (!/^[0-9A-F]+$/.test(certHex)) {
    log('Error: Certificate must be valid HEX.');
    return;
  }

  const certBytes = certHex.length / 2;
  log(`Certificate size: ${certBytes} bytes (${certBytes * 8} bits)`);

  let recoveredHex = null;
  let usedKey = null;

  if (autoDetect) {
    // Auto-detect mode: find matching CA keys by size
    const matchingKeys = caPublicKeys.filter(k => k.modulus.length === certHex.length);

    if (matchingKeys.length === 0) {
      log(`Error: No CA keys found matching certificate size of ${certBytes} bytes.`);
      log('Available key sizes: ' + [...new Set(caPublicKeys.map(k => k.size))].join(', ') + ' bits');
      log('Try disabling auto-detect and entering CA key manually.');
      return;
    }

    log(`Found ${matchingKeys.length} CA key(s) matching size. Attempting recovery...`);

    for (const key of matchingKeys) {
      const result = tryRecoverCert(certHex, key.modulus, key.exponent);
      if (result) {
        recoveredHex = result;
        usedKey = key;
        break;
      }
    }

    if (!recoveredHex || !usedKey) {
      log('Error: Could not recover certificate with any matching CA key.');
      log('The certificate may be invalid or signed by an unknown CA.');
      log('Try disabling auto-detect and entering CA key manually.');
      return;
    }

    if (detectedEl) {
      detectedEl.value = `${usedKey.network} - Index ${usedKey.index} (${usedKey.size} bit)`;
    }
    log(`CA Key: ${usedKey.network} Index ${usedKey.index} (${usedKey.size} bit)`);
  } else {
    // Manual mode: use provided CA key
    const manualExp = manualExpEl?.value.trim().replace(/\s+/g, '').toUpperCase() || '';
    const manualMod = manualModEl?.value.trim().replace(/\s+/g, '').toUpperCase() || '';

    if (!manualExp || !manualMod) {
      log('Error: CA Exponent and Modulus are required in manual mode.');
      return;
    }

    if (manualMod.length !== certHex.length) {
      log(`Error: CA Modulus length (${manualMod.length / 2} bytes) does not match certificate length (${certBytes} bytes).`);
      return;
    }

    recoveredHex = tryRecoverCert(certHex, manualMod, manualExp);

    if (!recoveredHex) {
      log('Error: Could not recover certificate with provided CA key.');
      log('Check that the CA key is correct for this certificate.');
      return;
    }

    log('Using manually provided CA key.');
  }
  log('');
  log('Recovered certificate data:');
  log(recoveredHex);
  log('');

  // Parse recovered data
  const recBytes = emvHexToBytes(recoveredHex);
  let pos = 0;

  function getField(len) {
    const out = recBytes.slice(pos, pos + len);
    pos += len;
    return out;
  }

  const header = getField(1)[0];
  const certFormat = getField(1)[0];
  const issuerId = getField(4);
  const certExpDate = getField(2);
  const certSerial = getField(3);
  const hashAlgInd = getField(1)[0];
  const pubKeyAlgInd = getField(1)[0];
  const pubKeyLen = getField(1)[0];
  const pubKeyExpLen = getField(1)[0];
  const pubKeyOrLeft = getField(recBytes.length - pos - 21);
  const hashResult = getField(20);
  const trailer = getField(1)[0];

  log('=== Parsed Certificate Fields ===');
  log(`Header: ${header.toString(16).toUpperCase().padStart(2, '0')} (${header === 0x6A ? 'Valid' : 'INVALID'})`);
  log(`Format: ${certFormat.toString(16).toUpperCase().padStart(2, '0')} (${certFormat === 0x02 ? 'Issuer PK Cert' : certFormat === 0x04 ? 'ICC PK Cert' : 'Unknown'})`);
  log(`Issuer ID: ${emvBytesToHex(issuerId)}`);

  const expHex = emvBytesToHex(certExpDate);
  log(`Expiration: ${expHex} (${expHex.substring(0,2)}/20${expHex.substring(2,4)})`);
  log(`Serial: ${emvBytesToHex(certSerial)}`);
  log(`Hash Algorithm: ${hashAlgInd === 0x01 ? 'SHA-1' : 'Unknown'}`);
  log(`PK Algorithm: ${pubKeyAlgInd === 0x01 ? 'RSA' : 'Unknown'}`);
  log(`PK Length: ${pubKeyLen} bytes`);
  log(`PK Exponent Length: ${pubKeyExpLen} bytes`);
  log(`Trailer: ${trailer.toString(16).toUpperCase().padStart(2, '0')} (${trailer === 0xBC ? 'Valid' : 'INVALID'})`);
  log('');
  log(`Issuer PK or Leftmost Digits: ${emvBytesToHex(pubKeyOrLeft)}`);
  log(`Hash in Certificate: ${emvBytesToHex(hashResult)}`);
  log('');

  // Hash verification
  log('=== Hash Verification ===');
  let hashDataArr = [
    certFormat,
    ...issuerId,
    ...certExpDate,
    ...certSerial,
    hashAlgInd,
    pubKeyAlgInd,
    pubKeyLen,
    pubKeyExpLen,
    ...pubKeyOrLeft
  ];
  if (remainderHex) hashDataArr.push(...emvHexToBytes(remainderHex));
  if (issuerExpHex) hashDataArr.push(...emvHexToBytes(issuerExpHex));
  let hashData = new Uint8Array(hashDataArr);

  emvCalcSHA1(hashData).then(calcHashBytes => {
    if (!calcHashBytes) {
      log('Error: SHA-1 calculation failed (WebCrypto not available).');
      return;
    }
    const calcHash = emvBytesToHex(calcHashBytes);
    const certHash = emvBytesToHex(hashResult);

    log(`Calculated SHA-1: ${calcHash}`);
    log(`Certificate Hash: ${certHash}`);
    log('');

    if (calcHash === certHash) {
      log('*** HASH MATCHES - Certificate is VALID! ***');
    } else {
      log('*** HASH DOES NOT MATCH ***');
      if (!issuerExpHex) {
        log('Note: Issuer Public Key Exponent not provided. Try adding it (usually 03).');
      }
    }
  });
});

// CSR Response Validation logic
const csrResponseFile = document.getElementById('csrResponseFile');
const csrFileInfo = document.getElementById('csrFileInfo');
const csrBinEl = document.getElementById('csrBin');
const csrFileIdEl = document.getElementById('csrFileId');
const csrCaIndexEl = document.getElementById('csrCaIndex');
const csrExponentEl = document.getElementById('csrExponent');
const csrCertSizeEl = document.getElementById('csrCertSize');
const validateCsrBtn = document.getElementById('validateCsrBtn');
const csrValidationResults = document.getElementById('csrValidationResults');
const csrErrorEl = document.getElementById('csrError');

let csrParsedData = null;

csrResponseFile?.addEventListener('change', function() {
  const file = this.files[0];
  if (!file) {
    if (csrFileInfo) csrFileInfo.style.display = 'none';
    if (validateCsrBtn) validateCsrBtn.disabled = true;
    csrParsedData = null;
    return;
  }

  if (csrErrorEl) csrErrorEl.textContent = '';
  if (csrValidationResults) csrValidationResults.value = '';

  const reader = new FileReader();
  reader.onload = function(e) {
    const data = new Uint8Array(e.target.result);

    if (data.length < 10) {
      if (csrErrorEl) csrErrorEl.textContent = 'File too small to be a valid CSR response.';
      if (csrFileInfo) csrFileInfo.style.display = 'none';
      if (validateCsrBtn) validateCsrBtn.disabled = true;
      return;
    }

    // Parse CSR file structure:
    // Bytes 0-3: BIN (3-4 bytes, padded with FF)
    // Bytes 4-6: FileId (Mastercard internal reference)
    // Byte 7: CA Key Index
    // Byte 8: Exponent
    // Bytes 9+: Certificate data

    // Extract BIN (remove FF padding)
    let binBytes = data.slice(0, 4);
    let binHex = Array.from(binBytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    binHex = binHex.replace(/F+$/, ''); // Remove trailing F padding

    // Extract FileId
    let fileIdBytes = data.slice(4, 7);
    let fileIdHex = Array.from(fileIdBytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    // Extract CA Key Index
    let caKeyIndex = data[7].toString(16).padStart(2, '0').toUpperCase();

    // Extract Exponent
    let exponent = data[8].toString(16).padStart(2, '0').toUpperCase();

    // Extract Certificate data (from byte 9 onwards)
    let certData = data.slice(9);
    let certHex = Array.from(certData).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    // Update UI
    if (csrBinEl) csrBinEl.textContent = binHex;
    if (csrFileIdEl) csrFileIdEl.textContent = fileIdHex;
    if (csrCaIndexEl) csrCaIndexEl.textContent = caKeyIndex;
    if (csrExponentEl) csrExponentEl.textContent = exponent;
    if (csrCertSizeEl) csrCertSizeEl.textContent = `${certData.length} bytes (${certData.length * 8} bits)`;
    const csrIssuerCertHexEl = document.getElementById('csrIssuerCertHex');
    if (csrIssuerCertHexEl) csrIssuerCertHexEl.value = certHex;
    if (csrFileInfo) csrFileInfo.style.display = 'block';

    // Store parsed data for validation
    csrParsedData = {
      bin: binHex,
      fileId: fileIdHex,
      caKeyIndex: caKeyIndex,
      exponent: exponent,
      certHex: certHex,
      certBytes: certData.length
    };

    if (validateCsrBtn) validateCsrBtn.disabled = false;
  };

  reader.onerror = function() {
    if (csrErrorEl) csrErrorEl.textContent = 'Error reading file.';
    if (csrFileInfo) csrFileInfo.style.display = 'none';
    if (validateCsrBtn) validateCsrBtn.disabled = true;
  };

  reader.readAsArrayBuffer(file);
});

validateCsrBtn?.addEventListener('click', function() {
  if (!csrParsedData) {
    if (csrErrorEl) csrErrorEl.textContent = 'Please upload a CSR response file first.';
    return;
  }

  const resultsEl = csrValidationResults;
  const summaryEl = document.getElementById('csrCertSummary');
  const hashVerEl = document.getElementById('csrHashVerification');
  if (resultsEl) resultsEl.value = '';
  if (summaryEl) summaryEl.style.display = 'none';
  if (hashVerEl) {
    hashVerEl.textContent = '';
    hashVerEl.style.color = '';
    hashVerEl.style.backgroundColor = '';
  }

  function log(msg) {
    if (resultsEl) resultsEl.value += msg + '\n';
  }

  function setSummaryField(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  const certHex = csrParsedData.certHex;
  const caKeyIndex = csrParsedData.caKeyIndex;
  const certBytes = csrParsedData.certBytes;

  log(`BIN: ${csrParsedData.bin}`);
  log(`File ID: ${csrParsedData.fileId}`);
  log(`CA Key Index: ${caKeyIndex}`);
  log(`Exponent from file: ${csrParsedData.exponent}`);
  log(`Certificate size: ${certBytes} bytes (${certBytes * 8} bits)`);
  log('');

  // Find matching CA key by index and size (Mastercard only - RID A000000004)
  const mastercardRid = 'A000000004';
  const matchingKeys = caPublicKeys.filter(k =>
    k.rid === mastercardRid &&
    k.index === caKeyIndex &&
    k.modulus.length === certHex.length
  );

  if (matchingKeys.length === 0) {
    log(`Error: No Mastercard CA key found with index ${caKeyIndex} and size ${certBytes * 8} bits.`);
    log('Available Mastercard keys:');
    caPublicKeys.filter(k => k.rid === mastercardRid).forEach(k => {
      log(`  Index ${k.index}: ${k.size} bits`);
    });
    return;
  }

  log(`Found CA Key: ${matchingKeys[0].network} Index ${matchingKeys[0].index} (${matchingKeys[0].size} bit)`);
  log('');

  // Try to recover certificate
  let recoveredHex = null;
  let usedKey = null;

  for (const key of matchingKeys) {
    const result = tryRecoverCert(certHex, key.modulus, key.exponent);
    if (result) {
      recoveredHex = result;
      usedKey = key;
      break;
    }
  }

  if (!recoveredHex) {
    log('Error: Could not recover certificate with CA key.');
    return;
  }

  log('Recovered certificate data:');
  log(recoveredHex);
  log('');

  // Parse recovered data
  const recBytes = emvHexToBytes(recoveredHex);
  let pos = 0;

  function getField(len) {
    const out = recBytes.slice(pos, pos + len);
    pos += len;
    return out;
  }

  const header = getField(1)[0];
  const certFormat = getField(1)[0];
  const issuerId = getField(4);
  const certExpDate = getField(2);
  const certSerial = getField(3);
  const hashAlgInd = getField(1)[0];
  const pubKeyAlgInd = getField(1)[0];
  const pubKeyLen = getField(1)[0];
  const pubKeyExpLen = getField(1)[0];
  const pubKeyOrLeft = getField(recBytes.length - pos - 21);
  const hashResult = getField(20);
  const trailer = getField(1)[0];

  // Populate summary table
  const headerValid = header === 0x6A;
  const trailerValid = trailer === 0xBC;
  const headerHex = header.toString(16).toUpperCase().padStart(2, '0');
  const trailerHex = trailer.toString(16).toUpperCase().padStart(2, '0');
  const formatDesc = certFormat === 0x02 ? 'Issuer PK Cert' : certFormat === 0x04 ? 'ICC PK Cert' : 'Unknown';
  const expHex = emvBytesToHex(certExpDate);
  const hashAlgDesc = hashAlgInd === 0x01 ? 'SHA-1' : 'Unknown';
  const pkAlgDesc = pubKeyAlgInd === 0x01 ? 'RSA' : 'Unknown';

  setSummaryField('csrParsedHeader', `${headerHex} (${headerValid ? 'Valid' : 'INVALID'})`);
  setSummaryField('csrParsedFormat', `${certFormat.toString(16).toUpperCase().padStart(2, '0')} - ${formatDesc}`);
  setSummaryField('csrParsedIssuerId', emvBytesToHex(issuerId));
  setSummaryField('csrParsedExpDate', `${expHex} (${expHex.substring(0,2)}/20${expHex.substring(2,4)})`);
  setSummaryField('csrParsedSerial', emvBytesToHex(certSerial));
  setSummaryField('csrParsedHashAlg', hashAlgDesc);
  setSummaryField('csrParsedPkAlg', pkAlgDesc);
  setSummaryField('csrParsedPkLen', `${pubKeyLen} bytes`);
  setSummaryField('csrParsedExpLen', `${pubKeyExpLen} bytes`);
  setSummaryField('csrParsedTrailer', `${trailerHex} (${trailerValid ? 'Valid' : 'INVALID'})`);

  if (summaryEl) summaryEl.style.display = 'block';

  log('=== Parsed Certificate Fields ===');
  log(`Header: ${headerHex} (${headerValid ? 'Valid' : 'INVALID'})`);
  log(`Format: ${certFormat.toString(16).toUpperCase().padStart(2, '0')} (${formatDesc})`);
  log(`Issuer ID: ${emvBytesToHex(issuerId)}`);
  log(`Expiration: ${expHex} (${expHex.substring(0,2)}/20${expHex.substring(2,4)})`);
  log(`Serial: ${emvBytesToHex(certSerial)}`);
  log(`Hash Algorithm: ${hashAlgDesc}`);
  log(`PK Algorithm: ${pkAlgDesc}`);
  log(`PK Length: ${pubKeyLen} bytes`);
  log(`PK Exponent Length: ${pubKeyExpLen} bytes`);
  log(`Trailer: ${trailerHex} (${trailerValid ? 'Valid' : 'INVALID'})`);
  log('');
  log(`Issuer PK or Leftmost Digits: ${emvBytesToHex(pubKeyOrLeft)}`);
  log(`Hash in Certificate: ${emvBytesToHex(hashResult)}`);
  log('');

  // Hash verification
  log('=== Hash Verification ===');
  const issuerExpHex = csrParsedData.exponent;
  let hashDataArr = [
    certFormat,
    ...issuerId,
    ...certExpDate,
    ...certSerial,
    hashAlgInd,
    pubKeyAlgInd,
    pubKeyLen,
    pubKeyExpLen,
    ...pubKeyOrLeft
  ];
  // Add exponent from file
  if (issuerExpHex) hashDataArr.push(...emvHexToBytes(issuerExpHex));
  let hashData = new Uint8Array(hashDataArr);

  emvCalcSHA1(hashData).then(calcHashBytes => {
    if (!calcHashBytes) {
      log('Error: SHA-1 calculation failed (WebCrypto not available).');
      if (hashVerEl) {
        hashVerEl.textContent = 'SHA-1 calculation failed';
        hashVerEl.style.color = '#f59e0b';
        hashVerEl.style.backgroundColor = 'rgba(245, 158, 11, 0.1)';
      }
      return;
    }
    const calcHash = emvBytesToHex(calcHashBytes);
    const certHash = emvBytesToHex(hashResult);

    log(`Calculated SHA-1: ${calcHash}`);
    log(`Certificate Hash: ${certHash}`);
    log('');

    if (calcHash === certHash) {
      log('*** HASH MATCHES - Certificate is VALID! ***');
      if (hashVerEl) {
        hashVerEl.innerHTML = `<strong>VALID</strong> - Hash matches<br><br>Calculated: ${calcHash}<br>Certificate: ${certHash}`;
        hashVerEl.style.color = '#22c55e';
        hashVerEl.style.backgroundColor = 'rgba(34, 197, 94, 0.1)';
        hashVerEl.style.padding = '10px';
        hashVerEl.style.borderRadius = '4px';
      }
    } else {
      log('*** HASH DOES NOT MATCH ***');
      if (hashVerEl) {
        hashVerEl.innerHTML = `<strong>INVALID</strong> - Hash mismatch<br><br>Calculated: ${calcHash}<br>Certificate: ${certHash}`;
        hashVerEl.style.color = '#ef4444';
        hashVerEl.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
        hashVerEl.style.padding = '10px';
        hashVerEl.style.borderRadius = '4px';
      }
    }
  });
});

// ===== Keyset Validation Logic =====
const keysetFileInput = document.getElementById('keysetFile');
const validateKeysetsBtn = document.getElementById('validateKeysetsBtn');
const keysetProgressEl = document.getElementById('keysetProgress');
const keysetReportSection = document.getElementById('keysetReportSection');
const keysetSummaryEl = document.getElementById('keysetSummary');
const keysetReportTableBody = document.querySelector('#keysetReportTable tbody');
const keysetDetailedLog = document.getElementById('keysetDetailedLog');
const keysetErrorEl = document.getElementById('keysetError');

let keysetData = null;

keysetFileInput?.addEventListener('change', function() {
  const file = this.files[0];
  if (!file) {
    if (validateKeysetsBtn) validateKeysetsBtn.disabled = true;
    keysetData = null;
    return;
  }

  if (keysetErrorEl) keysetErrorEl.textContent = '';
  if (keysetDetailedLog) keysetDetailedLog.value = '';
  if (keysetReportSection) keysetReportSection.style.display = 'none';

  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      keysetData = JSON.parse(e.target.result);
      if (!Array.isArray(keysetData)) {
        if (keysetErrorEl) keysetErrorEl.textContent = 'JSON file must contain an array of keysets.';
        keysetData = null;
        return;
      }
      if (validateKeysetsBtn) validateKeysetsBtn.disabled = false;

      // Count total certificates
      let totalCerts = 0;
      keysetData.forEach(ks => {
        if (ks.Certificates && Array.isArray(ks.Certificates)) {
          totalCerts += ks.Certificates.length;
        }
      });
      if (keysetDetailedLog) keysetDetailedLog.value = `Loaded ${keysetData.length} keyset(s) with ${totalCerts} certificate(s) total.\n`;
    } catch (err) {
      if (keysetErrorEl) keysetErrorEl.textContent = 'Invalid JSON: ' + err.message;
      keysetData = null;
      if (validateKeysetsBtn) validateKeysetsBtn.disabled = true;
    }
  };
  reader.onerror = function() {
    if (keysetErrorEl) keysetErrorEl.textContent = 'Error reading file.';
  };
  reader.readAsText(file);
});

validateKeysetsBtn?.addEventListener('click', async function() {
  if (!keysetData || !Array.isArray(keysetData)) {
    if (keysetErrorEl) keysetErrorEl.textContent = 'Please upload a valid keysets JSON file.';
    return;
  }

  if (caPublicKeys.length === 0) {
    if (keysetErrorEl) keysetErrorEl.textContent = 'CA Public Keys not loaded yet. Please wait and try again.';
    return;
  }

  // Reset UI
  if (keysetErrorEl) keysetErrorEl.textContent = '';
  if (keysetReportTableBody) keysetReportTableBody.innerHTML = '';
  if (keysetDetailedLog) keysetDetailedLog.value = '';
  if (keysetReportSection) keysetReportSection.style.display = 'none';
  if (keysetProgressEl) {
    keysetProgressEl.style.display = 'block';
    keysetProgressEl.textContent = 'Validating...';
  }

  validateKeysetsBtn.disabled = true;

  function log(msg) {
    if (keysetDetailedLog) keysetDetailedLog.value += msg + '\n';
  }

  let totalCerts = 0;
  let matchCount = 0;
  let mismatchCount = 0;
  let errorCount = 0;
  const results = [];

  for (let ksIdx = 0; ksIdx < keysetData.length; ksIdx++) {
    const ks = keysetData[ksIdx];
    const bin = ks.BIN || 'N/A';
    const name = ks.Name || ks.IssuerName || 'Unknown';
    const brand = ks.BrandName || '';

    if (!ks.Certificates || !Array.isArray(ks.Certificates) || ks.Certificates.length === 0) {
      log(`[${bin}] ${name}: No certificates found, skipping.`);
      continue;
    }

    for (let certIdx = 0; certIdx < ks.Certificates.length; certIdx++) {
      totalCerts++;
      const cert = ks.Certificates[certIdx];
      const certHex = (cert.IssuerPublicCertificate || '').replace(/\s+/g, '').toUpperCase();
      const caIdx = cert.CaPublicKeyIndex || '';
      const jsonExpDateStr = cert.CertificateExpirationDate || '';

      log(`--- [${bin}] ${name} (Cert ${certIdx + 1}, CA Index: ${caIdx}) ---`);

      if (!certHex) {
        log('  ERROR: No certificate data.');
        errorCount++;
        results.push({ bin, name, caIdx, jsonExp: jsonExpDateStr, certExp: '-', status: 'error', detail: 'No certificate data' });
        continue;
      }

      if (!jsonExpDateStr) {
        log('  ERROR: No CertificateExpirationDate in JSON.');
        errorCount++;
        results.push({ bin, name, caIdx, jsonExp: '-', certExp: '-', status: 'error', detail: 'No expiration date in JSON' });
        continue;
      }

      // Parse JSON expiration date to MM/YY
      const jsonExpDate = new Date(jsonExpDateStr);
      const jsonMM = (jsonExpDate.getMonth() + 1).toString().padStart(2, '0');
      const jsonYY = jsonExpDate.getFullYear().toString().slice(-2);
      const jsonMMYY = jsonMM + jsonYY;
      const jsonExpFormatted = `${jsonMM}/20${jsonYY}`;

      // Find matching CA key
      const certBytes = certHex.length / 2;
      let matchingKeys = caPublicKeys.filter(k => k.modulus.length === certHex.length);

      // If we have a CA index and brand, narrow the search
      if (caIdx && brand) {
        let ridFilter = '';
        if (brand.toUpperCase().includes('MASTER')) ridFilter = 'A000000004';
        else if (brand.toUpperCase().includes('VISA')) ridFilter = 'A000000003';

        if (ridFilter) {
          const narrowed = matchingKeys.filter(k => k.rid === ridFilter && k.index === caIdx);
          if (narrowed.length > 0) matchingKeys = narrowed;
        }
      }

      if (matchingKeys.length === 0) {
        log(`  ERROR: No CA key found matching certificate size (${certBytes} bytes).`);
        errorCount++;
        results.push({ bin, name, caIdx, jsonExp: jsonExpFormatted, certExp: '-', status: 'error', detail: `No matching CA key (${certBytes * 8} bit)` });
        continue;
      }

      // Try to recover certificate
      let recoveredHex = null;
      let usedKey = null;

      for (const key of matchingKeys) {
        const result = tryRecoverCert(certHex, key.modulus, key.exponent);
        if (result) {
          recoveredHex = result;
          usedKey = key;
          break;
        }
      }

      if (!recoveredHex) {
        log(`  ERROR: Could not recover certificate with any matching CA key.`);
        errorCount++;
        results.push({ bin, name, caIdx, jsonExp: jsonExpFormatted, certExp: '-', status: 'error', detail: 'Recovery failed' });
        continue;
      }

      log(`  CA Key: ${usedKey.network} Index ${usedKey.index} (${usedKey.size} bit)`);

      // Parse recovered data to extract expiration date (bytes 7-8, MMYY)
      const recBytes = emvHexToBytes(recoveredHex);

      // Verify header/trailer
      if (recBytes[0] !== 0x6A || recBytes[recBytes.length - 1] !== 0xBC) {
        log(`  ERROR: Invalid header/trailer after recovery.`);
        errorCount++;
        results.push({ bin, name, caIdx, jsonExp: jsonExpFormatted, certExp: '-', status: 'error', detail: 'Invalid header/trailer' });
        continue;
      }

      // Certificate structure: header(1) + format(1) + issuerID(4) + expDate(2) + ...
      // Expiration date is at offset 6, 2 bytes, MMYY BCD
      const certExpMM = recBytes[6].toString(16).padStart(2, '0').toUpperCase();
      const certExpYY = recBytes[7].toString(16).padStart(2, '0').toUpperCase();
      const certMMYY = certExpMM + certExpYY;
      const certExpFormatted = `${certExpMM}/20${certExpYY}`;

      log(`  JSON Expiration:  ${jsonExpFormatted} (${jsonMMYY})`);
      log(`  Cert Expiration:  ${certExpFormatted} (${certMMYY})`);

      if (jsonMMYY === certMMYY) {
        log(`  MATCH`);
        matchCount++;
        results.push({ bin, name, caIdx, jsonExp: jsonExpFormatted, certExp: certExpFormatted, status: 'match' });
      } else {
        log(`  MISMATCH`);
        mismatchCount++;
        results.push({ bin, name, caIdx, jsonExp: jsonExpFormatted, certExp: certExpFormatted, status: 'mismatch' });
      }
    }

    // Update progress
    if (keysetProgressEl) {
      keysetProgressEl.textContent = `Processed ${ksIdx + 1} of ${keysetData.length} keysets...`;
    }

    // Yield to UI every 50 keysets
    if (ksIdx % 50 === 49) {
      await new Promise(r => setTimeout(r, 0));
    }
  }

  // Build report
  log('');
  log(`===== SUMMARY =====`);
  log(`Total certificates: ${totalCerts}`);
  log(`Matches: ${matchCount}`);
  log(`Mismatches: ${mismatchCount}`);
  log(`Errors: ${errorCount}`);

  if (keysetSummaryEl) {
    let summaryHTML = `<strong>Total:</strong> ${totalCerts} certificates | `;
    summaryHTML += `<span style="color:#22c55e;">Matches: ${matchCount}</span> | `;
    summaryHTML += `<span style="color:#ef4444;">Mismatches: ${mismatchCount}</span>`;
    if (errorCount > 0) summaryHTML += ` | <span style="color:#f59e0b;">Errors: ${errorCount}</span>`;
    keysetSummaryEl.innerHTML = summaryHTML;
  }

  // Populate table - show mismatches and errors first
  if (keysetReportTableBody) {
    const sorted = [...results].sort((a, b) => {
      const order = { mismatch: 0, error: 1, match: 2 };
      return (order[a.status] ?? 3) - (order[b.status] ?? 3);
    });

    for (const r of sorted) {
      const tr = document.createElement('tr');
      let statusText = '';
      let statusColor = '';
      if (r.status === 'match') {
        statusText = 'OK';
        statusColor = '#22c55e';
      } else if (r.status === 'mismatch') {
        statusText = 'MISMATCH';
        statusColor = '#ef4444';
      } else {
        statusText = r.detail || 'Error';
        statusColor = '#f59e0b';
      }

      tr.innerHTML = `<td>${r.bin}</td><td>${r.name}</td><td>${r.caIdx}</td><td>${r.jsonExp}</td><td>${r.certExp}</td><td style="color:${statusColor};font-weight:bold;">${statusText}</td>`;
      keysetReportTableBody.appendChild(tr);
    }
  }

  if (keysetReportSection) keysetReportSection.style.display = 'block';
  if (keysetProgressEl) keysetProgressEl.style.display = 'none';
  validateKeysetsBtn.disabled = false;
});
</script>
