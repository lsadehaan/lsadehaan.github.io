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
    <button class="tab-button" onclick="openTool(event, 'hash')">Hash</button>
    <button class="tab-button" onclick="openTool(event, 'emvcalcs')">EMV Calcs</button>
  </div>

  <div id="symmetric" class="tab-content" style="display:block;">
    <h2>Symmetric Crypto</h2>
    <p>Tools for symmetric key cryptography (e.g., AES, DES). Provide input fields for plaintext/ciphertext, key, IV, and options for algorithm, mode, and padding.</p>
    <!-- UI for Symmetric Crypto will go here -->
  </div>

  <div id="rsa" class="tab-content">
    <h2>RSA</h2>
    <p>Perform raw RSA operations. All inputs and outputs are ASCII HEX. The exponent field is used for both public (e) and private (d) exponents. Ensure your data, when converted to a number, is less than the respective modulus.</p>
    
    <div style="margin-bottom: 10px;">
      <label for="rsaExponent" style="display: block; margin-bottom: 5px;">Exponent (e or d - HEX):</label>
      <textarea id="rsaExponent" rows="2" class="tool-textarea"></textarea>
    </div>

    <div style="margin-bottom: 10px;">
      <label for="rsaPublicModulus" style="display: block; margin-bottom: 5px;">Public Modulus (N - HEX):</label>
      <textarea id="rsaPublicModulus" rows="3" class="tool-textarea"></textarea>
    </div>

    <div style="margin-bottom: 10px;">
      <label for="rsaPrivateModulus" style="display: block; margin-bottom: 5px;">Private Modulus (N - HEX):</label>
      <textarea id="rsaPrivateModulus" rows="3" class="tool-textarea"></textarea>
    </div>

    <div style="margin-bottom: 10px;">
      <label for="rsaData" style="display: block; margin-bottom: 5px;">Data (Input - HEX):</label>
      <textarea id="rsaData" rows="4" class="tool-textarea"></textarea>
    </div>

    <button id="rsaPublicOpBtn" style="padding: 8px 15px; margin-right: 10px;">Perform Public Operation</button>
    <button id="rsaPrivateOpBtn" style="padding: 8px 15px;">Perform Private Operation</button>

    <div style="margin-top: 15px;">
      <label for="rsaResult" style="display: block; margin-bottom: 5px;">Result (Output - HEX):</label>
      <textarea id="rsaResult" rows="4" class="tool-textarea" style="background-color: #e9e9e9;" readonly></textarea>
    </div>
    <div id="rsaError" style="color: red; margin-top: 10px;"></div>

  </div>

  <div id="hex" class="tab-content">
    <h2>Hex Manipulator</h2>
    <p>Upload a binary file to view its content as a continuous block of ASCII HEX. Click inside the text area to see cursor offsets. You can edit the text to add formatting (spaces, newlines).</p>
    <input type="file" id="hexFile" style="margin-bottom: 10px;">
    <textarea id="hexOutput" class="tool-textarea" style="min-height: 200px; white-space: pre; overflow-wrap: break-word; background-color: #f5f5f5; border: 1px solid #ccc;"></textarea>
    <div style="margin-top: 10px;">
      <button id="addSpacesBtn" type="button">Add spaces between bytes</button>
      <button id="removeWhitespaceBtn" type="button">Remove all whitespace</button>
    </div>
    <div id="hexOffsetInfo" style="margin-top: 10px; font-family: monospace;">
      Cursor: Char 0 | Byte 0
    </div>
    <div id="hexSelectionInfo" style="margin-top: 5px; font-family: monospace;">
      Selected: 0 Chars | 0 Bytes
    </div>
  </div>

  <div id="hash" class="tab-content">
    <h2>Hash Calculation</h2>
    <p>Calculate cryptographic hashes. Input data as ASCII HEX.</p>

    <div style="margin-bottom: 10px;">
      <label for="hashAlgorithm" style="display: block; margin-bottom: 5px;">Select Hash Algorithm:</label>
      <select id="hashAlgorithm" style="padding: 5px; width: 100%; box-sizing: border-box;">
        <option value="sha1">SHA-1</option>
        <option value="sha256">SHA-256</option>
        <!-- Add other hash algorithms here if needed -->
      </select>
    </div>

    <div style="margin-bottom: 10px;">
      <label for="hashInput" style="display: block; margin-bottom: 5px;">Input Data (HEX):</label>
      <textarea id="hashInput" rows="4" class="tool-textarea"></textarea>
    </div>

    <button id="calculateHashBtn" style="padding: 8px 15px;">Calculate Hash</button>

    <div style="margin-top: 15px;">
      <label for="hashResult" style="display: block; margin-bottom: 5px;">Hash Result (HEX):</label>
      <textarea id="hashResult" rows="3" class="tool-textarea" style="background-color: #e9e9e9;" readonly></textarea>
    </div>
    <div id="hashError" style="color: red; margin-top: 10px;"></div>

  </div>

  <div id="emvcalcs" class="tab-content">
    <h2>Other EMV Calculations</h2>
    <label for="emvCalcSelect" style="display:block; margin-bottom:8px;">Select EMV Calculation Tool:</label>
    <select id="emvCalcSelect" style="margin-bottom: 16px; width: 100%; max-width: 400px;">
      <option value="eloParser" selected>ELO Request Parser</option>
      <option value="issuerCert">Issuer Certificate</option>
      <option value="pinBlock">PIN Block (TBD)</option>
      <option value="arqc">ARQC (TBD)</option>
    </select>

    <div id="eloParserTool" class="emv-tool-section">
      <h3>ELO Request Parser</h3>
      <p>Load an ELO binary file (<code>.req</code> extension) to parse and extract certificate information.</p>
      <div style="margin-bottom: 10px;">
        <label for="eloReqFile" style="display: block; margin-bottom: 5px;">Upload ELO Request File (.req):</label>
        <input type="file" id="eloReqFile" accept=".req" style="padding: 5px; width: 100%; box-sizing: border-box;">
      </div>
      <button id="downloadModulusBtn" type="button" style="padding: 8px 15px; margin-top: 5px; margin-bottom:15px;" disabled>Download Modulus (.bin)</button>

      <style>
        .summary-table {
          width: 100%;
          margin-bottom: 15px;
          border-collapse: collapse;
        }
        .summary-table th, .summary-table td {
          border: 1px solid #ddd;
          padding: 8px;
          text-align: left;
        }
        .summary-table th {
          background-color: #f2f2f2;
          width: 30%;
        }
      </style>
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

      <div style="margin-top: 15px;">
        <label for="eloReqOutput" style="display: block; margin-bottom: 5px;">Detailed Parsing Output:</label>
        <textarea id="eloReqOutput" rows="10" class="tool-textarea" style="background-color: #e9e9e9; white-space: pre; overflow-wrap: normal; font-family: monospace;" readonly></textarea>
      </div>
      <div id="eloReqError" style="color: red; margin-top: 10px;"></div>
    </div>

    <div id="issuerCertTool" class="emv-tool-section" style="display:none;">
      <h3>Issuer Certificate Validator</h3>
      <div style="margin-bottom:10px;">
        <label for="issuerCaExp" style="display:block;">CA Exponent (HEX):</label>
        <input id="issuerCaExp" class="tool-textarea" style="width:120px;" />
      </div>
      <div style="margin-bottom:10px;">
        <label for="issuerCaModulus" style="display:block;">CA Modulus (HEX):</label>
        <textarea id="issuerCaModulus" class="tool-textarea" rows="3" style="width:100%;"></textarea>
      </div>
      <div style="margin-bottom:10px;">
        <label for="issuerCert" style="display:block;">Certificate (HEX):</label>
        <textarea id="issuerCert" class="tool-textarea" rows="4" style="width:100%;"></textarea>
      </div>
      <div style="margin-bottom:10px;">
        <label for="issuerRemainder" style="display:block;">Issuer Public Key Remainder (HEX):</label>
        <input id="issuerRemainder" class="tool-textarea" style="width:100%;" />
      </div>
      <div style="margin-bottom:10px;">
        <label for="issuerExp" style="display:block;">Issuer Public Key Exponent (HEX):</label>
        <input id="issuerExp" class="tool-textarea" style="width:120px;" />
      </div>
      <button id="validateIssuerCertBtn" type="button" style="margin-bottom:10px;">Validate</button>
      <div style="margin-bottom:10px;"><label for="issuerCertResults" style="display:block;">Results:</label>
        <textarea id="issuerCertResults" class="tool-textarea" rows="8" style="width:100%; background:#f5f5f5;" readonly></textarea>
      </div>
    </div>

    <div id="pinBlockTool" class="emv-tool-section" style="display:none;">
      <h3>PIN Block (TBD)</h3>
      <p>Coming soon...</p>
    </div>
    <div id="arqcTool" class="emv-tool-section" style="display:none;">
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

// Hex Manipulator Logic
let currentByteArray = null;
const hexFileInput = document.getElementById('hexFile');
const hexOutputTextarea = document.getElementById('hexOutput');
const addSpacesBtn = document.getElementById('addSpacesBtn');
const removeWhitespaceBtn = document.getElementById('removeWhitespaceBtn');
const hexOffsetInfo = document.getElementById('hexOffsetInfo');
const hexSelectionInfo = document.getElementById('hexSelectionInfo');

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

// RSA Tool Logic
const rsaExponentEl = document.getElementById('rsaExponent');
const rsaPublicModulusEl = document.getElementById('rsaPublicModulus');
const rsaPrivateModulusEl = document.getElementById('rsaPrivateModulus');
const rsaDataEl = document.getElementById('rsaData');
const rsaResultEl = document.getElementById('rsaResult');
const rsaPublicOpBtn = document.getElementById('rsaPublicOpBtn');
const rsaPrivateOpBtn = document.getElementById('rsaPrivateOpBtn');
const rsaErrorEl = document.getElementById('rsaError');

function hexToBigInt(hex) {
  if (hex.startsWith('0x')) {
    hex = hex.substring(2);
  }
  if (hex.length === 0) return BigInt(0);
  return BigInt('0x' + hex);
}

function bigIntToHex(bigIntValue) {
  let hex = bigIntValue.toString(16);
  return hex.toUpperCase();
}

function power(base, exp, mod) {
  let res = BigInt(1);
  base = base % mod;
  while (exp > BigInt(0)) {
    if (exp % BigInt(2) === BigInt(1)) res = (res * base) % mod;
    base = (base * base) % mod;
    exp = exp / BigInt(2);
  }
  return res;
}

function performRsaOperation(operationType) {
  rsaErrorEl.textContent = '';
  rsaResultEl.value = '';
  try {
    const exponentHex = rsaExponentEl.value.trim();
    const dataHex = rsaDataEl.value.trim();
    let modulusHex = '';
    let modulusElForCheck = null;

    if (operationType === 'public') {
      modulusHex = rsaPublicModulusEl.value.trim();
      modulusElForCheck = rsaPublicModulusEl;
    } else if (operationType === 'private') {
      modulusHex = rsaPrivateModulusEl.value.trim();
      modulusElForCheck = rsaPrivateModulusEl;
    } else {
      rsaErrorEl.textContent = 'Invalid operation type.';
      return;
    }

    if (!exponentHex || !modulusHex || !dataHex) {
      rsaErrorEl.textContent = `Exponent, ${operationType} Modulus, and Data fields cannot be empty.`;
      return;
    }
    
    if (!/^[0-9a-fA-F]+$/.test(exponentHex.replace(/^0x/, '')) || 
        !/^[0-9a-fA-F]+$/.test(modulusHex.replace(/^0x/, '')) || 
        !/^[0-9a-fA-F]+$/.test(dataHex.replace(/^0x/, ''))) {
      rsaErrorEl.textContent = 'Inputs must be valid HEX strings (0-9, A-F).';
      return;
    }

    const exponent = hexToBigInt(exponentHex);
    const modulus = hexToBigInt(modulusHex);
    const data = hexToBigInt(dataHex);

    if (modulus <= BigInt(0)) {
        rsaErrorEl.textContent = `The ${operationType} Modulus must be positive.`;
        return;
    }
    if (data >= modulus) {
        console.warn(`RSA data is greater than or equal to the selected ${operationType} modulus. This might not be standard RSA usage.`);
    }

    const resultBigInt = power(data, exponent, modulus);
    rsaResultEl.value = bigIntToHex(resultBigInt);

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

function hexStringToArrayBuffer(hexString) {
  // Remove 0x prefix if present
  if (hexString.startsWith('0x')) {
    hexString = hexString.slice(2);
  }
  // Ensure even length for hex string
  if (hexString.length % 2 !== 0) {
    // Handle this case based on desired behavior, e.g., throw error or pad
    // For now, let it proceed; ArrayBuffer might handle odd length by ignoring last char or erroring
    // It's better to ensure valid, full-byte hex input from the user or pre-validation
    console.warn("Hex string has an odd length. Parsing might be affected.");
  }
  const buffer = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    buffer[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
  }
  return buffer.buffer;
}

function arrayBufferToHexString(buffer) {
  const byteArray = new Uint8Array(buffer);
  let hexString = '';
  for (let i = 0; i < byteArray.length; i++) {
    hexString += byteArray[i].toString(16).padStart(2, '0');
  }
  return hexString.toUpperCase();
}

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
    const hexInput = hashInputEl.value.trim();

    if (hexInput.length === 0) { // Allow empty string input for hashing
        // Some APIs might produce a hash for an empty input, some might not. 
        // SubtleCrypto does produce a hash for an empty ArrayBuffer.
    } else if (!/^[0-9a-fA-F]+$/.test(hexInput) || hexInput.length % 2 !== 0) {
      hashErrorEl.textContent = 'Input Data must be a valid HEX string with an even number of characters (full bytes).';
      return;
    }

    const dataBuffer = hexStringToArrayBuffer(hexInput);
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
    hashResultEl.value = arrayBufferToHexString(hashBuffer);

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

function eloBytesToHexString(byteArray) {
  return Array.from(byteArray).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

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
      const iinBinHex = eloBytesToHexString(iinBinBytes);
      output += `IIN/BIN: ${iinBinHex}\n`;
      if (summaryFields.iinBin) summaryFields.iinBin.textContent = iinBinHex;

      // 3. Issuer Key Index (3 bytes)
      if (offset + 3 > fileBytes.byteLength) throw new Error("File too short for Issuer Key Index.");
      const issuerKeyIndexBytes = new Uint8Array(fileBytes.buffer, offset, 3);
      offset += 3;
      const issuerKeyIndexHex = eloBytesToHexString(issuerKeyIndexBytes);
      output += `Issuer Key Index: ${issuerKeyIndexHex}\n`;
      if (summaryFields.keyIndex) summaryFields.keyIndex.textContent = issuerKeyIndexHex;

      // 4. Exp Date (2 bytes YYMM)
      if (offset + 2 > fileBytes.byteLength) throw new Error("File too short for Expiry Date.");
      const expYearBcdByte = dataView.getUint8(offset); // YY byte
      const expMonthBcdByte = dataView.getUint8(offset + 1); // MM byte
      offset += 2;
      
      const actualYear = bcdToDec(expYearBcdByte);
      const actualMonth = bcdToDec(expMonthBcdByte);

      const expYearStr = actualYear.toString().padStart(2,'0'); 
      const expMonthStr = actualMonth.toString().padStart(2,'0'); 
      const formattedExpDate = `${expMonthStr}/20${expYearStr}`;
      // Display raw hex bytes as they appear in file for YYMM_raw_bytes part
      output += `Expiry Date (YYMM_raw_bytes): ${expYearBcdByte.toString(16).padStart(2,'0').toUpperCase()}${expMonthBcdByte.toString(16).padStart(2,'0').toUpperCase()} (Interpreted MM/YYYY: ${formattedExpDate})\n`;
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
      const modulusHex = eloBytesToHexString(modulusBytes);
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
      const exponentHex = eloBytesToHexString(exponentBytes);
      offset += exponentLength;
      output += `Exponent (e): ${exponentHex}\n`;
      if (summaryFields.exponent) summaryFields.exponent.textContent = exponentHex.startsWith('0') && exponentHex.length > 1 ? exponentHex.substring(1) : exponentHex; // Remove leading 0 if present, like 03 -> 3

      // 11. HASH (20 bytes of SHA1 hash)
      if (offset + 20 > fileBytes.byteLength) throw new Error("File too short for HASH.");
      const hashBytes = new Uint8Array(fileBytes.buffer, offset, 20);
      const providedHashHex = eloBytesToHexString(hashBytes);
      offset += 20;
      output += `Provided HASH (SHA-1):\n${providedHashHex}\n`;

      // 12. SelfSignedCertificate (LM bytes)
      if (offset + modulusLength > fileBytes.byteLength) throw new Error("File too short for SelfSignedCertificate.");
      const selfSignedCertificateBytes = new Uint8Array(fileBytes.buffer, offset, modulusLength);
      const selfSignedCertificateHex = eloBytesToHexString(selfSignedCertificateBytes);
      offset += modulusLength;
      output += `SelfSignedCertificate (Encrypted/Signed Data Block):\n${selfSignedCertificateHex}\n`;

      output += "\n--- RSA Decryption/Recovery of SelfSignedCertificate ---\n";
      try {
        const N_rsa = hexToBigInt(modulusHex);
        const e_rsa = hexToBigInt(exponentHex);
        const C_rsa = hexToBigInt(selfSignedCertificateHex);

        if (N_rsa <= BigInt(0)) throw new Error("Modulus must be positive for RSA.");
        if (e_rsa <= BigInt(0)) throw new Error("Exponent must be positive for RSA.");
        if (C_rsa >= N_rsa) errors.push("Warning: SelfSignedCertificate data is numerically >= Modulus. This is unusual for RSA encrypted/signed blocks.");

        const openedDataBigInt = power(C_rsa, e_rsa, N_rsa); // power(base, exp, mod)
        let openedDataHex = bigIntToHex(openedDataBigInt);
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
  const issuerCertToolInitial = document.getElementById('issuerCertTool');
  const pinBlockToolInitial = document.getElementById('pinBlockTool');
  const arqcToolInitial = document.getElementById('arqcTool');

  if (emvCalcSelectInitial) { // Check if the select element exists
    const selectedValue = emvCalcSelectInitial.value; // Default should be 'eloParser' due to 'selected' attribute in HTML
    if(eloParserToolInitial) eloParserToolInitial.style.display = selectedValue === 'eloParser' ? '' : 'none';
    if(issuerCertToolInitial) issuerCertToolInitial.style.display = selectedValue === 'issuerCert' ? '' : 'none';
    if(pinBlockToolInitial) pinBlockToolInitial.style.display = selectedValue === 'pinBlock' ? '' : 'none';
    if(arqcToolInitial) arqcToolInitial.style.display = selectedValue === 'arqc' ? '' : 'none';
  }
}); // End of DOMContentLoaded

// Add EMV Calcs tool selection logic
const emvCalcSelect = document.getElementById('emvCalcSelect');
const eloParserTool = document.getElementById('eloParserTool'); 
const issuerCertTool = document.getElementById('issuerCertTool');
const pinBlockTool = document.getElementById('pinBlockTool');
const arqcTool = document.getElementById('arqcTool');

emvCalcSelect?.addEventListener('change', function() {
  const selectedValue = this.value;
  if(eloParserTool) eloParserTool.style.display = selectedValue === 'eloParser' ? '' : 'none';
  if(issuerCertTool) issuerCertTool.style.display = selectedValue === 'issuerCert' ? '' : 'none';
  if(pinBlockTool) pinBlockTool.style.display = selectedValue === 'pinBlock' ? '' : 'none';
  if(arqcTool) arqcTool.style.display = selectedValue === 'arqc' ? '' : 'none';
});

// Add a stub for the Validate button (Issuer Certificate validation logic from upstream)
const validateIssuerCertBtn = document.getElementById('validateIssuerCertBtn');
const issuerCertResults = document.getElementById('issuerCertResults');
const issuerCaExp = document.getElementById('issuerCaExp');
const issuerRemainder = document.getElementById('issuerRemainder');
const issuerExp = document.getElementById('issuerExp');

validateIssuerCertBtn?.addEventListener('click', function() {
  // Clear previous results
  issuerCertResults.value = '';
  // Get input values
  const caExpHex = issuerCaExp.value.trim().replace(/\s+/g, '');
  const caModulusHex = issuerCaModulus.value.trim().replace(/\s+/g, '');
  const certHex = issuerCert.value.trim().replace(/\s+/g, '');
  const remainderHex = issuerRemainder.value.trim().replace(/\s+/g, '');
  const issuerExpHex = issuerExp.value.trim().replace(/\s+/g, '');

  // Helper for output
  function log(msg) {
    issuerCertResults.value += msg + '\n';
  }

  // Input validation
  if (!caExpHex || !caModulusHex || !certHex) {
    log('Error: CA Exponent, CA Modulus, and Certificate are required.');
    return;
  }
  if (!/^[0-9a-fA-F]*$/.test(caExpHex) || !/^[0-9a-fA-F]+$/.test(caModulusHex) || !/^[0-9a-fA-F]+$/.test(certHex)) {
    log('Error: CA Exponent, CA Modulus, and Certificate must be valid HEX.');
    return;
  }
  if ((remainderHex && !/^[0-9a-fA-F]+$/.test(remainderHex)) || (issuerExpHex && !/^[0-9a-fA-F]+$/.test(issuerExpHex))) {
    log('Error: Issuer Remainder and Issuer Exponent must be valid HEX if provided.');
    return;
  }

  // Convert hex to BigInt/Uint8Array
  function hexToBytes(hex) {
    if (hex.length % 2 !== 0) hex = '0' + hex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }
  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  function hexToBigInt(hex) {
    return BigInt('0x' + hex);
  }

  // Step 1: Check certificate length
  if (certHex.length !== caModulusHex.length) {
    log('Fail: Certificate length does not match CA modulus length.');
    return;
  }
  log('Step 1: Certificate length matches CA modulus length.');

  // Step 2: RSA decrypt (recover) the certificate using CA public key
  // For EMV, the public exponent is usually 3 or 65537 (0x03 or 0x10001)
  let caExponent = 65537n; // Default to 65537
  try {
    if (caExpHex) caExponent = hexToBigInt(caExpHex);
  } catch (e) {
    log('Error: Invalid CA Exponent.');
    return;
  }
  const modulus = hexToBigInt(caModulusHex);
  const certInt = hexToBigInt(certHex);
  // RSA decrypt: m = c^e mod n
  let recoveredInt;
  try {
    recoveredInt = certInt ** caExponent % modulus;
  } catch (e) {
    log('Error: RSA operation failed.');
    return;
  }
  let recoveredHex = recoveredInt.toString(16).padStart(certHex.length, '0').toUpperCase();
  if (recoveredHex.length < certHex.length) recoveredHex = recoveredHex.padStart(certHex.length, '0');
  log('Step 2: Certificate decrypted (recovered data):');
  log(recoveredHex);

  // Step 3: Parse recovered data fields
  const recBytes = hexToBytes(recoveredHex);
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
  // The rest is issuer public key or leftmost digits, hash, trailer
  const pubKeyOrLeft = getField(recBytes.length - pos - 21); // 20 hash + 1 trailer
  const hashResult = getField(20);
  const trailer = getField(1)[0];

  // Step 4: Check header and trailer
  if (header !== 0x6A) {
    log('Fail: Recovered Data Header is not 6A.');
    return;
  }
  if (trailer !== 0xBC) {
    log('Fail: Recovered Data Trailer is not BC.');
    return;
  }
  log('Step 3: Header and Trailer are correct.');

  // Step 5: Check certificate format
  if (certFormat !== 0x02) {
    log('Fail: Certificate Format is not 02.');
    return;
  }
  log('Step 4: Certificate Format is correct.');

  // Step 6: Show parsed fields
  log('Issuer Identifier: ' + bytesToHex(issuerId));
  log('Certificate Expiration Date: ' + bytesToHex(certExpDate));
  log('Certificate Serial Number: ' + bytesToHex(certSerial));
  log('Hash Algorithm Indicator: ' + hashAlgInd.toString(16).padStart(2, '0'));
  log('Issuer Public Key Algorithm Indicator: ' + pubKeyAlgInd.toString(16).padStart(2, '0'));
  log('Issuer Public Key Length: ' + pubKeyLen);
  log('Issuer Public Key Exponent Length: ' + pubKeyExpLen);
  log('Issuer Public Key or Leftmost Digits: ' + bytesToHex(pubKeyOrLeft));
  log('Hash Result: ' + bytesToHex(hashResult));

  // Step 7: Hash check
  // Concatenate: certFormat, issuerId, certExpDate, certSerial, hashAlgInd, pubKeyAlgInd, pubKeyLen, pubKeyExpLen, pubKeyOrLeft, remainder, exponent
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
  if (remainderHex) hashDataArr.push(...hexToBytes(remainderHex));
  if (issuerExpHex) hashDataArr.push(...hexToBytes(issuerExpHex));
  let hashData = new Uint8Array(hashDataArr);
  log('Hash Data (for SHA1): ' + bytesToHex(hashData));

  // Use existing hash function (from hash tool)
  async function calcSHA1(hexStr) {
    if (!window.crypto || !window.crypto.subtle) return null;
    const buf = new Uint8Array(hexStr.match(/.{2}/g).map(b => parseInt(b, 16)));
    const hashBuf = await window.crypto.subtle.digest('SHA-1', buf);
    return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  calcSHA1(bytesToHex(hashData)).then(calcHash => {
    log('Calculated SHA1: ' + calcHash);
    log('Recovered Hash:  ' + bytesToHex(hashResult));
    if (calcHash === bytesToHex(hashResult)) {
      log('Hash matches!');
    } else {
      log('Hash does NOT match!');
    }
    log('Validation complete.');
  });
});
</script>
