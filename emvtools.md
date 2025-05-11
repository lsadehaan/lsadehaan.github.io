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
      <option value="issuerCert">Issuer Certificate</option>
      <option value="pinBlock">PIN Block (TBD)</option>
      <option value="arqc">ARQC (TBD)</option>
    </select>

    <div id="issuerCertTool" class="emv-tool-section">
      <h3>Issuer Certificate Validator</h3>
      <div style="margin-bottom:10px;">
        <label for="issuerCaPubKey" style="display:block;">CA Public Key (HEX):</label>
        <textarea id="issuerCaPubKey" class="tool-textarea" rows="2" style="width:100%;"></textarea>
      </div>
      <div style="margin-bottom:10px;">
        <label for="issuerCaModulus" style="display:block;">CA Modulus (HEX):</label>
        <textarea id="issuerCaModulus" class="tool-textarea" rows="2" style="width:100%;"></textarea>
      </div>
      <div style="margin-bottom:10px;">
        <label for="issuerCert" style="display:block;">Certificate (HEX):</label>
        <textarea id="issuerCert" class="tool-textarea" rows="4" style="width:100%;"></textarea>
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

// Open the first tab by default on page load
document.addEventListener('DOMContentLoaded', function() {
  var firstTabButton = document.querySelector('.tab-button.active'); // Target the already active one if set in HTML
  if (!firstTabButton) firstTabButton = document.querySelector('.tab-button'); // Fallback
  
  if (firstTabButton) {
    // Simulate a click if openTool expects an event, or call directly
    // openTool(null, firstTabButton.getAttribute('onclick').match(/'([^']+)'/)[1]); 
    // Simpler: ensure the first tab's content is visible directly if no click logic is needed beyond class
    const toolName = firstTabButton.getAttribute('onclick').match(/openTool\(event, '([^']*)'\)/)[1];
    if (toolName) {
        openTool(null, toolName); // Pass null for event if not strictly needed for this init call
        firstTabButton.className += ' active'; // Ensure it's marked active
    }
  }
});

// Add EMV Calcs tool selection logic
const emvCalcSelect = document.getElementById('emvCalcSelect');
const issuerCertTool = document.getElementById('issuerCertTool');
const pinBlockTool = document.getElementById('pinBlockTool');
const arqcTool = document.getElementById('arqcTool');

emvCalcSelect?.addEventListener('change', function() {
  issuerCertTool.style.display = this.value === 'issuerCert' ? '' : 'none';
  pinBlockTool.style.display = this.value === 'pinBlock' ? '' : 'none';
  arqcTool.style.display = this.value === 'arqc' ? '' : 'none';
});

// Add a stub for the Validate button
const validateIssuerCertBtn = document.getElementById('validateIssuerCertBtn');
const issuerCertResults = document.getElementById('issuerCertResults');
validateIssuerCertBtn?.addEventListener('click', function() {
  issuerCertResults.value = 'Validation logic coming soon...';
});
</script>
