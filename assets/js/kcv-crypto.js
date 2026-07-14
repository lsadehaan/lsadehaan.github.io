// Minimal encrypt-only DES/TDES and AES block ciphers for KCV calculation.
// KCV conventions:
//   DES/TDES: encrypt 8 zero bytes, take first 3 bytes.
//   AES: encrypt 16 bytes of 0x01 (GlobalPlatform SCP03 convention), take first 3 bytes.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.KCV = factory();
})(typeof self !== "undefined" ? self : this, function () {
  // ---------- DES ----------
  const IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7];
  const FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25];
  const E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1];
  const P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25];
  const PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];
  const PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32];
  const SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];
  const SBOX = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
  ];

  function bytesToBits(bytes) {
    const bits = [];
    for (const b of bytes) for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
    return bits;
  }
  function bitsToBytes(bits) {
    const out = [];
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
      out.push(b);
    }
    return out;
  }
  function permute(bits, table) {
    return table.map(function (i) { return bits[i - 1]; });
  }

  function desSubkeys(keyBytes) {
    const key = permute(bytesToBits(keyBytes), PC1);
    let C = key.slice(0, 28), D = key.slice(28);
    const subkeys = [];
    for (const s of SHIFTS) {
      C = C.slice(s).concat(C.slice(0, s));
      D = D.slice(s).concat(D.slice(0, s));
      subkeys.push(permute(C.concat(D), PC2));
    }
    return subkeys;
  }

  function feistel(R, K) {
    const x = permute(R, E).map(function (b, i) { return b ^ K[i]; });
    const out = [];
    for (let i = 0; i < 8; i++) {
      const c = x.slice(i * 6, i * 6 + 6);
      const row = (c[0] << 1) | c[5];
      const col = (c[1] << 3) | (c[2] << 2) | (c[3] << 1) | c[4];
      const val = SBOX[i][row * 16 + col];
      for (let j = 3; j >= 0; j--) out.push((val >> j) & 1);
    }
    return permute(out, P);
  }

  function desBlock(keyBytes, block, decrypt) {
    const keys = desSubkeys(keyBytes);
    if (decrypt) keys.reverse();
    const bits = permute(bytesToBits(block), IP);
    let L = bits.slice(0, 32), R = bits.slice(32);
    for (let i = 0; i < 16; i++) {
      const f = feistel(R, keys[i]);
      const newR = L.map(function (b, j) { return b ^ f[j]; });
      L = R;
      R = newR;
    }
    return bitsToBytes(permute(R.concat(L), FP));
  }

  function tdesEncryptBlock(keyBytes, block) {
    let k1, k2, k3;
    if (keyBytes.length === 8) { k1 = k2 = k3 = keyBytes; }
    else if (keyBytes.length === 16) { k1 = keyBytes.slice(0, 8); k2 = keyBytes.slice(8, 16); k3 = k1; }
    else if (keyBytes.length === 24) { k1 = keyBytes.slice(0, 8); k2 = keyBytes.slice(8, 16); k3 = keyBytes.slice(16, 24); }
    else throw new Error("DES key must be 8, 16 or 24 bytes");
    return desBlock(k3, desBlock(k2, desBlock(k1, block, false), true), false);
  }

  // ---------- AES (encrypt only) ----------
  const AES_SBOX = (function () {
    const sbox = new Uint8Array(256);
    const rotl8 = function (x, n) { return ((x << n) | (x >>> (8 - n))) & 0xff; };
    let p = 1, q = 1;
    do {
      p = (p ^ (p << 1) ^ (p & 0x80 ? 0x11b : 0)) & 0xff;
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
      if (q & 0x80) q ^= 0x09;
      sbox[p] = (q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63) & 0xff;
    } while (p !== 1);
    sbox[0] = 0x63;
    return sbox;
  })();

  const xtime = function (b) { return ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff; };

  function aesKeyExpansion(keyBytes) {
    const Nk = keyBytes.length / 4;
    const Nr = Nk + 6;
    const w = [];
    for (let i = 0; i < Nk; i++) w.push(keyBytes.slice(4 * i, 4 * i + 4));
    let rcon = 1;
    for (let i = Nk; i < 4 * (Nr + 1); i++) {
      let temp = w[i - 1].slice();
      if (i % Nk === 0) {
        temp = [AES_SBOX[temp[1]] ^ rcon, AES_SBOX[temp[2]], AES_SBOX[temp[3]], AES_SBOX[temp[0]]];
        rcon = xtime(rcon);
      } else if (Nk > 6 && i % Nk === 4) {
        temp = temp.map(function (b) { return AES_SBOX[b]; });
      }
      w.push(temp.map(function (b, j) { return b ^ w[i - Nk][j]; }));
    }
    return { w: w, Nr: Nr };
  }

  function aesEncryptBlock(keyBytes, block) {
    if (![16, 24, 32].includes(keyBytes.length)) throw new Error("AES key must be 16, 24 or 32 bytes");
    const exp = aesKeyExpansion(keyBytes);
    const w = exp.w, Nr = exp.Nr;
    const s = block.slice();
    const addRoundKey = function (round) {
      for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[4 * c + r] ^= w[4 * round + c][r];
    };
    const subBytes = function () {
      for (let i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
    };
    const shiftRows = function () {
      for (let r = 1; r < 4; r++) {
        const row = [s[r], s[r + 4], s[r + 8], s[r + 12]];
        for (let c = 0; c < 4; c++) s[r + 4 * c] = row[(c + r) % 4];
      }
    };
    const mixColumns = function () {
      for (let c = 0; c < 4; c++) {
        const a = s.slice(4 * c, 4 * c + 4);
        s[4 * c] = xtime(a[0]) ^ xtime(a[1]) ^ a[1] ^ a[2] ^ a[3];
        s[4 * c + 1] = a[0] ^ xtime(a[1]) ^ xtime(a[2]) ^ a[2] ^ a[3];
        s[4 * c + 2] = a[0] ^ a[1] ^ xtime(a[2]) ^ xtime(a[3]) ^ a[3];
        s[4 * c + 3] = xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xtime(a[3]);
      }
    };
    addRoundKey(0);
    for (let round = 1; round < Nr; round++) {
      subBytes(); shiftRows(); mixColumns(); addRoundKey(round);
    }
    subBytes(); shiftRows(); addRoundKey(Nr);
    return s;
  }

  // ---------- KCV ----------
  function hexToBytes(hex) {
    const out = [];
    for (let i = 0; i + 2 <= hex.length; i += 2) out.push(parseInt(hex.substr(i, 2), 16));
    return out;
  }
  function bytesToHex(bytes) {
    return bytes.map(function (b) { return b.toString(16).padStart(2, "0"); }).join("").toUpperCase();
  }

  function calcKcv(keyHex, type) {
    const key = hexToBytes(keyHex.replace(/\s+/g, ""));
    if (type === "aes") {
      return bytesToHex(aesEncryptBlock(key, new Array(16).fill(0x01))).substring(0, 6);
    }
    return bytesToHex(tdesEncryptBlock(key, new Array(8).fill(0))).substring(0, 6);
  }

  return {
    tdesEncryptBlock: tdesEncryptBlock,
    aesEncryptBlock: aesEncryptBlock,
    calcKcv: calcKcv
  };
});
