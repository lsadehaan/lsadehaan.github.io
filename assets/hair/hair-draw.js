/* Hair Day — draws a cartoon portrait as inline SVG from a "look" object */
(function (global) {
  "use strict";
  const D = global.HairData;

  let uid = 0;

  /* deterministic tiny RNG so a look always draws the same way */
  function rng(seedStr) {
    let h = 1779033703 ^ String(seedStr).length;
    for (let i = 0; i < String(seedStr).length; i++) {
      h = Math.imul(h ^ String(seedStr).charCodeAt(i), 3432918353);
      h = (h << 13) | (h >>> 19);
    }
    let a = h >>> 0;
    return function () {
      a |= 0; a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  const HEAD = { cx: 110, cy: 104, rx: 42, ry: 48 };
  const HAIRLINE = 64;

  function n(v) { return Math.round(v * 10) / 10; }

  /* ------------------------------------------------------------- utilities */
  function circ(cx, cy, r, fill, extra) {
    return '<circle cx="' + n(cx) + '" cy="' + n(cy) + '" r="' + n(r) +
      '" fill="' + fill + '"' + (extra || "") + "/>";
  }
  function ell(cx, cy, rx, ry, fill, rot, extra) {
    return '<ellipse cx="' + n(cx) + '" cy="' + n(cy) + '" rx="' + n(rx) + '" ry="' + n(ry) +
      '" fill="' + fill + '"' +
      (rot ? ' transform="rotate(' + n(rot) + " " + n(cx) + " " + n(cy) + ')"' : "") +
      (extra || "") + "/>";
  }
  function path(d, fill, extra) {
    return '<path d="' + d + '" fill="' + (fill || "none") + '"' + (extra || "") + "/>";
  }

  /* a wobbly bottom edge, left to right */
  function wavyEdge(x0, x1, y, bumps, amp) {
    let d = "";
    const step = (x1 - x0) / bumps;
    for (let i = 0; i < bumps; i++) {
      const cx = x0 + step * (i + 0.5);
      const ex = x0 + step * (i + 1);
      const dir = i % 2 === 0 ? 1 : -0.35;
      d += " Q" + n(cx) + "," + n(y + amp * dir) + " " + n(ex) + "," + n(y);
    }
    return d;
  }

  /* fluffy outline of circles around an ellipse */
  function cloud(cx, cy, rx, ry, fill, count, size, seed, from, to) {
    const r = rng(seed);
    let out = ell(cx, cy, rx, ry, fill);
    const a0 = from === undefined ? 0 : from;
    const a1 = to === undefined ? Math.PI * 2 : to;
    for (let i = 0; i < count; i++) {
      const a = a0 + ((a1 - a0) * i) / count;
      const jitter = 0.82 + r() * 0.3;
      const px = cx + Math.cos(a) * rx * jitter;
      const py = cy + Math.sin(a) * ry * jitter;
      out += circ(px, py, size * (0.75 + r() * 0.5), fill);
    }
    return out;
  }

  /* a tapered lock of hair from (ax,ay) at angle deg, length len */
  function lock(ax, ay, deg, len, w, fill, bend) {
    const a = (deg * Math.PI) / 180;
    const ex = ax + Math.cos(a) * len;
    const ey = ay + Math.sin(a) * len;
    const px = -Math.sin(a) * w;
    const py = Math.cos(a) * w;
    const bx = Math.cos(a + Math.PI / 2) * (bend || 0);
    const by = Math.sin(a + Math.PI / 2) * (bend || 0);
    const m1x = ax + Math.cos(a) * len * 0.45 + bx;
    const m1y = ay + Math.sin(a) * len * 0.45 + by;
    const d =
      "M" + n(ax + px) + "," + n(ay + py) +
      " C" + n(m1x + px * 1.15) + "," + n(m1y + py * 1.15) +
      " " + n(ex + px * 0.5) + "," + n(ey + py * 0.5) +
      " " + n(ex) + "," + n(ey) +
      " C" + n(ex - px * 0.5) + "," + n(ey - py * 0.5) +
      " " + n(m1x - px * 1.15) + "," + n(m1y - py * 1.15) +
      " " + n(ax - px) + "," + n(ay - py) + " Z";
    return { d: path(d, fill), ex: ex, ey: ey, mx: m1x, my: m1y };
  }

  function texturedTail(ax, ay, deg, len, w, C, tex, seed, shape) {
    const a = (deg * Math.PI) / 180;
    if (shape === "bubble") {
      let b = "";
      const n4 = 4;
      for (let i = 0; i < n4; i++) {
        const t = (i + 0.55) / n4;
        const px = ax + Math.cos(a) * len * t;
        const py = ay + Math.sin(a) * len * t;
        b += ell(px, py, w * 1.45 * (1 - i * 0.09), (len / n4) * 0.46, C.hex, deg + 90);
        b += ell(px + Math.cos(a) * (len / n4) * 0.5, py + Math.sin(a) * (len / n4) * 0.5,
          w * 0.55, w * 0.4, C.shade, deg + 90);
      }
      return b;
    }
    let out = lock(ax, ay, deg, len, w, C.hex, tex === "straight" ? 0 : 10).d;
    if (tex === "curly" || tex === "coily") {
      const r = rng(seed);
      const bumps = tex === "coily" ? 9 : 7;
      for (let i = 1; i <= bumps; i++) {
        const t = i / (bumps + 1);
        const px = ax + Math.cos(a) * len * t;
        const py = ay + Math.sin(a) * len * t;
        const spread = w * (1 - t * 0.35);
        out += circ(px - Math.sin(a) * spread, py + Math.cos(a) * spread, w * (0.42 + r() * 0.2), C.hex);
        out += circ(px + Math.sin(a) * spread, py - Math.cos(a) * spread, w * (0.42 + r() * 0.2), C.hex);
      }
    } else if (tex === "wavy") {
      for (let i = 1; i <= 4; i++) {
        const t = i / 5;
        const px = ax + Math.cos(a) * len * t;
        const py = ay + Math.sin(a) * len * t;
        const s = (i % 2 ? 1 : -1) * w * 0.85;
        out += circ(px - Math.sin(a) * s, py + Math.cos(a) * s, w * 0.42, C.hex);
      }
    }
    return out;
  }

  /* a braid: chain of tilted beans along a straight axis */
  function braid(ax, ay, deg, len, w, C, tieColor) {
    const a = (deg * Math.PI) / 180;
    const segs = Math.max(4, Math.round(len / 13));
    let out = lock(ax, ay, deg, len * 0.98, w * 0.55, C.shade).d;
    for (let i = 0; i < segs; i++) {
      const t = (i + 0.5) / segs;
      const px = ax + Math.cos(a) * len * t;
      const py = ay + Math.sin(a) * len * t;
      const size = w * (1 - t * 0.35);
      out += ell(px, py, size, size * 0.62, i % 2 ? C.hex : C.light, deg + (i % 2 ? 32 : -32));
    }
    const ex = ax + Math.cos(a) * len;
    const ey = ay + Math.sin(a) * len;
    out += ell(ex - Math.cos(a) * 4, ey - Math.sin(a) * 4, w * 0.5, w * 0.34, tieColor || "#ff6fae", deg);
    out += lock(ex - Math.cos(a) * 3, ey - Math.sin(a) * 3, deg, 14, w * 0.4, C.shade).d;
    return out;
  }

  /* braid following an arc (crown / front) */
  function arcBraid(pts, w, C) {
    let out = "";
    for (let i = 0; i < pts.length; i++) {
      const p = pts[i];
      out += ell(p[0], p[1], w, w * 0.62, i % 2 ? C.shade : C.light, p[2] + (i % 2 ? 30 : -30),
        ' stroke="' + C.shade + '" stroke-width="1"');
    }
    return out;
  }

  function arcPoints(cx, cy, rx, ry, a0, a1, count) {
    const pts = [];
    for (let i = 0; i <= count; i++) {
      const a = a0 + ((a1 - a0) * i) / count;
      pts.push([cx + Math.cos(a) * rx, cy + Math.sin(a) * ry, (a * 180) / Math.PI + 90]);
    }
    return pts;
  }

  /* ------------------------------------------------------------ components */
  function looseHair(look, C, seed) {
    const len = look.length || "medium";
    const tex = look.texture || "straight";
    const yBot = { short: 138, medium: 182, long: 228 }[len];
    if (tex === "curly" || tex === "coily") {
      const top = 46;
      const cy = (top + yBot) / 2;
      const ry = (yBot - top) / 2;
      const rx = len === "short" ? 60 : 58;
      const count = tex === "coily" ? 26 : 20;
      const size = tex === "coily" ? 13 : 12;
      return cloud(110, cy, rx, ry, C.hex, count, size, seed + "loose") +
        cloud(110, cy - ry * 0.3, rx * 0.8, ry * 0.7, C.light, 8, size * 0.6, seed + "hl", 0.9, 2.3);
    }
    const hw = 56;
    const amp = tex === "wavy" ? 13 : 9;
    const bumps = tex === "wavy" ? 4 : 2;
    let d = "M110,48 C" + n(110 - hw * 0.7) + ",48 " + n(110 - hw) + ",72 " +
      n(110 - hw) + ",106 C" + n(110 - hw - 2) + "," + n(yBot - 60) + " " +
      n(110 - hw + 2) + "," + n(yBot - 18) + " " + n(110 - hw + 2) + "," + n(yBot);
    d += wavyEdge(110 - hw + 2, 110 + hw - 2, yBot, bumps * 2, amp);
    d += " C" + n(110 + hw - 2) + "," + n(yBot - 18) + " " + n(110 + hw + 2) + "," + n(yBot - 60) +
      " " + n(110 + hw) + ",106 C" + n(110 + hw) + ",72 " + n(110 + hw * 0.7) + ",48 110,48 Z";
    let out = path(d, C.hex);
    /* shine strands */
    out += path("M" + n(110 - hw + 16) + ",96 C" + n(110 - hw + 8) + "," + n(yBot * 0.6) +
      " " + n(110 - hw + 10) + "," + n(yBot * 0.8) + " " + n(110 - hw + 18) + "," + n(yBot - 14),
      null, ' stroke="' + C.light + '" stroke-width="5" stroke-linecap="round" opacity="0.65"');
    out += path("M" + n(110 + hw - 18) + ",100 C" + n(110 + hw - 6) + "," + n(yBot * 0.62) +
      " " + n(110 + hw - 10) + "," + n(yBot * 0.82) + " " + n(110 + hw - 20) + "," + n(yBot - 10),
      null, ' stroke="' + C.shade + '" stroke-width="4" stroke-linecap="round" opacity="0.5"');
    return out;
  }

  function pulledBack(C) {
    /* smooth hair hugging the skull, used when everything is tied up */
    return ell(110, 100, 50, 56, C.hex) +
      path("M60,104 C60,58 82,42 110,42 C138,42 160,58 160,104 C156,80 134,66 110,66 C86,66 64,80 60,104 Z", C.light, ' opacity="0.35"');
  }

  function scalp(C, tex, seed) {
    let out = path(
      "M62,112 C56,50 84,34 110,34 C136,34 164,50 158,112 C152,78 136," + HAIRLINE +
      " 110," + HAIRLINE + " C84," + HAIRLINE + " 68,78 62,112 Z", C.hex);
    if (tex === "curly" || tex === "coily") {
      out += cloud(110, 74, 50, 42, C.hex, tex === "coily" ? 16 : 13, 11, seed + "scalp", Math.PI * 1.02, Math.PI * 1.98);
    }
    out += path("M74,74 C82,56 100,48 116,50", null,
      ' stroke="' + C.light + '" stroke-width="6" stroke-linecap="round" opacity="0.55"');
    return out;
  }

  function bangs(kind, C) {
    if (kind === "straight") {
      return path("M70,62 C70,86 84,94 110,94 C136,94 150,86 150,62 C142,52 126,46 110,46 C94,46 78,52 70,62 Z", C.hex) +
        path("M80,64 C88,80 100,86 110,86", null, ' stroke="' + C.light + '" stroke-width="4" stroke-linecap="round" opacity="0.5"');
    }
    if (kind === "side") {
      return path("M66,60 C70,92 98,96 132,80 C146,74 152,64 150,54 C132,44 96,42 66,60 Z", C.hex) +
        path("M78,58 C92,76 112,82 134,72", null, ' stroke="' + C.light + '" stroke-width="4" stroke-linecap="round" opacity="0.5"');
    }
    if (kind === "curtain") {
      return path("M68,58 C66,84 78,94 96,92 C94,76 100,64 110,58 C96,46 78,48 68,58 Z", C.hex) +
        path("M152,58 C154,84 142,94 124,92 C126,76 120,64 110,58 C124,46 142,48 152,58 Z", C.hex);
    }
    return "";
  }

  function faceShape(skin, shade) {
    return ell(HEAD.cx, HEAD.cy, HEAD.rx, HEAD.ry, skin) +
      circ(68, 112, 9, skin) + circ(152, 112, 9, skin) +
      circ(68, 112, 4.5, shade, ' opacity="0.45"') + circ(152, 112, 4.5, shade, ' opacity="0.45"');
  }

  function face(mood) {
    const eye = function (x) {
      return ell(x, 110, 7.5, 8.5, "#ffffff") +
        circ(x + 0.5, 111, 4.6, "#3b2240") +
        circ(x + 2, 108.5, 1.7, "#ffffff") +
        path("M" + (x - 8) + ",96 Q" + x + ",90 " + (x + 8) + ",95", null,
          ' stroke="#3b2240" stroke-width="2.6" stroke-linecap="round" opacity="0.8"');
    };
    let out = eye(92) + eye(128);
    out += path("M106,120 Q110,126 114,121", null,
      ' stroke="#b98071" stroke-width="2.4" stroke-linecap="round" fill="none"');
    const smile = mood === "wow"
      ? ell(110, 136, 8, 9, "#c85a72")
      : path("M96,132 Q110,145 124,132", null,
        ' stroke="#c85a72" stroke-width="3.4" stroke-linecap="round" fill="none"');
    out += smile;
    out += ell(80, 126, 8, 5, "#ff9bb5", 0, ' opacity="0.45"');
    out += ell(140, 126, 8, 5, "#ff9bb5", 0, ' opacity="0.45"');
    return out;
  }

  function body(shirt) {
    return path("M14,280 C18,214 58,186 110,186 C162,186 202,214 206,280 Z", shirt) +
      path("M92,168 C92,182 128,182 128,168 L128,150 L92,150 Z", "var(--skin)");
  }

  /* ------------------------------------------------------------ accessories */
  function bowShape(x, y, color, scale, rot) {
    const s = scale || 1;
    const g = '<g transform="translate(' + n(x) + "," + n(y) + ') scale(' + s + ') rotate(' + (rot || 0) + ')">';
    return g +
      path("M0,0 C-6,-14 -26,-16 -26,-4 C-26,8 -8,8 0,0 Z", color) +
      path("M0,0 C6,-14 26,-16 26,-4 C26,8 8,8 0,0 Z", color) +
      path("M-4,2 C-12,14 -16,20 -12,22 C-8,24 -4,12 -1,4 Z", color) +
      path("M4,2 C12,14 16,20 12,22 C8,24 4,12 1,4 Z", color) +
      circ(0, -1, 6, color) + circ(-2, -3, 2, "#ffffff", ' opacity="0.5"') +
      "</g>";
  }

  function flowerShape(x, y, color, s) {
    let out = "";
    for (let i = 0; i < 5; i++) {
      const a = (i / 5) * Math.PI * 2;
      out += ell(x + Math.cos(a) * 5 * s, y + Math.sin(a) * 5 * s, 4.4 * s, 3.4 * s, color, (a * 180) / Math.PI);
    }
    return out + circ(x, y, 2.6 * s, "#ffe07a");
  }

  function heartShape(x, y, color, s) {
    return '<path transform="translate(' + n(x) + "," + n(y) + ') scale(' + s +
      ')" d="M0,5 C-9,-2 -7,-10 -2.5,-8 C-1,-7.2 0,-6 0,-5 C0,-6 1,-7.2 2.5,-8 C7,-10 9,-2 0,5 Z" fill="' + color + '"/>';
  }

  function starShape(x, y, s, color) {
    return '<path transform="translate(' + n(x) + "," + n(y) + ') scale(' + s +
      ')" d="M0,-6 L1.7,-1.7 L6,0 L1.7,1.7 L0,6 L-1.7,1.7 L-6,0 L-1.7,-1.7 Z" fill="' + color + '"/>';
  }

  function featherShape(x, y, rot, color, s) {
    return '<g transform="translate(' + n(x) + "," + n(y) + ") rotate(" + n(rot) + ") scale(" + s + ')">' +
      path("M0,0 C-9,-16 -7,-40 0,-52 C7,-40 9,-16 0,0 Z", color) +
      path("M0,-2 L0,-48", null, ' stroke="#ffffff" stroke-width="1.6" opacity="0.6"') +
      "</g>";
  }

  function accessories(look, C, A, anchors) {
    const acc = look.accessory;
    const col = A[look.accColor] || A.pink;
    let out = "";
    if (acc === "bow") {
      out += bowShape(anchors.tie.x, anchors.tie.y, col, 1.05, anchors.tie.rot || 0);
    } else if (acc === "flower") {
      out += flowerShape(74, 74, col, 1.2) + flowerShape(92, 58, col, 0.95) +
        flowerShape(146, 76, col, 1.1) + flowerShape(128, 56, "#fff3b0", 0.85);
    } else if (acc === "headband") {
      out += path("M60,104 C60,50 84,36 110,36 C136,36 160,50 160,104", null,
        ' stroke="' + col + '" stroke-width="9" stroke-linecap="round" fill="none"') +
        path("M66,88 C70,58 88,46 110,46", null, ' stroke="#ffffff" stroke-width="3" opacity="0.5" fill="none"');
    } else if (acc === "scrunchie") {
      out += ell(anchors.tie.x, anchors.tie.y, 17, 12, col, anchors.tie.rot || 0) +
        ell(anchors.tie.x, anchors.tie.y, 9, 6, "#ffffff", anchors.tie.rot || 0, ' opacity="0.35"');
    } else if (acc === "tiara") {
      const y = anchors.top.y;
      out += path("M84," + n(y + 10) + " L92," + n(y - 8) + " L101," + n(y + 3) +
        " L110," + n(y - 14) + " L119," + n(y + 3) + " L128," + n(y - 8) +
        " L136," + n(y + 10) + " Z", col, ' stroke="#e0a800" stroke-width="1.5"') +
        circ(110, y - 12, 3.4, "#fff") + circ(92, y - 6, 2.4, "#fff") + circ(128, y - 6, 2.4, "#fff");
    } else if (acc === "ribbons") {
      anchors.tails.forEach(function (t, i) {
        const c = i % 2 ? A.gold : col;
        for (let k = 1; k <= 4; k++) {
          const tt = k / 5;
          const a = (t.deg * Math.PI) / 180;
          out += ell(t.x + Math.cos(a) * t.len * tt, t.y + Math.sin(a) * t.len * tt,
            t.w * 0.95, 4, c, t.deg + 90);
        }
        const a2 = (t.deg * Math.PI) / 180;
        out += bowShape(t.x + Math.cos(a2) * t.len * 0.96, t.y + Math.sin(a2) * t.len * 0.96, c, 0.7, 0);
      });
      if (!anchors.tails.length) out += bowShape(anchors.tie.x, anchors.tie.y, col, 0.9, 0);
    } else if (acc === "bandana") {
      out += path("M58,96 C62,48 86,38 110,38 C134,38 158,48 162,96 C140,80 80,80 58,96 Z", col) +
        path("M58,96 C80,84 140,84 162,96", null, ' stroke="#ffffff" stroke-width="2.5" opacity="0.4" fill="none"') +
        circ(160, 92, 9, col) + path("M162,92 L182,80 L178,98 Z", col) +
        circ(86, 62, 3, "#fff", ' opacity="0.7"') + circ(120, 52, 3, "#fff", ' opacity="0.7"');
    } else if (acc === "clips") {
      const cols = [col, A.gold, A.mint, A.purple];
      for (let i = 0; i < 4; i++) {
        out += '<rect x="' + (62 + i * 3) + '" y="' + (72 + i * 15) + '" width="26" height="8" rx="4" fill="' +
          cols[i % cols.length] + '" transform="rotate(-20 ' + (62 + i * 3) + ' ' + (72 + i * 15) + ')"/>';
      }
    } else if (acc === "feathers") {
      out += featherShape(80, 48, -22, col, 0.85) + featherShape(96, 40, -10, A.gold, 1) +
        featherShape(110, 36, 0, col, 1.15) + featherShape(124, 40, 10, A.mint, 1) +
        featherShape(140, 48, 22, A.gold, 0.85) +
        path("M62,60 C74,40 146,40 158,60", null, ' stroke="' + col + '" stroke-width="7" fill="none" stroke-linecap="round"');
    } else if (acc === "glitter") {
      const r = rng("glitter" + look.updo + look.length);
      for (let i = 0; i < 16; i++) {
        const x = 58 + r() * 104;
        const y = 26 + r() * 120;
        out += starShape(x, y, 0.35 + r() * 0.55, i % 3 ? "#ffe07a" : col);
      }
    } else if (acc === "santa") {
      out += path("M56,74 C62,30 108,16 140,26 C166,34 172,52 170,62 C150,44 92,44 56,74 Z", "#e63946") +
        path("M52,76 C78,52 148,50 172,64 C176,74 168,82 156,80 C120,72 84,76 60,88 C52,88 48,82 52,76 Z", "#ffffff") +
        circ(176, 30, 12, "#ffffff") +
        path("M168,60 C176,50 178,40 176,32", null, ' stroke="#e63946" stroke-width="12" fill="none" stroke-linecap="round"');
    } else if (acc === "spider") {
      const sx = anchors.top.x, sy = anchors.top.y + 20;
      for (let i = 0; i < 4; i++) {
        const dy = -8 + i * 6;
        out += path("M" + sx + "," + (sy + dy) + " C" + (sx - 16) + "," + (sy + dy - 6) + " " +
          (sx - 24) + "," + (sy + dy + 8) + " " + (sx - 28) + "," + (sy + dy + 4), null,
          ' stroke="#2b2028" stroke-width="2.4" fill="none"');
        out += path("M" + sx + "," + (sy + dy) + " C" + (sx + 16) + "," + (sy + dy - 6) + " " +
          (sx + 24) + "," + (sy + dy + 8) + " " + (sx + 28) + "," + (sy + dy + 4), null,
          ' stroke="#2b2028" stroke-width="2.4" fill="none"');
      }
      out += ell(sx, sy, 11, 13, "#2b2028") + circ(sx, sy - 12, 7, "#2b2028") +
        circ(sx - 3, sy - 13, 2, "#ff6fae") + circ(sx + 3, sy - 13, 2, "#ff6fae");
    } else if (acc === "hearts") {
      out += heartShape(76, 78, col, 1.2) + heartShape(96, 56, col, 0.9) +
        heartShape(124, 54, col, 1.1) + heartShape(144, 78, col, 0.95);
    } else if (acc === "sunhat" || acc === "strawhat") {
      const brim = acc === "sunhat" ? 96 : 84;
      const base = acc === "sunhat" ? col : "#e9c46a";
      out += ell(110, 72, brim, 20, base) +
        path("M66,72 C66,30 96,20 110,20 C124,20 154,30 154,72 Z", base) +
        path("M66,64 C88,74 132,74 154,64 L154,72 C132,80 88,80 66,72 Z",
          acc === "sunhat" ? "#ffffff" : "#c1121f") +
        ell(110, 72, brim, 20, "#000", 0, ' opacity="0.06"');
    }
    return out;
  }

  /* ----------------------------------------------------------------- render */
  function render(look, opts) {
    opts = opts || {};
    const HC = D.HAIR_COLORS[look.color] || D.HAIR_COLORS.chestnut;
    const A = D.ACC_COLORS;
    const id = "hg" + ++uid;
    let C = HC;
    let defs = "";
    if (HC.rainbow) {
      defs = '<linearGradient id="' + id + '" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="#ff6fae"/><stop offset="30%" stop-color="#ffc83d"/>' +
        '<stop offset="60%" stop-color="#2dd4bf"/><stop offset="100%" stop-color="#8b5cf6"/>' +
        "</linearGradient>";
      C = { hex: "url(#" + id + ")", light: "#ffe3f1", shade: "#a34b7e" };
    }
    const skin = D.SKIN_TONES[look.skin] || D.SKIN_TONES.light;
    const shirt = opts.shirt || "#8b5cf6";
    const tex = look.texture || "straight";
    const seed = [look.length, tex, look.updo, look.braid, look.accessory].join("|");

    const up = look.updo && look.updo !== "none" && look.updo !== "halfUp";
    const fullyUp = up && look.updo !== "ponyLow" && look.updo !== "ponySide";

    let back = "", front = "", top = "", overHead = "";
    const tails = [];
    let tie = { x: 110, y: 58, rot: 0 };
    let topAnchor = { x: 110, y: 40 };

    /* --- the mass of hair -------------------------------------------- */
    if (look.braid === "two" && !up) {
      back += pulledBack(C);
    } else if (up) {
      back += pulledBack(C);
    } else {
      back += looseHair(look, C, seed);
    }

    /* --- ties, tails, buns ------------------------------------------- */
    const tlen = { short: 58, medium: 82, long: 104 }[look.length || "medium"];
    switch (look.updo) {
      case "ponyHigh":
        back += ell(110, 44, 27, 17, C.hex);
        overHead += texturedTail(120, 50, 54, tlen, 15, C, tex, seed + "t", look.tail);
        tails.push({ x: 120, y: 50, deg: 54, len: tlen, w: 15 });
        tie = { x: 114, y: 47, rot: 0 };
        topAnchor = { x: 110, y: 36 };
        break;
      case "ponyLow":
        back += texturedTail(110, 146, 90, tlen, 17, C, tex, seed + "t");
        tails.push({ x: 110, y: 146, deg: 90, len: tlen, w: 17 });
        tie = { x: 110, y: 150, rot: 0 };
        break;
      case "ponySide":
        back += texturedTail(152, 128, 74, tlen, 15, C, tex, seed + "t");
        tails.push({ x: 152, y: 128, deg: 74, len: tlen, w: 15 });
        tie = { x: 152, y: 128, rot: 20 };
        break;
      case "pigtails":
        back += texturedTail(64, 96, 118, tlen * 0.86, 13, C, tex, seed + "l");
        back += texturedTail(156, 96, 62, tlen * 0.86, 13, C, tex, seed + "r");
        tails.push({ x: 64, y: 96, deg: 118, len: tlen * 0.86, w: 13 });
        tails.push({ x: 156, y: 96, deg: 62, len: tlen * 0.86, w: 13 });
        tie = { x: 66, y: 94, rot: 0 };
        break;
      case "bunTop":
        top += ell(110, 40, 20, 13, C.hex);
        top += (tex === "curly" || tex === "coily")
          ? cloud(110, 26, 22, 20, C.hex, 12, 10, seed + "bun")
          : circ(110, 26, 22, C.hex) +
            path("M96,22 C100,12 122,12 126,24", null, ' stroke="' + C.light + '" stroke-width="4" fill="none" stroke-linecap="round"');
        tie = { x: 110, y: 44, rot: 0 };
        topAnchor = { x: 110, y: 6 };
        break;
      case "bunsTwo":
        top += (tex === "curly" || tex === "coily")
          ? cloud(72, 36, 17, 16, C.hex, 10, 8, seed + "b1") + cloud(148, 36, 17, 16, C.hex, 10, 8, seed + "b2")
          : circ(72, 36, 17, C.hex) + circ(148, 36, 17, C.hex) +
            path("M62,32 C66,24 80,24 84,34", null, ' stroke="' + C.light + '" stroke-width="3.4" fill="none" stroke-linecap="round"') +
            path("M138,32 C142,24 156,24 160,34", null, ' stroke="' + C.light + '" stroke-width="3.4" fill="none" stroke-linecap="round"');
        top += ell(76, 50, 13, 9, C.hex) + ell(144, 50, 13, 9, C.hex);
        tie = { x: 72, y: 50, rot: 0 };
        topAnchor = { x: 110, y: 22 };
        break;
      case "bunLow":
        back += ell(110, 152, 31, 22, C.hex);
        back += path("M92,148 C98,134 126,134 132,150", null,
          ' stroke="' + C.light + '" stroke-width="4" fill="none" stroke-linecap="round"');
        tie = { x: 110, y: 148, rot: 0 };
        break;
      case "knots": {
        const spots = [[84, 46], [110, 36], [136, 46], [70, 72], [150, 72], [110, 62]];
        spots.forEach(function (s, i) {
          top += circ(s[0], s[1], 10 - (i % 2), C.hex) +
            path("M" + (s[0] - 6) + "," + (s[1] - 2) + " C" + (s[0] - 2) + "," + (s[1] - 9) + " " +
              (s[0] + 6) + "," + (s[1] - 8) + " " + (s[0] + 6) + "," + (s[1] + 1), null,
              ' stroke="' + C.shade + '" stroke-width="2.4" fill="none"');
        });
        topAnchor = { x: 110, y: 22 };
        break;
      }
      case "halfUp":
        back += ell(110, 50, 32, 18, C.hex);
        top += ell(110, 30, 17, 14, C.hex) +
          path("M99,26 C103,18 119,18 122,28", null,
            ' stroke="' + C.light + '" stroke-width="3.4" fill="none" stroke-linecap="round"') +
          ell(110, 42, 15, 7, C.shade, 0, ' opacity="0.55"');
        tie = { x: 110, y: 42, rot: 0 };
        topAnchor = { x: 110, y: 14 };
        break;
      default:
        break;
    }

    /* --- braids ------------------------------------------------------ */
    if (look.braid === "one") {
      back += braid(110, 140, 90, tlen + 10, 11, C, A[look.accColor] || A.pink);
      tails.push({ x: 110, y: 140, deg: 90, len: tlen + 10, w: 11 });
    } else if (look.braid === "two") {
      back += braid(70, 112, 105, tlen, 10, C, A[look.accColor] || A.pink);
      back += braid(150, 112, 75, tlen, 10, C, A[look.accColor] || A.pink);
      tails.push({ x: 70, y: 112, deg: 105, len: tlen, w: 10 });
      tails.push({ x: 150, y: 112, deg: 75, len: tlen, w: 10 });
    } else if (look.braid === "crown") {
      front += arcBraid(arcPoints(110, 96, 52, 56, Math.PI * 1.03, Math.PI * 1.97, 11), 9, C);
      topAnchor = { x: 110, y: 34 };
    } else if (look.braid === "front") {
      front += arcBraid(arcPoints(110, 104, 46, 50, Math.PI * 1.12, Math.PI * 1.62, 7), 8.5, C);
    }

    /* --- assemble ---------------------------------------------------- */
    let svg = "";
    svg += body(shirt).replace("var(--skin)", skin);
    svg += back;
    svg += faceShape(skin, "#c98b5f");
    svg += face(opts.mood);
    svg += scalp(C, fullyUp ? "straight" : tex, seed);
    svg += bangs(look.bangs, C);
    if (!up && (tex === "curly" || tex === "coily")) {
      svg += circ(64, 96, 12, C.hex) + circ(156, 96, 12, C.hex);
    }
    svg += overHead;
    svg += top;
    svg += front;
    svg += accessories(look, C, A, { tie: tie, top: topAnchor, tails: tails });

    const w = opts.width || "100%";
    return '<svg viewBox="0 0 220 280" width="' + w + '" xmlns="http://www.w3.org/2000/svg" ' +
      'role="img" aria-label="' + (opts.label || "hairstyle") + '">' +
      (defs ? "<defs>" + defs + "</defs>" : "") + svg + "</svg>";
  }

  /* build a full look from a style + the user's own hair */
  function lookFor(style, profile) {
    const l = Object.assign({}, style.look);
    l.length = l.length || (profile && profile.hairLength) || "medium";
    l.texture = l.texture || (profile && profile.hairTexture) || "straight";
    /* a style that names its own colour (one you made in the salon) keeps it */
    l.color = l.color || (profile && profile.hairColor) || "chestnut";
    l.skin = (profile && profile.skinTone) || "light";
    return l;
  }

  global.HairDraw = { render: render, lookFor: lookFor, rng: rng };
})(window);
