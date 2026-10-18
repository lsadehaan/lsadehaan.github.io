/*
 * Procedural fingerprints.
 *
 * Every suspect gets a unique print built from a pattern type (whorl, loop,
 * arch, tented arch) plus a seed. Ridges are traced as evenly spaced
 * streamlines through a Sherlock-Monro orientation field, so the same spec
 * always produces exactly the same ridges. That lets the crime-scene print be
 * the culprit's print, just cropped, turned and smudged.
 */
(function (global) {
  "use strict";

  function rng(seed) {
    var a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // Fingertip outline in pattern space (x across, y down).
  var RX = 0.84;
  var RY = 1.12;
  function insideFinger(x, y) {
    var nx = x / RX;
    var ny = y / RY;
    return nx * nx + ny * ny < 1 && y < 0.98;
  }

  // Cores and deltas for each pattern type, jittered by the seed.
  function singularities(type, rand) {
    function j(s) {
      return (rand() - 0.5) * s;
    }
    switch (type) {
      case "whorl":
        return {
          cores: [
            [j(0.08), -0.2 + j(0.08)],
            [j(0.08), 0.04 + j(0.08)],
          ],
          deltas: [
            [-0.62 + j(0.12), 0.62 + j(0.1)],
            [0.62 + j(0.12), 0.62 + j(0.1)],
          ],
          dome: 0.25,
        };
      case "loopL":
        return {
          cores: [[0.06 + j(0.1), -0.08 + j(0.12)]],
          deltas: [[0.6 + j(0.1), 0.55 + j(0.12)]],
          dome: 0.3,
        };
      case "loopR":
        return {
          cores: [[-0.06 + j(0.1), -0.08 + j(0.12)]],
          deltas: [[-0.6 + j(0.1), 0.55 + j(0.12)]],
          dome: 0.3,
        };
      case "tented":
        return {
          cores: [[j(0.08), 0.02 + j(0.08)]],
          deltas: [[j(0.08), 0.3 + j(0.06)]],
          dome: 0.35,
        };
      default:
        return { cores: [], deltas: [], dome: 0.55 + j(0.15) };
    }
  }

  function makeField(spec) {
    var rand = rng(spec.seed * 7919 + 13);
    var s = singularities(spec.type, rand);
    var archAmp = s.dome;
    var archWidth = 0.42 + rand() * 0.12;
    var archY = -0.05 + (rand() - 0.5) * 0.2;
    var wobble = [rand() * 6, rand() * 6, 0.05 + rand() * 0.05];
    return {
      sing: s,
      angle: function (x, y) {
        var t = 0;
        for (var i = 0; i < s.deltas.length; i++) {
          t -= Math.atan2(y - s.deltas[i][1], x - s.deltas[i][0]);
        }
        for (var k = 0; k < s.cores.length; k++) {
          t += Math.atan2(y - s.cores[k][1], x - s.cores[k][0]);
        }
        t *= 0.5;
        // Arch-shaped dome so the ridges follow the fingertip.
        var g = Math.exp(-(x * x) / (archWidth * archWidth));
        var fade = Math.exp(-Math.pow((y - archY) / 0.75, 2));
        var slope = ((2 * archAmp * x) / (archWidth * archWidth)) * g * fade;
        t += Math.atan(slope);
        // Gentle per-person wobble.
        t +=
          wobble[2] * Math.sin(x * 5 + wobble[0]) * Math.cos(y * 4 + wobble[1]);
        return t;
      },
    };
  }

  // Evenly spaced streamlines (Jobard & Lefer) through the orientation field.
  function traceRidges(spec) {
    var field = makeField(spec);
    var rand = rng(spec.seed * 104729 + 7);
    var dsep = 0.056;
    var dtest = dsep * 0.55;
    var h = dsep * 0.22;
    var cell = dsep;
    var grid = new Map();
    var lines = [];

    function key(cx, cy) {
      return cx * 4096 + cy;
    }
    function addPoint(x, y, id) {
      var k = key(Math.floor((x + 2) / cell), Math.floor((y + 2) / cell));
      var list = grid.get(k);
      if (!list) grid.set(k, (list = []));
      list.push(x, y, id);
    }
    function nearOther(x, y, dist, ignoreId) {
      var cx = Math.floor((x + 2) / cell);
      var cy = Math.floor((y + 2) / cell);
      var d2 = dist * dist;
      for (var i = -1; i <= 1; i++) {
        for (var j = -1; j <= 1; j++) {
          var list = grid.get(key(cx + i, cy + j));
          if (!list) continue;
          for (var p = 0; p < list.length; p += 3) {
            if (list[p + 2] === ignoreId) continue;
            var dx = list[p] - x;
            var dy = list[p + 1] - y;
            if (dx * dx + dy * dy < d2) return true;
          }
        }
      }
      return false;
    }
    function dir(x, y, px, py) {
      var a = field.angle(x, y);
      var vx = Math.cos(a);
      var vy = Math.sin(a);
      if (vx * px + vy * py < 0) {
        vx = -vx;
        vy = -vy;
      }
      return [vx, vy];
    }
    function nearCore(x, y) {
      var cs = field.sing.cores.concat(field.sing.deltas);
      for (var i = 0; i < cs.length; i++) {
        var dx = x - cs[i][0];
        var dy = y - cs[i][1];
        if (dx * dx + dy * dy < dsep * dsep * 0.12) return true;
      }
      return false;
    }
    function half(sx, sy, ivx, ivy, id) {
      var pts = [];
      var x = sx;
      var y = sy;
      var px = ivx;
      var py = ivy;
      var selfGap = Math.ceil((dsep * 2.2) / h);
      for (var n = 0; n < 900; n++) {
        var v1 = dir(x, y, px, py);
        var mx = x + (v1[0] * h) / 2;
        var my = y + (v1[1] * h) / 2;
        var v2 = dir(mx, my, v1[0], v1[1]);
        if (v2[0] * px + v2[1] * py < 0.5) break; // too sharp a turn
        var nx = x + v2[0] * h;
        var ny = y + v2[1] * h;
        if (!insideFinger(nx, ny)) break;
        if (nearCore(nx, ny)) break;
        if (nearOther(nx, ny, dtest, id)) break;
        // Do not run into our own earlier points (spirals).
        var hitSelf = false;
        for (var q = 0; q < pts.length - selfGap; q += 2) {
          var ddx = pts[q] - nx;
          var ddy = pts[q + 1] - ny;
          if (ddx * ddx + ddy * ddy < dtest * dtest) {
            hitSelf = true;
            break;
          }
        }
        if (hitSelf) break;
        pts.push(nx, ny);
        x = nx;
        y = ny;
        px = v2[0];
        py = v2[1];
      }
      return pts;
    }
    function trace(sx, sy) {
      var id = lines.length;
      var a = field.angle(sx, sy);
      var vx = Math.cos(a);
      var vy = Math.sin(a);
      var fwd = half(sx, sy, vx, vy, id);
      var back = half(sx, sy, -vx, -vy, id);
      var pts = [];
      for (var i = back.length - 2; i >= 0; i -= 2)
        pts.push(back[i], back[i + 1]);
      pts.push(sx, sy);
      for (var k = 0; k < fwd.length; k++) pts.push(fwd[k]);
      if (pts.length / 2 < 4) return null;
      for (var p = 0; p < pts.length; p += 2) addPoint(pts[p], pts[p + 1], id);
      lines.push(pts);
      return pts;
    }
    function validSeed(x, y) {
      return (
        insideFinger(x, y) &&
        !nearCore(x, y) &&
        !nearOther(x, y, dsep * 0.98, -1)
      );
    }

    var queue = [];
    var first = trace((rand() - 0.5) * 0.2, 0.55 + rand() * 0.1);
    if (first) queue.push(first);
    function drain() {
      while (queue.length) {
        var line = queue.shift();
        for (var p = 0; p < line.length - 2; p += 6) {
          var x = line[p];
          var y = line[p + 1];
          var tx = line[p + 2] - x;
          var ty = line[p + 3] - y;
          var len = Math.sqrt(tx * tx + ty * ty) || 1;
          var nx = -ty / len;
          var ny = tx / len;
          for (var s = -1; s <= 1; s += 2) {
            var cx = x + nx * dsep * s;
            var cy = y + ny * dsep * s;
            if (validSeed(cx, cy)) {
              var nl = trace(cx, cy);
              if (nl) queue.push(nl);
            }
          }
        }
      }
    }
    drain();
    // Fill any gaps the flood fill missed.
    for (var t = 0; t < 2500; t++) {
      var rx = (rand() * 2 - 1) * RX;
      var ry = (rand() * 2 - 1) * RY;
      if (validSeed(rx, ry)) {
        var l = trace(rx, ry);
        if (l) {
          queue.push(l);
          drain();
        }
      }
    }
    return lines;
  }

  var cache = new Map();
  function ridgesFor(spec) {
    var k = spec.type + ":" + spec.seed;
    if (!cache.has(k)) cache.set(k, traceRidges(spec));
    return cache.get(k);
  }

  // Irregular mask for partial prints; returns a function (x, y) -> bool.
  function partialMask(crop, seed) {
    if (!crop || crop === "full") return null;
    var rand = rng(seed * 31 + 5);
    if (crop === "top") {
      var p1 = rand() * 6;
      return function (x, y) {
        return y < 0.05 + 0.08 * Math.sin(x * 7 + p1);
      };
    }
    if (crop === "left" || crop === "right") {
      var p2 = rand() * 6;
      var sign = crop === "left" ? 1 : -1;
      return function (x, y) {
        return sign * x < 0.18 + 0.07 * Math.sin(y * 6 + p2);
      };
    }
    // "blob": a lumpy oval around the middle of the print.
    var cx = (rand() - 0.5) * 0.2;
    var cy = -0.05 + (rand() - 0.5) * 0.2;
    var bumps = [rand() * 6, rand() * 6, rand() * 6];
    return function (x, y) {
      var dx = x - cx;
      var dy = (y - cy) * 0.8;
      var a = Math.atan2(dy, dx);
      var r =
        0.58 +
        0.08 * Math.sin(a * 3 + bumps[0]) +
        0.05 * Math.sin(a * 5 + bumps[1]) +
        0.04 * Math.sin(a * 7 + bumps[2]);
      return dx * dx + dy * dy < r * r;
    };
  }

  /*
   * Draw a print onto a canvas.
   * spec: { type, seed, scar?: { x1, y1, x2, y2 } }
   * opts: { crop, rotate (deg), smudge (0-1), ink, paper, scale }
   */
  function draw(canvas, spec, opts) {
    opts = opts || {};
    var dpr = Math.min(global.devicePixelRatio || 1, 2);
    var cssW = canvas.clientWidth || canvas.width;
    var cssH = canvas.clientHeight || canvas.height;
    canvas.width = Math.round(cssW * dpr);
    canvas.height = Math.round(cssH * dpr);
    var ctx = canvas.getContext("2d");
    var W = canvas.width;
    var H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    if (opts.paper) {
      ctx.fillStyle = opts.paper;
      ctx.fillRect(0, 0, W, H);
    }
    var lines = ridgesFor(spec);
    var zoom = opts.scale || 1;
    var unit = (Math.min(W / (RX * 2), H / (RY * 2)) / 1.08) * zoom;
    var mask = partialMask(opts.crop, spec.seed + (opts.maskSeed || 0));
    var smudge = opts.smudge || 0;
    var rand = rng(spec.seed * 17 + 3 + (opts.maskSeed || 0));

    ctx.save();
    ctx.translate(W / 2, H / 2);
    ctx.rotate(((opts.rotate || 0) * Math.PI) / 180);
    ctx.scale(unit, unit);
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.strokeStyle = opts.ink || "#2b2420";
    ctx.lineWidth = 0.056 * 0.5;
    if (smudge > 0)
      ctx.filter = "blur(" + (smudge * 1.6 * dpr).toFixed(2) + "px)";

    for (var i = 0; i < lines.length; i++) {
      var pts = lines[i];
      var drawing = false;
      ctx.beginPath();
      for (var p = 0; p < pts.length; p += 2) {
        var x = pts[p];
        var y = pts[p + 1];
        var visible = !mask || mask(x, y);
        if (visible && smudge > 0 && rand() < smudge * 0.04) visible = false;
        if (visible) {
          if (drawing) ctx.lineTo(x, y);
          else ctx.moveTo(x, y);
          drawing = true;
        } else {
          drawing = false;
        }
      }
      ctx.stroke();
    }
    ctx.filter = "none";

    // A scar is a pale line cutting across the ridges.
    if (spec.scar) {
      ctx.globalCompositeOperation = opts.paper
        ? "source-over"
        : "destination-out";
      ctx.strokeStyle = opts.paper || "#000";
      ctx.lineWidth = 0.05;
      ctx.beginPath();
      ctx.moveTo(spec.scar[0], spec.scar[1]);
      ctx.quadraticCurveTo(
        (spec.scar[0] + spec.scar[2]) / 2 + 0.06,
        (spec.scar[1] + spec.scar[3]) / 2 - 0.06,
        spec.scar[2],
        spec.scar[3],
      );
      ctx.stroke();
      ctx.globalCompositeOperation = "source-over";
    }

    // Smudged prints get a few faded patches.
    if (smudge > 0) {
      ctx.globalCompositeOperation = opts.paper
        ? "source-over"
        : "destination-out";
      var blots = Math.round(4 + smudge * 8);
      for (var b = 0; b < blots; b++) {
        var bx = (rand() * 2 - 1) * RX * 0.9;
        var by = (rand() * 2 - 1) * RY * 0.9;
        var br = 0.08 + rand() * 0.18 * smudge;
        var grad = ctx.createRadialGradient(bx, by, 0, bx, by, br);
        grad.addColorStop(
          0,
          opts.paper ? fade(opts.paper, 0.75) : "rgba(0,0,0,0.75)",
        );
        grad.addColorStop(
          1,
          opts.paper ? fade(opts.paper, 0) : "rgba(0,0,0,0)",
        );
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(bx, by, br, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalCompositeOperation = "source-over";
    }
    ctx.restore();
  }

  function fade(hex, alpha) {
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
    if (!m) return hex;
    return (
      "rgba(" +
      parseInt(m[1], 16) +
      "," +
      parseInt(m[2], 16) +
      "," +
      parseInt(m[3], 16) +
      "," +
      alpha +
      ")"
    );
  }

  var NAMES = {
    whorl: "Whorl",
    loopL: "Loop",
    loopR: "Loop",
    arch: "Arch",
    tented: "Tented arch",
  };

  global.Fingerprint = {
    draw: draw,
    ridgesFor: ridgesFor,
    patternName: function (t) {
      return NAMES[t] || t;
    },
  };
})(window);
