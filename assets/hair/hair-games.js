/* Hair Day — the salon sandbox and the two games */
(function (global) {
  "use strict";
  const D = global.HairData;
  const Draw = global.HairDraw;
  const App = global.HairApp;
  const L = App.L, t = App.t, esc = App.esc;

  let ticker = null;
  function stopAll() { if (ticker) { clearInterval(ticker); ticker = null; } }
  window.addEventListener("hashchange", stopAll);

  const GROUPS = [
    ["oLength", "length", ["short", "medium", "long"], "length"],
    ["oTexture", "texture", ["straight", "wavy", "curly", "coily"], "texture"],
    ["oUpdo", "updo", ["none", "ponyHigh", "ponyLow", "ponySide", "pigtails", "bunTop", "bunsTwo", "bunLow", "halfUp", "knots"], "updo"],
    ["oBraid", "braid", ["none", "one", "two", "crown", "front"], "braid"],
    ["oBangs", "bangs", ["none", "straight", "side", "curtain"], "bangs"],
    ["oAcc", "accessory", ["none", "bow", "flower", "headband", "scrunchie", "tiara", "ribbons",
      "bandana", "clips", "feathers", "glitter", "santa", "spider", "hearts", "sunhat", "strawhat"], "accessory"]
  ];

  function optButtons(group, field, values, current) {
    return values.map(function (v) {
      const lab = D.OPT_LABELS[group] && D.OPT_LABELS[group][v] ? D.OPT_LABELS[group][v] : { en: v, pt: v };
      return '<button class="opt' + (current === v ? " on" : "") + '" data-field="' + field +
        '" data-val="' + v + '">' + esc(L(lab)) + "</button>";
    }).join("");
  }

  function colorButtons(field, current, set) {
    return Object.keys(set).map(function (k) {
      const c = set[k];
      const bg = typeof c === "string" ? c
        : (c.rainbow ? "linear-gradient(135deg,#ff6fae,#ffc83d,#2dd4bf,#8b5cf6)" : c.hex);
      return '<button class="swatch' + (current === k ? " on" : "") + '" data-field="' + field +
        '" data-val="' + k + '" style="background:' + bg + '"></button>';
    }).join("");
  }

  function controlPanel(look, fields) {
    let html = "";
    GROUPS.forEach(function (g) {
      if (fields && fields.indexOf(g[1]) < 0) return;
      html += '<div class="opt-group"><h4>' + t(g[0]) + '</h4><div class="opts">' +
        optButtons(g[3], g[1], g[2], look[g[1]]) + "</div></div>";
    });
    if (!fields || fields.indexOf("color") >= 0) {
      html += '<div class="opt-group"><h4>' + t("oColor") + '</h4><div class="opts">' +
        colorButtons("color", look.color, D.HAIR_COLORS) + "</div></div>";
    }
    if (!fields || fields.indexOf("accColor") >= 0) {
      html += '<div class="opt-group"><h4>' + t("oAccColor") + '</h4><div class="opts">' +
        colorButtons("accColor", look.accColor, D.ACC_COLORS) + "</div></div>";
    }
    return html;
  }

  function randomLook(fields, seedRnd) {
    const r = seedRnd || Math.random;
    const pick = function (arr) { return arr[Math.floor(r() * arr.length)]; };
    const look = {
      length: pick(["short", "medium", "long"]),
      texture: pick(["straight", "wavy", "curly", "coily"]),
      updo: pick(["none", "ponyHigh", "ponyLow", "ponySide", "pigtails", "bunTop", "bunsTwo", "bunLow", "halfUp", "knots"]),
      braid: pick(["none", "none", "one", "two", "crown", "front"]),
      bangs: pick(["none", "none", "straight", "side", "curtain"]),
      accessory: pick(["none", "bow", "flower", "headband", "scrunchie", "tiara", "ribbons",
        "bandana", "clips", "feathers", "glitter", "hearts"]),
      color: pick(Object.keys(D.HAIR_COLORS)),
      accColor: pick(Object.keys(D.ACC_COLORS)),
      skin: App.state.profile.skinTone,
      tail: "plain"
    };
    if (fields) {
      const base = defaultLook();
      Object.keys(look).forEach(function (k) {
        if (fields.indexOf(k) < 0 && k !== "skin" && k !== "tail") look[k] = base[k];
      });
    }
    return look;
  }

  function defaultLook() {
    const p = App.state.profile;
    return {
      length: p.hairLength, texture: p.hairTexture, updo: "none", braid: "none",
      bangs: "none", accessory: "none", color: p.hairColor, accColor: "pink",
      skin: p.skinTone, tail: "plain"
    };
  }

  function wire(root, look, after) {
    Array.prototype.forEach.call(root.querySelectorAll("[data-field]"), function (b) {
      b.addEventListener("click", function () {
        look[b.dataset.field] = b.dataset.val;
        after();
      });
    });
  }

  /* ------------------------------------------------------------ the salon */
  function salon(mount) {
    stopAll();
    let look = defaultLook();

    function draw() {
      mount.innerHTML =
        '<div class="page-head"><button class="back-btn" data-go="#/">←</button><h2>💇 ' +
          t("menuSalon") + "</h2></div>" +
        '<p class="muted" style="margin:-8px 0 16px">' + t("salonHint") + "</p>" +
        '<div class="salon">' +
          '<div class="card"><div class="portrait">' +
            Draw.render(look, { mood: "wow", label: "your style" }) + "</div>" +
            '<div class="btn-row" style="margin-top:14px;justify-content:center">' +
              '<button class="btn primary" id="savestyle">💾 ' + t("save") + "</button>" +
              '<button class="btn" id="shuffle">🎲 ' + t("randomize") + "</button>" +
              '<button class="btn ghost" id="resetlook">↺ ' + t("reset") + "</button>" +
            "</div></div>" +
          '<div class="card">' + controlPanel(look) + "</div>" +
        "</div>";

      wire(mount, look, draw);
      mount.querySelector("#shuffle").addEventListener("click", function () {
        look = randomLook(); look.skin = App.state.profile.skinTone; draw();
      });
      mount.querySelector("#resetlook").addEventListener("click", function () {
        look = defaultLook(); draw();
      });
      mount.querySelector("#savestyle").addEventListener("click", function () {
        const name = prompt(t("nameYourStyle"), L({
          en: "My style " + (App.state.saved.length + 1),
          pt: "Meu penteado " + (App.state.saved.length + 1)
        }));
        if (!name) return;
        App.state.saved.push({
          id: "my-" + Date.now().toString(36),
          name: name,
          look: JSON.parse(JSON.stringify(look))
        });
        App.save(); App.clearPlans(); App.confetti(); App.toast("💾 " + t("saved"));
      });
    }
    draw();
  }

  /* ------------------------------------------------- copy the client's hair */
  const GAME_FIELDS = ["updo", "braid", "bangs", "accessory", "color"];
  const ROUNDS = 5;
  const ROUND_SECONDS = 45;

  function copycat(mount) {
    stopAll();
    let round = 0, score = 0, target = null, mine = null, left = ROUND_SECONDS, playing = false;

    function shell(inner) {
      mount.innerHTML =
        '<div class="page-head"><button class="back-btn" data-go="#/">←</button><h2>⏱️ ' +
        t("menuGame") + "</h2></div>" + inner;
    }

    function intro() {
      stopAll();
      shell('<div class="card center">' +
        '<div style="font-size:3rem">💇‍♀️</div>' +
        "<p>" + t("gRules") + "</p>" +
        '<p class="muted">' + t("gBest") + ': <b>' + App.state.best.copycat + '</b></p>' +
        '<button class="btn primary" id="startg">▶ ' + t("gStart") + "</button></div>");
      mount.querySelector("#startg").addEventListener("click", function () {
        round = 0; score = 0; nextRound();
      });
    }

    function nextRound() {
      round++;
      if (round > ROUNDS) return over();
      target = randomLook(GAME_FIELDS);
      mine = defaultLook();
      mine.length = target.length;
      mine.texture = target.texture;
      left = ROUND_SECONDS;
      playing = true;
      draw();
      stopAll();
      ticker = setInterval(function () {
        left -= 1;
        const bar = mount.querySelector("#tfill");
        if (bar) bar.style.width = Math.max(0, (left / ROUND_SECONDS) * 100) + "%";
        const tn = mount.querySelector("#tnum");
        if (tn) tn.textContent = Math.max(0, left);
        if (left <= 0) { stopAll(); submit(); }
      }, 1000);
    }

    function draw() {
      shell(
        '<div class="game-hud">' +
          '<span class="hud-item">👩 ' + t("gRound") + " " + round + "/" + ROUNDS + "</span>" +
          '<span class="hud-item">⭐ ' + t("gScore") + ': <b id="snum">' + score + "</b></span>" +
          '<span class="hud-item">⏳ <b id="tnum">' + left + "</b>s</span>" +
        "</div>" +
        '<div class="timer-bar"><i class="timer-fill" id="tfill" style="display:block;width:' +
          (left / ROUND_SECONDS) * 100 + '%"></i></div>' +
        '<div class="card"><div class="versus">' +
          "<div><h4>" + t("gClient") + '</h4><div class="portrait">' +
            Draw.render(target, { label: "target" }) + "</div></div>" +
          "<div><h4>" + t("gYours") + '</h4><div class="portrait">' +
            Draw.render(mine, { mood: "wow", label: "yours" }) + "</div></div>" +
        "</div>" +
        '<div class="btn-row" style="justify-content:center;margin-top:14px">' +
          '<button class="btn primary" id="doneg">✅ ' + t("gDone") + "</button></div></div>" +
        '<div class="card">' + controlPanel(mine, GAME_FIELDS.concat(["accColor"])) + "</div>"
      );
      wire(mount, mine, draw);
      mount.querySelector("#doneg").addEventListener("click", function () {
        if (playing) { stopAll(); submit(); }
      });
    }

    function submit() {
      playing = false;
      let hits = 0;
      GAME_FIELDS.forEach(function (f) { if (mine[f] === target[f]) hits++; });
      if (mine.accessory !== "none" && mine.accessory === target.accessory &&
        mine.accColor === target.accColor) hits += 0.5;
      const gained = Math.round(hits * 20 + (hits === GAME_FIELDS.length ? left : 0));
      score += gained;
      const msg = hits >= GAME_FIELDS.length ? t("gPerfect")
        : hits >= GAME_FIELDS.length - 1 ? t("gClose") : t("gOops");
      if (hits >= GAME_FIELDS.length) App.confetti();

      shell(
        '<div class="card center">' +
          "<h2>" + msg + "</h2>" +
          '<div class="versus" style="max-width:520px;margin:0 auto">' +
            "<div><h4>" + t("gClient") + '</h4><div class="portrait">' + Draw.render(target, {}) + "</div></div>" +
            "<div><h4>" + t("gYours") + '</h4><div class="portrait">' + Draw.render(mine, {}) + "</div></div>" +
          "</div>" +
          "<p><b>+" + gained + "</b> ⭐ · " + t("gScore") + ": <b>" + score + "</b></p>" +
          '<button class="btn primary" id="nextg">' +
            (round >= ROUNDS ? t("gOver") : "👩 " + t("gRound") + " " + (round + 1)) + "</button>" +
        "</div>"
      );
      mount.querySelector("#nextg").addEventListener("click", nextRound);
    }

    function over() {
      stopAll();
      const best = Math.max(score, App.state.best.copycat || 0);
      if (best > (App.state.best.copycat || 0)) { App.state.best.copycat = best; App.save(); App.confetti(); }
      shell('<div class="card center"><div style="font-size:3rem">🏆</div>' +
        "<h2>" + t("gOver") + "</h2>" +
        "<p>" + t("gFinal") + ': <b style="font-size:1.6rem">' + score + "</b> ⭐</p>" +
        '<p class="muted">' + t("gBest") + ": " + App.state.best.copycat + "</p>" +
        '<div class="btn-row" style="justify-content:center">' +
        '<button class="btn primary" id="againg">' + t("gPlayAgain") + "</button>" +
        '<button class="btn ghost" data-go="#/">' + t("back") + "</button></div></div>");
      mount.querySelector("#againg").addEventListener("click", function () {
        round = 0; score = 0; nextRound();
      });
    }

    intro();
  }

  /* ------------------------------------------------------------ memory game */
  function memory(mount) {
    stopAll();
    const PAIRS = 8;
    let cards = [], flipped = [], moves = 0, matched = 0, busy = false;

    function build() {
      const pool = D.STYLES.slice();
      for (let i = pool.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        const tmp = pool[i]; pool[i] = pool[j]; pool[j] = tmp;
      }
      const chosen = pool.slice(0, PAIRS);
      cards = chosen.concat(chosen).map(function (s, i) {
        return { id: s.id, style: s, key: i, up: false, done: false };
      });
      for (let i = cards.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        const tmp = cards[i]; cards[i] = cards[j]; cards[j] = tmp;
      }
      moves = 0; matched = 0; flipped = []; busy = false;
    }

    function draw() {
      const best = App.state.best.memory;
      mount.innerHTML =
        '<div class="page-head"><button class="back-btn" data-go="#/">←</button><h2>🃏 ' +
          t("menuMemory") + "</h2></div>" +
        '<p class="muted" style="margin:-8px 0 12px">' + t("mRules") + "</p>" +
        '<div class="game-hud"><span class="hud-item">🔁 ' + t("mMoves") + ": <b>" + moves + "</b></span>" +
        '<span class="hud-item">💖 ' + matched + "/" + PAIRS + "</span>" +
        (best ? '<span class="hud-item">🏆 ' + t("gBest") + ": " + best + "</span>" : "") +
        '<button class="chip" id="newgame">↺ ' + t("gPlayAgain") + "</button></div>" +
        '<div class="card"><div class="saved-grid" id="cards">' +
          cards.map(function (c, i) {
            if (c.up || c.done) {
              return '<button class="mini' + (c.done ? " on" : "") + '" data-card="' + i + '">' +
                App.portrait(c.style) + "<b>" + esc(L(c.style.n)) + "</b></button>";
            }
            return '<button class="mini" data-card="' + i +
              '" style="background:linear-gradient(135deg,var(--pink),var(--grape));border-color:transparent">' +
              '<div style="height:86px;display:grid;place-items:center;font-size:2rem">✂️</div>' +
              '<b style="color:#fff">?</b></button>';
          }).join("") +
        "</div></div>";

      Array.prototype.forEach.call(mount.querySelectorAll("[data-card]"), function (b) {
        b.addEventListener("click", function () { flip(+b.dataset.card); });
      });
      mount.querySelector("#newgame").addEventListener("click", function () { build(); draw(); });
    }

    function flip(i) {
      const c = cards[i];
      if (busy || c.up || c.done) return;
      c.up = true;
      flipped.push(i);
      if (flipped.length === 2) {
        moves++;
        const a = cards[flipped[0]], b = cards[flipped[1]];
        if (a.id === b.id) {
          a.done = b.done = true;
          matched++;
          flipped = [];
          draw();
          if (matched === PAIRS) {
            App.confetti();
            const best = App.state.best.memory;
            if (!best || moves < best) { App.state.best.memory = moves; App.save(); }
            App.toast("🎉 " + t("mWin") + " " + moves + " " + t("mMoves").toLowerCase());
          }
          return;
        }
        busy = true;
        draw();
        setTimeout(function () {
          a.up = false; b.up = false; flipped = []; busy = false; draw();
        }, 900);
        return;
      }
      draw();
    }

    build();
    draw();
  }

  global.HairGames = { salon: salon, copycat: copycat, memory: memory };
})(window);
