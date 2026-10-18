(function () {
  "use strict";

  var CASES = window.CASES;
  var app = document.getElementById("app");
  var modalRoot = document.getElementById("modal-root");
  var STORE_KEY = "crime-scene-detective-v1";

  // ---------------------------------------------------------------- progress

  function loadProgress() {
    try {
      return JSON.parse(localStorage.getItem(STORE_KEY)) || {};
    } catch (e) {
      return {};
    }
  }
  var progress = loadProgress();
  progress.stars = progress.stars || {};

  function saveProgress() {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(progress));
    } catch (e) {
      // Private mode or blocked storage: the game still works, it just forgets.
    }
  }
  function starsFor(c) {
    return progress.stars[c.id] || 0;
  }
  function isUnlocked(i) {
    return i === 0 || starsFor(CASES[i - 1]) > 0;
  }

  // ------------------------------------------------------------------- sound

  var audio = null;
  function beep(notes, o) {
    if (progress.muted) return;
    try {
      audio = audio || new (window.AudioContext || window.webkitAudioContext)();
      var t = audio.currentTime;
      notes.forEach(function (f, i) {
        var osc = audio.createOscillator();
        var gain = audio.createGain();
        var start = t + i * o.gap;
        osc.type = o.type || "sine";
        osc.frequency.value = f;
        gain.gain.setValueAtTime(0.0001, start);
        gain.gain.exponentialRampToValueAtTime(o.vol || 0.15, start + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, start + o.len);
        osc.connect(gain);
        gain.connect(audio.destination);
        osc.start(start);
        osc.stop(start + o.len + 0.05);
      });
    } catch (e) {
      // No Web Audio: play silently.
    }
  }
  var sfx = {
    clue: function () {
      beep([660, 880], { gap: 0.09, len: 0.2 });
    },
    dust: function () {
      beep([300, 340, 380, 420, 460], {
        gap: 0.2,
        len: 0.15,
        type: "triangle",
        vol: 0.05,
      });
    },
    wrong: function () {
      beep([220, 160], { gap: 0.18, len: 0.32, type: "square", vol: 0.05 });
    },
    win: function () {
      beep([523, 659, 784, 1047], { gap: 0.13, len: 0.4, type: "triangle" });
    },
  };

  // ----------------------------------------------------------------- helpers

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (ch) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[ch];
    });
  }
  function img(src, alt, cls) {
    return (
      '<img src="' +
      esc(src) +
      '" alt="' +
      esc(alt) +
      '"' +
      (cls ? ' class="' + cls + '"' : "") +
      ">"
    );
  }
  function printCanvas(spec, opts, cls) {
    var data = esc(JSON.stringify({ spec: spec, opts: opts || {} }));
    return (
      '<canvas class="' +
      (cls || "") +
      '" data-print="' +
      data +
      '" aria-hidden="true"></canvas>'
    );
  }
  function drawPrints(root) {
    requestAnimationFrame(function () {
      (root || document)
        .querySelectorAll("canvas[data-print]")
        .forEach(function (c) {
          if (!c.clientWidth) return;
          var d = JSON.parse(c.getAttribute("data-print"));
          window.Fingerprint.draw(c, d.spec, d.opts);
        });
    });
  }
  function difficultyHtml(level) {
    var out = "";
    for (var i = 1; i <= CASES.length; i++) {
      out += i <= level ? "🔍" : '<span class="off">🔍</span>';
    }
    return out;
  }
  function starsHtml(n) {
    var out = "";
    for (var i = 1; i <= 3; i++)
      out += i <= n ? "★" : '<span class="off">★</span>';
    return out;
  }
  function firstName(s) {
    return s.name.replace(/^(Dr\.|Prof\.)\s+/, "").split(" ")[0];
  }
  function muteButton() {
    return (
      '<button class="icon-btn" data-act="mute" aria-label="' +
      (progress.muted ? "Turn sound on" : "Turn sound off") +
      '">' +
      (progress.muted ? "🔇" : "🔊") +
      "</button>"
    );
  }

  var toastTimer = null;
  function toast(msg) {
    var old = document.querySelector(".toast");
    if (old) old.remove();
    var el = document.createElement("div");
    el.className = "toast";
    el.setAttribute("role", "status");
    el.textContent = msg;
    document.body.appendChild(el);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      el.remove();
    }, 5000);
  }

  // ------------------------------------------------------------------ modals

  var modalLocked = false;
  function openModal(html, opts) {
    modalLocked = !!(opts && opts.locked);
    modalRoot.innerHTML = '<div class="modal-backdrop">' + html + "</div>";
    document.body.style.overflow = "hidden";
    drawPrints(modalRoot);
    var focus = modalRoot.querySelector(".modal-close, .btn");
    if (focus) focus.focus({ preventScroll: true });
  }
  function closeModal() {
    modalRoot.innerHTML = "";
    modalLocked = false;
    document.body.style.overflow = "";
  }

  // -------------------------------------------------------------- game state

  var game = null;

  function startCase(i) {
    game = {
      i: i,
      c: CASES[i],
      found: [],
      dusted: {},
      cracked: {},
      ruled: {},
      cleared: {},
      wrong: 0,
      view: "scene",
      rot: 0,
      cmp: null,
    };
    closeModal();
    renderCase();
    window.scrollTo(0, 0);
    showBriefing();
  }

  function suspectById(id) {
    return game.c.suspects.filter(function (s) {
      return s.id === id;
    })[0];
  }
  function hotspotById(id) {
    return game.c.hotspots.filter(function (h) {
      return h.id === id;
    })[0];
  }
  function isFound(id) {
    return game.found.indexOf(id) >= 0;
  }
  function printHotspot() {
    return game.c.hotspots.filter(function (h) {
      return h.closeup.type === "print";
    })[0];
  }
  function evidenceHotspot() {
    var h = printHotspot();
    return h && game.dusted[h.id] ? h : null;
  }
  function solvedStep(h) {
    if (h.closeup.type === "print") return !!game.dusted[h.id];
    if (h.closeup.type === "cipher") return !!game.cracked[h.id];
    return true;
  }
  function clueText(h) {
    if (h.closeup.type === "print" && !game.dusted[h.id]) {
      return h.title + ": not dusted for fingerprints yet!";
    }
    if (h.closeup.type === "cipher" && game.cracked[h.id]) return h.clueAfter;
    return h.clue;
  }
  // The culprit's print as it was found at the scene, plus the player's turn.
  function evidencePrint(h, scale, forOverlay) {
    var p = h.closeup.print;
    var opts = {
      crop: p.crop,
      rotate: (p.rotate || 0) + (forOverlay ? 0 : game.rot),
      smudge: p.smudge,
      scale: scale || 1,
      maskSeed: 1,
    };
    if (forOverlay) {
      opts.ink = h.closeup.dark
        ? "rgba(70,55,40,0.9)"
        : "rgba(246,243,236,0.95)";
    } else {
      opts.paper = "#ffffff";
    }
    return { spec: suspectById(p.of).print, opts: opts };
  }

  // -------------------------------------------------------------------- home

  function renderHome() {
    game = null;
    closeModal();
    var solved = CASES.filter(function (c) {
      return starsFor(c) > 0;
    }).length;
    var next = 0;
    while (next < CASES.length - 1 && starsFor(CASES[next]) > 0) next++;

    var cards = CASES.map(function (c, i) {
      var st = starsFor(c);
      var locked = !isUnlocked(i);
      return (
        '<button class="case-folder' +
        (locked ? " locked" : "") +
        '" data-act="open-case" data-i="' +
        i +
        '" data-tab="CASE #' +
        (i + 1) +
        '">' +
        '<div class="thumb">' +
        img(c.scene, "") +
        (locked ? '<div class="lock">🔒</div>' : "") +
        "</div>" +
        (st ? '<span class="stamp-solved">SOLVED</span>' : "") +
        '<div class="info"><h3>' +
        esc(c.title) +
        "</h3>" +
        '<div class="meta"><span class="difficulty" title="Difficulty">' +
        difficultyHtml(c.level) +
        '</span><span class="stars">' +
        (st ? starsHtml(st) : locked ? "Locked" : "New!") +
        "</span></div>" +
        '<div class="meta"><span>' +
        esc(c.rank) +
        " level</span></div>" +
        "</div></button>"
      );
    }).join("");

    var steps = [
      [
        "🔎",
        "Search the room",
        "Tap the important things in the crime scene to look at them up close.",
      ],
      [
        "📒",
        "Collect clues",
        "Every clue goes into your notebook. Dust things for fingerprints!",
      ],
      [
        "🪪",
        "Check the suspects",
        "Compare your clues with each ID card: photo, job, address, nationality, ID number and fingerprint.",
      ],
      [
        "👉",
        "Accuse!",
        "Pick the culprit. Careful: a wrong guess costs you a star.",
      ],
    ]
      .map(function (s) {
        return (
          '<div class="how-step"><div class="n">' +
          s[0] +
          "</div><b>" +
          s[1] +
          "</b><p>" +
          s[2] +
          "</p></div>"
        );
      })
      .join("");

    app.innerHTML =
      '<section class="hero" style="background-image:url(img/title.jpg)"><div class="hero-inner">' +
      "<h1>Crime Scene<br><span>Detective</span></h1>" +
      "<p>Search the crime scene. Collect the clues. Compare fingerprints and ID cards. Catch the culprit!</p>" +
      '<div class="hero-actions"><button class="btn" data-act="open-case" data-i="' +
      (solved === CASES.length ? 0 : next) +
      '">' +
      (solved === CASES.length
        ? "🏆 All cases solved! Play again"
        : solved
          ? "🔎 Continue: Case #" + (next + 1)
          : "🔎 Start your first case") +
      "</button>" +
      muteButton() +
      "</div></div></section>" +
      '<section class="section"><h2>How to play</h2><div class="how">' +
      steps +
      "</div></section>" +
      '<section class="section"><h2>Case board <small>(' +
      solved +
      "/" +
      CASES.length +
      " solved)</small></h2>" +
      '<div class="cases-grid">' +
      cards +
      "</div></section>" +
      '<p class="footer-note">Pictures made with Magnific. <button data-act="reset">Reset progress</button></p>';
    window.scrollTo(0, 0);
  }

  function openCase(i) {
    if (isUnlocked(i)) return startCase(i);
    openModal(
      '<div class="modal narrow" role="dialog" aria-label="Locked case"><div class="modal-pad">' +
        "<h3>🔒 Top secret!</h3>" +
        "<p>This case is for more experienced detectives. Solve <b>Case #" +
        i +
        "</b> first to unlock it… or try it anyway if you're feeling brave!</p>" +
        '<div class="modal-actions"><button class="btn" data-act="force-case" data-i="' +
        i +
        '">Try it anyway</button><button class="btn ghost" data-act="close">OK</button></div>' +
        "</div></div>",
    );
  }

  // -------------------------------------------------------------------- case

  function renderCase() {
    var c = game.c;
    var scrollY = window.scrollY;
    var scroller = app.querySelector(".scene-scroll");
    var scrollX = scroller ? scroller.scrollLeft : null;

    app.innerHTML =
      '<header class="topbar">' +
      '<button class="btn ghost small" data-act="home">← Cases</button>' +
      '<div class="case-name"><small>CASE #' +
      (game.i + 1) +
      "</small>" +
      esc(c.title) +
      "</div>" +
      '<div class="tabs" role="tablist">' +
      tab("scene", "🔎 Crime scene") +
      tab("suspects", "🪪 Suspects") +
      "</div>" +
      '<span class="counter">Clues <b>' +
      game.found.length +
      "/" +
      c.hotspots.length +
      '</b> <span class="stars" title="Stars you can still earn">' +
      starsHtml(Math.max(1, 3 - game.wrong)) +
      "</span></span>" +
      '<button class="icon-btn" data-act="hint" title="Get a hint" aria-label="Get a hint">💡</button>' +
      '<button class="icon-btn" data-act="briefing" title="Read the case file" aria-label="Read the case file">📁</button>' +
      muteButton() +
      "</header>" +
      '<main class="case-main">' +
      (game.view === "scene" ? sceneView() : suspectsView()) +
      "</main>";

    drawPrints(app);
    window.scrollTo(0, scrollY);
    var newScroller = app.querySelector(".scene-scroll");
    if (newScroller && scrollX !== null) newScroller.scrollLeft = scrollX;
  }

  function tab(view, label) {
    return (
      '<button role="tab" aria-selected="' +
      (game.view === view) +
      '" data-act="view" data-view="' +
      view +
      '" class="' +
      (game.view === view ? "on" : "") +
      '">' +
      label +
      "</button>"
    );
  }

  function sceneView() {
    var c = game.c;
    var spots = c.hotspots
      .map(function (h) {
        var found = isFound(h.id);
        return (
          '<button class="hotspot" data-act="inspect" data-id="' +
          h.id +
          '" style="left:' +
          h.x +
          "%;top:" +
          h.y +
          "%;width:" +
          h.w +
          "%;height:" +
          h.h +
          '%" aria-label="Inspect: ' +
          esc(h.label) +
          '"><span class="tag">' +
          esc(found ? h.title : "Inspect") +
          "</span>" +
          (found ? '<span class="check">✓</span>' : "") +
          "</button>"
        );
      })
      .join("");
    return (
      '<div class="scene-layout"><section>' +
      '<div class="scene-scroll"><div class="scene">' +
      img(c.scene, "The crime scene: " + c.title) +
      spots +
      "</div></div>" +
      '<p class="scene-help">Tap anything that looks important to take a closer look. ' +
      '<span class="swipe-hint">↔ Swipe the picture to look around the whole room.</span></p>' +
      "</section>" +
      notebookHtml() +
      "</div>"
    );
  }

  function notebookHtml() {
    var c = game.c;
    var items = game.found
      .map(function (id) {
        var h = hotspotById(id);
        var thumb;
        if (h.closeup.type === "print" && game.dusted[id]) {
          var d = evidencePrint(h);
          thumb = printCanvas(d.spec, d.opts);
        } else {
          thumb = '<span class="ico">' + h.icon + "</span>";
        }
        return (
          '<li><button class="clue-item" data-act="inspect" data-id="' +
          id +
          '">' +
          thumb +
          "<span>" +
          esc(clueText(h)) +
          "</span></button></li>"
        );
      })
      .join("");
    for (var k = game.found.length; k < c.hotspots.length; k++) {
      items +=
        '<li><div class="clue-item unknown">❓ A clue is still hidden in the room…</div></li>';
    }
    return (
      '<aside class="notebook"><h2>📒 Detective\'s notebook</h2>' +
      '<ul class="clue-list">' +
      items +
      "</ul>" +
      '<button class="btn to-suspects" data-act="view" data-view="suspects">🪪 Line up the suspects →</button>' +
      guideHtml() +
      "</aside>"
    );
  }

  function guideHtml() {
    var samples = [
      ["whorl", "Whorl", 901],
      ["loopL", "Loop", 902],
      ["arch", "Arch", 903],
      ["tented", "Tented arch", 904],
    ];
    return (
      '<details class="guide"' +
      (game.c.level <= 2 ? " open" : "") +
      "><summary>🖐️ Fingerprint guide</summary>" +
      '<div class="guide-grid">' +
      samples
        .map(function (s) {
          return (
            "<div>" +
            printCanvas({ type: s[0], seed: s[2] }, {}) +
            s[1] +
            "</div>"
          );
        })
        .join("") +
      "</div><p>A <b>whorl</b> goes round in circles. A <b>loop</b> comes in from one side and turns back: check which way it opens! An <b>arch</b> is a smooth hill, and a <b>tented arch</b> has a sharp point.</p></details>"
    );
  }

  function suspectsView() {
    var c = game.c;
    var chips = game.found.length
      ? game.found
          .map(function (id) {
            var h = hotspotById(id);
            return (
              '<button class="chip" data-act="inspect" data-id="' +
              id +
              '">' +
              h.icon +
              " " +
              esc(clueText(h)) +
              "</button>"
            );
          })
          .join("")
      : '<span class="chip none">No clues yet. Search the crime scene first!</span>';

    var ev = evidenceHotspot();
    var evHtml = "";
    if (ev) {
      var d = evidencePrint(ev);
      evHtml =
        '<div class="ev-print"><button class="lift-card" data-act="compare" data-id="' +
        c.suspects[0].id +
        '" aria-label="Compare the evidence print">' +
        printCanvas(d.spec, d.opts) +
        "EVIDENCE</button>" +
        '<div class="rot-tools"><span>Turn the print</span><div>' +
        '<button class="icon-btn" data-act="rot" data-d="-15" aria-label="Turn left">↺</button> ' +
        '<button class="icon-btn" data-act="rot" data-d="15" aria-label="Turn right">↻</button>' +
        "</div><span>" +
        game.rot +
        "°</span></div></div>";
    } else if (printHotspot()) {
      evHtml =
        '<div class="ev-print"><span class="chip none">🔍 No fingerprint lifted yet</span></div>';
    }

    return (
      '<section class="evidence-bar"><div class="ev-clues"><h3>📒 Your clues (' +
      game.found.length +
      "/" +
      c.hotspots.length +
      ')</h3><div class="chips">' +
      chips +
      "</div></div>" +
      evHtml +
      "</section>" +
      '<section class="id-grid">' +
      c.suspects.map(idCardHtml).join("") +
      "</section>"
    );
  }

  function field(label, value, cls) {
    return (
      "<dt>" +
      label +
      '</dt><dd class="' +
      (cls || "") +
      '">' +
      esc(value) +
      "</dd>"
    );
  }

  function idCardHtml(s) {
    var ruled = game.ruled[s.id];
    return (
      '<article class="idcard' +
      (ruled ? " ruled" : "") +
      '" aria-label="ID card: ' +
      esc(s.name) +
      '">' +
      '<div class="id-band"><span class="crest">★</span>CITY IDENTITY CARD</div>' +
      '<div class="id-body">' +
      '<button class="photo-btn" data-act="photo" data-id="' +
      s.id +
      '" aria-label="Look closely at ' +
      esc(s.name) +
      "'s photo\">" +
      img(s.photo, "Photo of " + s.name, "id-photo") +
      "</button>" +
      '<dl class="id-fields">' +
      field("Name", s.name, "name") +
      field("Job", s.job) +
      field("House No.", s.house) +
      field("Street", s.street) +
      field("Nationality", s.nationality) +
      "</dl></div>" +
      '<div class="id-lower">' +
      '<button class="id-print" data-act="compare" data-id="' +
      s.id +
      '" aria-label="Compare ' +
      esc(s.name) +
      "'s fingerprint\">" +
      printCanvas(s.print, {}) +
      "</button>" +
      '<div class="id-no">ID No.<b>' +
      esc(s.idNo) +
      "</b>Fingerprint: right index finger<br>Tap it to compare</div></div>" +
      '<div class="id-actions">' +
      '<button class="btn ghost" data-act="rule" data-id="' +
      s.id +
      '">' +
      (ruled ? "↩ Bring back" : "✗ Rule out") +
      "</button>" +
      '<button class="btn red" data-act="accuse" data-id="' +
      s.id +
      '">👉 Accuse!</button>' +
      "</div>" +
      '<div class="ruled-stamp">' +
      (game.cleared[s.id] ? "CLEARED" : "RULED OUT") +
      "</div>" +
      "</article>"
    );
  }

  // ---------------------------------------------------------------- briefing

  function showBriefing() {
    var c = game.c;
    openModal(
      '<div class="modal narrow casefile" role="dialog" aria-label="Case file"><div class="modal-pad">' +
        '<div class="file-head"><div><div class="file-no">CASE FILE #' +
        (game.i + 1) +
        " · " +
        esc(c.rank) +
        "</div><h3>" +
        esc(c.title) +
        '</h3><div class="difficulty">' +
        difficultyHtml(c.level) +
        '</div></div><span class="stamp">URGENT</span></div>' +
        c.briefing
          .map(function (p) {
            return "<p>" + esc(p) + "</p>";
          })
          .join("") +
        '<p class="sign"><i>Chief Inspector Moss</i></p>' +
        '<p class="mission">🎯 ' +
        esc(c.mission) +
        "</p>" +
        '<p class="tipbox">💡 ' +
        esc(c.tip) +
        "</p>" +
        '<div class="modal-actions"><button class="btn" data-act="close">🔎 Go to the crime scene</button></div>' +
        "</div></div>",
    );
  }

  // ---------------------------------------------------------------- close-ups

  function inspect(id) {
    var h = hotspotById(id);
    if (!isFound(id)) {
      game.found.push(id);
      sfx.clue();
      renderCase();
    }
    openCloseup(h);
  }

  function openCloseup(h) {
    var cu = h.closeup;
    var media;
    if (cu.type === "image") {
      media =
        '<div class="cu-media' +
        (cu.tall ? " tall" : "") +
        '">' +
        img(cu.src, h.title) +
        "</div>";
    } else if (cu.type === "print") {
      var o = evidencePrint(h, 1, true);
      media =
        '<div class="cu-media"><div class="dust-stage' +
        (game.dusted[h.id] ? " dusted" : "") +
        (cu.dark ? " dark" : "") +
        '">' +
        img(cu.src, h.title) +
        printCanvas(o.spec, o.opts, "found-print") +
        '<div class="powder"></div><div class="brush">🖌️</div>' +
        (game.dusted[h.id]
          ? ""
          : '<button class="btn dust-btn" data-act="dust" data-id="' +
            h.id +
            '">🖌️ Dust for fingerprints</button>') +
        "</div></div>";
    } else if (cu.type === "doc") {
      media =
        '<div class="cu-media"><div class="doc-wrap"><div class="doc ' +
        cu.style +
        '">' +
        cu.html +
        "</div></div></div>";
    } else {
      media = '<div class="cu-media">' + cipherHtml(h) + "</div>";
    }
    openModal(
      '<div class="modal closeup" role="dialog" aria-label="' +
        esc(h.title) +
        '">' +
        '<button class="modal-close" data-act="close" aria-label="Close">×</button>' +
        media +
        '<div class="cu-text">' +
        closeupText(h) +
        "</div></div>",
    );
  }

  function closeupText(h) {
    var done = solvedStep(h);
    var text = done && h.textAfter ? h.textAfter : h.text;
    var out =
      "<h3>" + esc(h.title) + '</h3><p class="cu-desc">' + esc(text) + "</p>";
    if (done) {
      out +=
        '<div class="cu-clue"><small>📒 In your notebook</small>' +
        esc(clueText(h)) +
        "</div>";
    }
    if (h.closeup.type === "print" && game.dusted[h.id]) {
      var d = evidencePrint(h);
      out +=
        '<div class="lift-row"><div class="lift-card">' +
        printCanvas(d.spec, d.opts) +
        "LIFTED PRINT</div>" +
        '<button class="btn" data-act="compare" data-id="' +
        game.c.suspects[0].id +
        '">🔍 Compare with the suspects</button></div>';
    }
    out +=
      '<div class="modal-actions"><button class="btn ghost" data-act="close">Back to the room</button></div>';
    return out;
  }

  function refreshCloseupText(h) {
    var box = modalRoot.querySelector(".cu-text");
    if (!box) return;
    box.innerHTML = closeupText(h);
    drawPrints(box);
  }

  function dust(id) {
    var h = hotspotById(id);
    var stage = modalRoot.querySelector(".dust-stage");
    var btn = modalRoot.querySelector(".dust-btn");
    if (!stage || game.dusted[id]) return;
    if (btn) btn.remove();
    stage.classList.add("dusting");
    sfx.dust();
    setTimeout(function () {
      game.dusted[id] = true;
      stage.classList.remove("dusting");
      stage.classList.add("dusted");
      sfx.clue();
      refreshCloseupText(h);
      renderCase();
    }, 1300);
  }

  // Caesar shift on capital letters.
  function shiftText(text, n) {
    return text.replace(/[A-Z]/g, function (ch) {
      return String.fromCharCode(
        ((ch.charCodeAt(0) - 65 + n + 26 * 2) % 26) + 65,
      );
    });
  }

  function cipherHtml(h) {
    var cu = h.closeup;
    var coded = shiftText(cu.plain, cu.shift);
    var n = game.cracked[h.id] ? cu.shift : 0;
    return (
      '<div class="cipher" data-id="' +
      h.id +
      '">' +
      '<div class="cipher-note">' +
      esc(coded) +
      "</div>" +
      '<label class="cipher-ctrl">Move every letter back by <b class="cipher-n">' +
      n +
      "</b>" +
      '<input type="range" min="0" max="25" value="' +
      n +
      '" data-input="cipher" data-id="' +
      h.id +
      '">' +
      '<div class="wheel">' +
      wheelText(n) +
      "</div></label>" +
      '<div class="cipher-out' +
      (game.cracked[h.id] ? " cracked" : "") +
      '" aria-live="polite">' +
      esc(shiftText(coded, -n)) +
      "</div></div>"
    );
  }

  function wheelText(n) {
    return "DEFGH"
      .split("")
      .map(function (ch) {
        return ch + "→" + shiftText(ch, -n);
      })
      .join("   ");
  }

  function onCipher(input) {
    var h = hotspotById(input.getAttribute("data-id"));
    var cu = h.closeup;
    var n = parseInt(input.value, 10);
    var box = input.closest(".cipher");
    var coded = shiftText(cu.plain, cu.shift);
    box.querySelector(".cipher-n").textContent = n;
    box.querySelector(".wheel").textContent = wheelText(n);
    var out = box.querySelector(".cipher-out");
    out.textContent = shiftText(coded, -n);
    if (n === cu.shift && !game.cracked[h.id]) {
      game.cracked[h.id] = true;
      out.classList.add("cracked");
      sfx.clue();
      refreshCloseupText(h);
      renderCase();
    }
  }

  // ------------------------------------------------------------------ compare

  function openCompare(id) {
    var idx = 0;
    game.c.suspects.forEach(function (s, i) {
      if (s.id === id) idx = i;
    });
    game.cmp = { idx: idx, zoom: game.cmp ? game.cmp.zoom : 1 };
    var ev = evidenceHotspot();
    var left;
    if (ev) {
      left =
        '<div class="cmp-label">🔍 Evidence: ' +
        esc(ev.title) +
        "</div>" +
        '<canvas class="cmp-ev"></canvas>' +
        '<div class="cmp-tools">' +
        '<button class="icon-btn" data-act="rot" data-d="-15" aria-label="Turn left">↺</button>' +
        '<input type="range" min="-180" max="180" step="5" value="' +
        game.rot +
        '" data-input="rot" aria-label="Turn the evidence print">' +
        '<button class="icon-btn" data-act="rot" data-d="15" aria-label="Turn right">↻</button>' +
        '</div><div class="rot-val">Turned ' +
        game.rot +
        "°</div>";
    } else if (printHotspot()) {
      left =
        '<div class="cmp-label">🔍 Evidence</div><div class="cmp-empty">No fingerprint lifted yet. Find something at the crime scene and dust it for prints!</div>';
    } else {
      left =
        '<div class="cmp-label">🔍 Evidence</div><div class="cmp-empty">There are no fingerprints at this crime scene. You\'ll have to use the other clues!</div>';
    }
    openModal(
      '<div class="modal" role="dialog" aria-label="Compare fingerprints">' +
        '<button class="modal-close" data-act="close" aria-label="Close">×</button>' +
        '<div class="modal-pad"><h3>Compare fingerprints</h3>' +
        "<p>Look at the middle of each print. Is it a whorl, a loop or an arch? Which way does it turn? Are the little lines the same?</p>" +
        '<div class="compare"><div class="cmp-pane">' +
        left +
        '</div><div class="cmp-vs">VS</div><div class="cmp-pane">' +
        '<div class="cmp-label cmp-who"></div>' +
        '<canvas class="cmp-sus"></canvas>' +
        '<div class="cmp-tools"><button class="btn ghost small" data-act="cmp-step" data-d="-1">◀ Prev</button>' +
        '<span class="cmp-count"></span>' +
        '<button class="btn ghost small" data-act="cmp-step" data-d="1">Next ▶</button></div>' +
        "</div></div>" +
        '<div class="cmp-zoom">🔎 Zoom <input type="range" min="1" max="2.6" step="0.1" value="' +
        game.cmp.zoom +
        '" data-input="zoom" aria-label="Zoom"></div>' +
        "</div></div>",
    );
    requestAnimationFrame(redrawCompare);
  }

  function redrawCompare() {
    if (!game || !game.cmp) return;
    var s = game.c.suspects[game.cmp.idx];
    var z = game.cmp.zoom;
    var who = modalRoot.querySelector(".cmp-who");
    if (!who) return;
    who.innerHTML = img(s.photo, s.name) + esc(s.name);
    modalRoot.querySelector(".cmp-count").textContent =
      game.cmp.idx + 1 + " / " + game.c.suspects.length;
    window.Fingerprint.draw(modalRoot.querySelector(".cmp-sus"), s.print, {
      paper: "#ffffff",
      scale: z,
    });
    var ev = evidenceHotspot();
    var evCanvas = modalRoot.querySelector(".cmp-ev");
    if (ev && evCanvas) {
      var d = evidencePrint(ev, z);
      window.Fingerprint.draw(evCanvas, d.spec, d.opts);
      modalRoot.querySelector(".rot-val").textContent =
        "Turned " + game.rot + "°";
      modalRoot.querySelector('[data-input="rot"]').value = game.rot;
    }
  }

  function setRotation(deg) {
    deg = Math.max(-180, Math.min(180, deg));
    game.rot = deg;
    redrawCompare();
    if (game.view === "suspects") renderCase();
  }

  // ------------------------------------------------------------------ accuse

  function confirmAccuse(id) {
    var s = suspectById(id);
    var c = game.c;
    var warn = [];
    if (game.found.length < c.hotspots.length) {
      warn.push(
        "You've only found " +
          game.found.length +
          " of " +
          c.hotspots.length +
          " clues.",
      );
    }
    var ph = printHotspot();
    if (ph && isFound(ph.id) && !game.dusted[ph.id])
      warn.push("You haven't dusted for fingerprints yet.");
    c.hotspots.forEach(function (h) {
      if (h.closeup.type === "cipher" && isFound(h.id) && !game.cracked[h.id]) {
        warn.push("You haven't cracked the secret code yet.");
      }
    });
    openModal(
      '<div class="modal narrow" role="dialog" aria-label="Accuse ' +
        esc(s.name) +
        '"><div class="modal-pad">' +
        "<h3>Accuse " +
        esc(s.name) +
        "?</h3>" +
        '<div class="culprit-row">' +
        img(s.photo, s.name) +
        "<p>Are you sure? If you're wrong, you'll lose a star.</p></div>" +
        (warn.length
          ? '<p class="tipbox">⚠️ ' +
            esc(warn.join(" ")) +
            " A good detective finds all the evidence first!</p>"
          : "") +
        '<div class="modal-actions"><button class="btn red" data-act="accuse-yes" data-id="' +
        id +
        '">👉 Yes, it was ' +
        esc(firstName(s)) +
        "!</button>" +
        '<button class="btn ghost" data-act="close">Not yet</button></div>' +
        "</div></div>",
    );
  }

  function accuse(id) {
    var c = game.c;
    if (id === c.culprit) return caseSolved();
    var s = suspectById(id);
    game.wrong++;
    game.ruled[id] = true;
    game.cleared[id] = true;
    sfx.wrong();
    renderCase();
    openModal(
      '<div class="modal narrow" role="dialog" aria-label="Wrong suspect">' +
        '<div class="result-hero"><div class="big-stamp bad">WRONG SUSPECT</div></div>' +
        '<div class="modal-pad"><div class="culprit-row">' +
        img(s.photo, s.name) +
        "<p><b>" +
        esc(s.name) +
        " didn't do it.</b> " +
        esc(s.whyNot) +
        "</p></div>" +
        '<p>You lost a star. <span class="stars">' +
        starsHtml(Math.max(1, 3 - game.wrong)) +
        "</span></p>" +
        '<div class="modal-actions"><button class="btn" data-act="close">🔍 Keep investigating</button></div>' +
        "</div></div>",
    );
  }

  function caseSolved() {
    var c = game.c;
    var stars = Math.max(1, 3 - game.wrong);
    var firstTime = !starsFor(c);
    if (stars > starsFor(c)) progress.stars[c.id] = stars;
    saveProgress();
    sfx.win();
    var s = suspectById(c.culprit);
    var hasNext = game.i + 1 < CASES.length;
    openModal(
      '<div class="modal" role="dialog" aria-label="Case closed">' +
        '<div class="result-hero"><div class="big-stamp">CASE CLOSED</div>' +
        '<div class="result-stars">' +
        starsHtml(stars) +
        "</div></div>" +
        '<div class="modal-pad"><h3>' +
        esc(c.solution.headline) +
        "</h3>" +
        '<div class="culprit-row">' +
        img(s.photo, s.name) +
        "<p>" +
        esc(c.solution.story) +
        "</p></div>" +
        "<h4>How you cracked it</h4>" +
        '<ul class="reasoning">' +
        c.solution.reasoning
          .map(function (r) {
            return "<li>" + esc(r) + "</li>";
          })
          .join("") +
        "</ul>" +
        (firstTime
          ? '<div class="rank-up">🎖️ New rank: ' + esc(c.rank) + "!</div>"
          : "") +
        (hasNext
          ? ""
          : '<div class="rank-up">🏆 You solved every case. You are a true Master Detective!</div>') +
        '<div class="modal-actions">' +
        (hasNext
          ? '<button class="btn" data-act="next">Next case →</button>'
          : "") +
        '<button class="btn ghost" data-act="home">📁 Case board</button>' +
        "</div></div></div>",
      { locked: true },
    );
  }

  // -------------------------------------------------------------------- hints

  function hint() {
    var c = game.c;
    var hidden = c.hotspots.filter(function (h) {
      return !isFound(h.id);
    });
    if (hidden.length) {
      if (game.view !== "scene") {
        game.view = "scene";
        renderCase();
      }
      var h = hidden[Math.floor(Math.random() * hidden.length)];
      var el = app.querySelector('.hotspot[data-id="' + h.id + '"]');
      el.classList.add("pulse");
      el.scrollIntoView({
        block: "center",
        inline: "center",
        behavior: "smooth",
      });
      setTimeout(function () {
        el.classList.remove("pulse");
      }, 4000);
      toast("💡 Look closely at the glowing spot!");
      return;
    }
    var ph = printHotspot();
    if (ph && !game.dusted[ph.id]) {
      toast(
        "💡 You haven't dusted for fingerprints yet! Open “" +
          ph.title +
          "” again and use the brush.",
      );
      return;
    }
    var code = c.hotspots.filter(function (h) {
      return h.closeup.type === "cipher" && !game.cracked[h.id];
    })[0];
    if (code) {
      toast(
        "💡 You still need to crack the secret code. Is there something in the room that explains how the code works?",
      );
      return;
    }
    toast(
      "💡 " +
        c.tip +
        " Rule out everyone who doesn't match a clue. The one left over is your culprit!",
    );
  }

  var lastMiss = 0;
  function nothingHere() {
    if (Date.now() - lastMiss < 2500) return;
    lastMiss = Date.now();
    toast("🔍 Nothing important there. Keep looking!");
  }

  // ------------------------------------------------------------------- events

  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-act]");
    if (!t) {
      if (e.target.classList.contains("modal-backdrop") && !modalLocked)
        closeModal();
      else if (game && e.target.closest(".scene")) nothingHere();
      return;
    }
    var id = t.getAttribute("data-id");
    switch (t.getAttribute("data-act")) {
      case "home":
        renderHome();
        break;
      case "open-case":
        openCase(parseInt(t.getAttribute("data-i"), 10));
        break;
      case "force-case":
        startCase(parseInt(t.getAttribute("data-i"), 10));
        break;
      case "next":
        startCase(game.i + 1);
        break;
      case "close":
        closeModal();
        break;
      case "view":
        game.view = t.getAttribute("data-view");
        renderCase();
        window.scrollTo(0, 0);
        break;
      case "inspect":
        inspect(id);
        break;
      case "dust":
        dust(id);
        break;
      case "briefing":
        showBriefing();
        break;
      case "hint":
        hint();
        break;
      case "rule":
        if (game.ruled[id]) {
          delete game.ruled[id];
          delete game.cleared[id];
        } else {
          game.ruled[id] = true;
        }
        renderCase();
        break;
      case "accuse":
        confirmAccuse(id);
        break;
      case "accuse-yes":
        accuse(id);
        break;
      case "compare":
        openCompare(id);
        break;
      case "cmp-step":
        var n = game.c.suspects.length;
        game.cmp.idx =
          (game.cmp.idx + parseInt(t.getAttribute("data-d"), 10) + n) % n;
        redrawCompare();
        break;
      case "rot":
        setRotation(game.rot + parseInt(t.getAttribute("data-d"), 10));
        break;
      case "photo":
        var s = suspectById(id);
        openModal(
          '<div class="modal narrow" role="dialog" aria-label="Photo of ' +
            esc(s.name) +
            '"><button class="modal-close" data-act="close" aria-label="Close">×</button>' +
            img(s.photo, "Photo of " + s.name, "big-photo") +
            '<div class="modal-pad"><h3>' +
            esc(s.name) +
            "</h3><p>" +
            esc(s.job) +
            " · " +
            esc(s.house + " " + s.street) +
            " · " +
            esc(s.nationality) +
            "</p></div></div>",
        );
        break;
      case "mute":
        progress.muted = !progress.muted;
        saveProgress();
        t.outerHTML = muteButton();
        break;
      case "reset":
        openModal(
          '<div class="modal narrow" role="dialog" aria-label="Reset progress"><div class="modal-pad">' +
            "<h3>Start over?</h3><p>This forgets all your solved cases and stars.</p>" +
            '<div class="modal-actions"><button class="btn red" data-act="reset-yes">Yes, start over</button>' +
            '<button class="btn ghost" data-act="close">No, keep them</button></div></div></div>',
        );
        break;
      case "reset-yes":
        progress = { stars: {}, muted: progress.muted };
        saveProgress();
        renderHome();
        break;
    }
  });

  document.addEventListener("input", function (e) {
    var kind = e.target.getAttribute && e.target.getAttribute("data-input");
    if (kind === "cipher") onCipher(e.target);
    else if (kind === "rot") setRotation(parseInt(e.target.value, 10));
    else if (kind === "zoom") {
      game.cmp.zoom = parseFloat(e.target.value);
      redrawCompare();
    }
  });

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && modalRoot.firstChild && !modalLocked)
      closeModal();
  });

  // Missing pictures get a plain placeholder instead of a broken-image icon.
  document.addEventListener(
    "error",
    function (e) {
      if (e.target.tagName === "IMG") e.target.classList.add("missing");
    },
    true,
  );

  // Prints inside a closed <details> have no size until it opens.
  document.addEventListener(
    "toggle",
    function (e) {
      drawPrints(e.target);
    },
    true,
  );

  var resizeTimer = null;
  window.addEventListener("resize", function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      drawPrints(document);
      redrawCompare();
    }, 200);
  });

  renderHome();
})();
